"""Discovery regressions exercise real local HTTP transport and CLI output."""

import json
import re
import sqlite3
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from graphqler import config
from graphqler.discovery import _recognize, candidates, discover
from graphqler.output import ResultStore, recording


@pytest.fixture
def server(monkeypatch):
    """Serve GraphQL, deceptive JSON, redirects, and GET-only endpoints locally."""
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            """Keep test server noise out of the test output."""

        def do_POST(self):
            """Read a JSON probe and dispatch its query."""
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            self.respond(payload.get("query", ""))

        def do_GET(self):
            """Read a query parameter probe."""
            self.respond(parse_qs(urlsplit(self.path).query).get("query", [""])[0])

        def respond(self, query):
            """Simulate recognized and unrecognized endpoint responses."""
            path = urlsplit(self.path).path
            observed.append((path, self.command, self.headers.get("Authorization")))
            if path in {"/redirect", "/external"}:
                self.send_response(307)
                self.send_header("Location", "/graphql/v2" if path == "/redirect" else "http://example.invalid/graphql")
                self.end_headers()
                return
            alias = re.search(r"(graphqler_[a-f0-9]+):", query)
            valid = path in {"/graphql/v2", "/v1/graphql", "/app/graphql"} or (path == "/get-only" and self.command == "GET")
            if valid and alias:
                body = {"data": {alias.group(1): "Query"}}
                status = 200
            elif path == "/fake":
                body, status = {"data": {"__typename": "Query"}}, 200
            else:
                body, status = {"errors": [{"message": "Not Found"}]}, 404
            content = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    monkeypatch.setattr(config, "AUTHORIZATION", "Bearer discovery-token")
    monkeypatch.setattr(config, "CUSTOM_HEADERS", {})
    monkeypatch.setattr(config, "PROXY", "")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=httpd.serve_forever, daemon=True)
    worker.start()
    yield f"http://127.0.0.1:{httpd.server_port}", observed
    httpd.shutdown()
    httpd.server_close()
    worker.join()


def test_discovery_records_all_probes_and_finds_versioned_paths(server, tmp_path):
    """A base URL discovers multiple real endpoints while rejecting generic error JSON."""
    base, observed = server
    store = ResultStore(tmp_path, base, "discover")
    with recording(store):
        matches = discover(base)
    store.finish()
    assert {item.url for item in matches if item.confirmed} >= {base + "/graphql/v2", base + "/v1/graphql"}
    assert all(auth == "Bearer discovery-token" for _, _, auth in observed)
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == len(observed)
        assert db.execute("SELECT COUNT(*) FROM endpoints WHERE confirmed=0").fetchone()[0] > 0
    assert "discovery-token" not in (tmp_path / "results.jsonl").read_text()


def test_wordlist_redirect_get_and_wildcard_behavior(server, tmp_path):
    """Only same-origin redirects are followed and GET-only endpoints are cataloged."""
    base, _observed = server
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("# Custom paths\nfake\nexternal\nredirect\nget-only\n")
    matches = discover(base, str(wordlist))
    positive = {(item.url, item.method) for item in matches if item.confirmed}
    assert (base + "/graphql/v2", "POST") in positive
    assert (base + "/get-only", "GET") in positive
    assert not any("fake" in url for url, _ in positive)
    assert any("Cross-origin" in item.evidence for item in matches)


def test_prefix_and_custom_wordlist_constraints(tmp_path):
    """Base path variants stay on origin and hostile wordlists are rejected."""
    urls = candidates("https://example.test/app/")
    assert "https://example.test/app/graphql" in urls
    assert "https://example.test/graphql/v1" in urls
    for invalid in ("https://other.test/graphql", "//other.test/graphql", "../graphql"):
        path = tmp_path / "bad.txt"
        path.write_text(invalid)
        with pytest.raises(ValueError):
            candidates("https://example.test", str(path))
    for url in ("file:///etc/passwd", "https://user:pass@example.test", "http://example.test:99999"):
        with pytest.raises(ValueError):
            candidates(url)


def test_validation_errors_require_graphql_specific_evidence():
    """Ordinary application errors and static data are not endpoint evidence."""
    assert not _recognize({"errors": [{"message": "Unauthorized"}]}, "alias")[0]
    assert not _recognize({"data": {"__typename": "Query"}}, "alias")[0]
    assert _recognize({"errors": [{"message": "Introspection is disabled", "locations": [{"line": 1, "column": 1}]}]}, "alias")[0]


def test_cli_discovery_writes_database_and_exports(server, tmp_path):
    """Exercise the installed module entry point against a local server only."""
    base, _ = server
    result = subprocess.run([sys.executable, "-m", "graphqler", "--url", base, "--mode", "discover", "--path", str(tmp_path)],
                            check=False, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["status"] == "completed"
    assert manifest["counts"]["endpoint"] > 0
    with sqlite3.connect(tmp_path / "results.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM endpoints WHERE confirmed=1").fetchone()[0] >= 2


def test_http_proxy_transports_discovery_requests(server, monkeypatch):
    """An HTTP proxy handles a target whose hostname cannot resolve directly."""
    proxy, observed = server
    monkeypatch.setattr(config, "PROXY", proxy)
    matches = discover("http://example.invalid/graphql/v2", first=True)
    assert matches[0].confirmed
    assert observed == [("/graphql/v2", "POST", "Bearer discovery-token")]


def test_cli_partial_batch_has_aggregate_findings_and_resolvable_sources(server, tmp_path):
    """Validate the real CLI's exit 3 and universal references across target directories."""
    base, _ = server
    inputs = tmp_path / "targets.txt"
    inputs.write_text(base + "\nhttp://127.0.0.1:1/graphql\n")
    output = tmp_path / "output"
    result = subprocess.run([
        sys.executable, "-m", "graphqler", "--input", str(inputs), "--mode", "discover", "--output", str(output),
        "--format", "all", "--customer-id", "test-customer", "--job-id", "test-job", "--discovery-timeout", "0.2",
    ], check=False, capture_output=True, text=True, timeout=30)
    assert result.returncode == 3, result.stdout + result.stderr
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["status"] == "partial"
    assert manifest["succeeded"] == manifest["failed"] == 1
    assert (output / "findings.md").is_file()
    for line in (output / "universal/records.jsonl").read_text().splitlines():
        record = json.loads(line)
        source = record["source_ref"]
        native = json.loads((output / source["file"]).read_text().splitlines()[source["line"] - 1])
        assert native["record_type"] == "endpoint"
        assert native["data"]["url"] == record["url"]
