"""Regression coverage for worker state and reusable/embedded run isolation."""

import multiprocessing
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from graphql import build_schema, graphql_sync

import pytest
import requests

from graphqler import config
from graphqler.compiler.compiler import Compiler, validate_schema_names
from graphqler.fuzzer import Fuzzer
from graphqler.output import ResultStore, active_store, recording
from graphqler.utils.cli_utils import compiled_target, is_compiled, write_compilation_target
from graphqler.utils.config_handler import isolated_run, validate_config, write_config_to_toml
from graphqler.utils.file_utils import initialize_file
from graphqler.utils.stats import Stats


def test_spawned_worker_preserves_config_and_binds_restored_stats(tmp_path, monkeypatch):
    context = multiprocessing.get_context("spawn")
    monkeypatch.setattr(multiprocessing, "Process", context.Process)
    monkeypatch.setattr(multiprocessing, "Queue", context.Queue)
    monkeypatch.setattr(multiprocessing, "get_start_method", lambda: "spawn")
    monkeypatch.setattr(config, "AUTHORIZATION", "Bearer spawn-only-credential")
    monkeypatch.setattr(config, "PROXY", "http://127.0.0.1:8087")
    monkeypatch.setattr(config, "MAX_TIME", 20)
    monkeypatch.setattr(config, "DEBUG", False)
    getattr(Stats, "reset")()
    fuzzer = Fuzzer.__new__(Fuzzer)
    fuzzer.stats = Stats()
    fuzzer.stats.number_of_successes = 73
    store = ResultStore(tmp_path, "https://example.test/", "fuzz")

    def worker(queue):
        assert config.AUTHORIZATION == "Bearer spawn-only-credential"
        assert config.PROXY == "http://127.0.0.1:8087"
        current = active_store()
        assert current is not None
        current.summary({"successes": Stats().number_of_successes})

    with recording(store):
        fuzzer._run_worker(worker)
    assert store.run_info()["summary"] == {"successes": 73}
    getattr(Stats, "reset")()


def test_real_spawned_fuzzer_reuses_discovered_endpoint_and_proxy(tmp_path):
    """Compile via a local proxy, then fuzz the saved schema using an actual spawn worker."""
    schema = build_schema("type Query { greeting: String }")
    auth_seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            auth_seen.append(self.headers.get("Authorization"))
            valid = urlsplit(self.path).path == "/graphql/v2"
            result = graphql_sync(schema, payload["query"], root_value={"greeting": "hello"}).formatted if valid else {"error": "Not Found"}
            body = json.dumps(result).encode()
            self.send_response(200 if valid else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    entry = tmp_path / "spawn_cli.py"
    entry.write_text("import multiprocessing\nif __name__ == '__main__':\n    multiprocessing.set_start_method('spawn', force=True)\n    from graphqler.__main__ import cli\n    cli()\n")
    output = tmp_path / "results"
    common = [sys.executable, str(entry), "--url", "http://example.invalid/", "--output", str(output),
              "--proxy", f"http://127.0.0.1:{server.server_port}", "--auth", "spawn-token", "--no-detections", "--max-time", "30"]
    try:
        for mode in ("compile", "fuzz"):
            result = subprocess.run([*common, "--mode", mode], capture_output=True, text=True, timeout=60)
            assert result.returncode == 0, result.stdout + result.stderr
        manifest = json.loads((output / "manifest.json").read_text())
        assert manifest["target"] == "http://example.invalid/graphql/v2"
        assert manifest["counts"]["result"] > 0
        assert set(auth_seen) == {"Bearer spawn-token"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_failed_compile_invalidates_previous_schema_and_removes_old_chains(tmp_path, monkeypatch):
    target = "https://example.test/graphql"
    compiler = Compiler(str(tmp_path), target)
    chain = tmp_path / config.CHAINS_DIR_NAME / "old.yml"
    chain.parent.mkdir(parents=True, exist_ok=True)
    chain.write_text("old: chains\n")
    write_compilation_target(tmp_path, target, "completed")
    monkeypatch.setattr(compiler, "get_introspection_query_results", lambda: (_ for _ in ()).throw(RuntimeError("offline")))
    with pytest.raises(RuntimeError, match="offline"):
        compiler.run()
    assert not is_compiled(tmp_path)
    assert not chain.exists()


@pytest.mark.parametrize("status", [None, 200])
def test_compilation_success_cannot_mask_fuzzer_transport_failures(tmp_path, monkeypatch, status):
    monkeypatch.setattr(config, "DEBUG", True)
    store = ResultStore(tmp_path, "https://example.test/", "run")
    success = requests.Response()
    success.status_code = 200
    success._content = b'{"data":{}}'
    store.request(store.target, "POST", {}, success)
    fuzzer = Fuzzer.__new__(Fuzzer)

    def worker(queue):
        response = None
        if status is not None:
            response = requests.Response()
            response.status_code = status
            response._content = b""
        store.request(store.target, "POST", {}, response, error="HTTP request time budget exhausted")

    with recording(store), pytest.raises(RuntimeError, match="no usable HTTP responses"):
        fuzzer._run_worker(worker)


def test_discovered_schema_reuses_endpoint_only_for_original_target(tmp_path):
    store = ResultStore(tmp_path, "https://example.test/?api_key=secret", "compile")
    with recording(store):
        write_compilation_target(tmp_path, "https://example.test/graphql/v2?api_key=secret", "completed")
    assert compiled_target(tmp_path, "https://example.test/?api_key=new") == "https://example.test/graphql/v2?api_key=new"
    with pytest.raises(ValueError, match="different target"):
        compiled_target(tmp_path, "https://unrelated.test/")
    assert "secret" not in (tmp_path / config.COMPILED_DIR_NAME / "target.json").read_text()


@pytest.mark.parametrize("name", ["../../outside", "/tmp/file", "field\nheader", "<script>", ["field"]])
def test_hostile_introspection_names_cannot_become_output_paths(name):
    with pytest.raises(ValueError, match="invalid GraphQL name"):
        validate_schema_names({"data": {"__schema": {"types": [{"name": name}]}}})


def test_legacy_output_helpers_reject_symlinks_and_path_escape(tmp_path):
    store = ResultStore(tmp_path / "output", "https://example.test/", "run")
    outside = tmp_path / "outside.txt"
    outside.write_text("sentinel")
    link = store.directory / "stats.txt"
    link.symlink_to(outside)
    with recording(store):
        with pytest.raises(ValueError, match="symlink"):
            initialize_file(link)
        with pytest.raises(ValueError):
            initialize_file(outside)
    assert outside.read_text() == "sentinel"


def test_saved_config_replaces_symlink_without_modifying_its_target(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("sentinel")
    link = tmp_path / "config.toml"
    link.symlink_to(outside)
    write_config_to_toml(str(link))
    assert outside.read_text() == "sentinel"
    assert not link.is_symlink()


@pytest.mark.parametrize("linked_directory", [False, True])
def test_detection_writers_cannot_follow_output_symlinks(tmp_path, monkeypatch, linked_directory):
    from graphqler.utils.detection_writer import write_from_detector
    store = ResultStore(tmp_path / "output", "https://example.test/", "run")
    monkeypatch.setattr(config, "OUTPUT_DIRECTORY", str(store.directory))
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("sentinel")
    if linked_directory:
        (store.directory / "detections").symlink_to(outside, target_is_directory=True)
    else:
        directory = store.directory / "detections" / "custom" / "getUser"
        directory.mkdir(parents=True)
        (directory / "raw_log.txt").symlink_to(sentinel)
    with recording(store), pytest.raises(ValueError, match="symlink"):
        write_from_detector(vuln_name="custom", node_name="getUser", is_vulnerable=True, potentially_vulnerable=False,
                            payload="query { getUser }", graphql_response={}, status_code=200, evidence="matched")
    assert sentinel.read_text() == "sentinel"
    assert len(list(outside.iterdir())) == 1


def test_logger_rejects_existing_output_symlink(tmp_path):
    from graphqler.utils.logging_utils import Logger
    store = ResultStore(tmp_path / "output", "https://example.test/", "run")
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("sentinel")
    link = store.directory / "fuzzer.log"
    link.symlink_to(sentinel)
    with recording(store), pytest.raises(ValueError, match="symlink"):
        Logger()._get_logger("test-output-boundary", link)
    assert sentinel.read_text() == "sentinel"


def test_embedded_run_restores_credentials_after_system_exit(monkeypatch):
    monkeypatch.setattr(config, "AUTHORIZATION", "baseline")
    monkeypatch.setattr(config, "CUSTOM_HEADERS", {"X-API-Key": "baseline"})

    @isolated_run
    def fail():
        config.AUTHORIZATION = "temporary"
        config.CUSTOM_HEADERS["X-API-Key"] = "temporary"
        raise SystemExit("failed")

    with pytest.raises(SystemExit):
        fail()
    assert config.AUTHORIZATION == "baseline"
    assert config.CUSTOM_HEADERS == {"X-API-Key": "baseline"}


def test_mcp_captures_system_exit_instead_of_exiting_server():
    pytest.importorskip("fastmcp")
    from graphqler.utils.mcp_utils.server import _capture

    def failure():
        raise SystemExit("compiler failed")

    _, result, error = _capture(failure)
    assert result is None and "compiler failed" in error


@pytest.mark.parametrize("name,value", [("MAX_TIME", float("nan")), ("MAX_RESPONSE_BYTES", -1), ("REQUEST_TIMEOUT", 0)])
def test_config_resource_limits_cannot_bypass_validation(name, value, monkeypatch):
    monkeypatch.setattr(config, name, value)
    with pytest.raises(ValueError, match=name):
        validate_config()
