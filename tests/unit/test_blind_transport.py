"""Blind introspection must use the same transport boundaries as normal scans."""

import asyncio
import copy
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
import requests
from graphql import build_schema, graphql_sync

from graphqler import config
from graphqler.compiler.compiler import Compiler
from graphqler.output import ResultStore, recording
from graphqler.utils import request_utils
from graphqler.utils.blind_introspection import BoundedClient


@pytest.fixture
def blind_server(monkeypatch):
    for key, value in vars(config).copy().items():
        if key.isupper():
            monkeypatch.setattr(config, key, copy.deepcopy(value))
    config.CUSTOM_HEADERS = {}
    config.AUTHORIZATION = ""
    config.PROFILES = {}
    config.PROXY = ""
    config.REQUEST_TIMEOUT = 1
    config.MAX_TIME = 5
    config.MAX_RESPONSE_BYTES = 8192
    config.TIME_BETWEEN_REQUESTS = 0
    monkeypatch.setenv("NO_PROXY", "*")
    schema = build_schema("type Query { greeting: String }")
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            path = urlsplit(self.path).path
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            seen.append({"path": path, "query": payload.get("query"), "auth": self.headers.get("X-API-Key")})
            if path == "/redirect":
                self.send_response(307)
                self.send_header("Location", f"http://localhost:{server.server_port}/escaped")
                self.end_headers()
                return
            query = payload.get("query") or ""
            if "__schema" in query:
                body = {"errors": [{"message": "GraphQL introspection is not allowed"}]}
            elif path == "/large":
                body = {"data": {"value": "x" * 10000}}
            elif path == "/echo":
                body = {"data": {"value": self.headers.get("X-API-Key")}}
            else:
                body = graphql_sync(schema, query, root_value={"greeting": "Hello"}).formatted
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                if path == "/slow":
                    for _ in range(100):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.02)
                else:
                    self.wfile.write(json.dumps(body).encode())
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        request_utils.reset_session()


@pytest.mark.parametrize("path,match", [("/redirect", "Cross-origin"), ("/large", "bytes"), ("/slow", "time|Time|timeout")])
def test_blind_transport_bounds_and_records_failures(blind_server, tmp_path, path, match):
    base, seen = blind_server
    store = ResultStore(tmp_path, base, "compile")
    client = BoundedClient(base + path, {"X-API-Key": "private-secret"}, time.monotonic() + 0.15)
    started = time.monotonic()
    with recording(store), pytest.raises((requests.RequestException, TimeoutError), match=match):
        asyncio.run(client.post("{ greeting }"))
    assert time.monotonic() - started < 0.8
    assert len(seen) == 1
    with store.connect() as db:
        row = db.execute("SELECT error FROM requests").fetchone()
    assert row["error"]


def test_blind_transport_respects_explicit_proxy(blind_server, tmp_path):
    base, seen = blind_server
    config.PROXY = base
    store = ResultStore(tmp_path, "http://example.invalid/graphql", "compile")
    with recording(store):
        client = BoundedClient(store.target, {"X-API-Key": "private-secret"}, time.monotonic() + 1)
        result = asyncio.run(client.post("{ greeting }"))
    assert result == {"data": {"greeting": "Hello"}, "errors": []}
    assert seen[0]["auth"] == "private-secret"
    assert store.counts()["request"] == 1


def test_real_blind_compilation_catalogs_all_inference_requests(blind_server, tmp_path, monkeypatch):
    base, seen = blind_server
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("greeting\n")
    monkeypatch.setattr(config, "WORDLIST_PATH", str(wordlist))
    output = tmp_path / "output"
    store = ResultStore(output, base + "/graphql", "compile")
    with recording(store):
        Compiler(str(output), store.target).run()
    assert len(seen) > 1
    assert store.counts()["request"] == len(seen)
    assert store.counts()["endpoint"] == 1
    assert "greeting" in (output / config.COMPILED_QUERIES_FILE_NAME).read_text()
    assert json.loads((output / config.INTROSPECTION_RESULT_FILE_NAME).read_text())["data"]["__schema"]


def test_blind_deadline_includes_rate_limit_wait(blind_server, monkeypatch):
    base, seen = blind_server
    config.TIME_BETWEEN_REQUESTS = 10
    monkeypatch.setattr(request_utils, "last_request_time", time.time())
    client = BoundedClient(base + "/graphql", {}, time.monotonic() + 0.1)
    with pytest.raises(TimeoutError, match="rate-limit delay"):
        asyncio.run(client.post("{ greeting }"))
    assert seen == []


def test_blind_transport_redacts_credentials_passed_directly_to_the_client(blind_server, tmp_path):
    base, _ = blind_server
    store = ResultStore(tmp_path, base, "compile")
    client = BoundedClient(base + "/echo", {"X-API-Key": "private-secret"}, time.monotonic() + 1)
    with recording(store):
        asyncio.run(client.post("{ greeting }"))
    with store.connect() as db:
        row = db.execute("SELECT response_body FROM requests").fetchone()
    assert "private-secret" not in row["response_body"]
