"""Exercise hostile HTTP behavior over real local sockets."""

import gzip
import ipaddress
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from graphqler import config
from graphqler.discovery import _probe, candidates
from graphqler.output import ResultStore, recording
from graphqler.utils import request_utils


@pytest.fixture(params=["http", "https"])
def hostile_server(monkeypatch, request, tmp_path):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            observed.append(self.path)
            if self.path == "/slow-headers":
                self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Padding: ")
                try:
                    for _ in range(100):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", f"http://localhost:{server.server_port}/escaped")
                self.end_headers()
                return
            self.send_response(200)
            if self.path == "/slow-chunk":
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"f")
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            if self.path in {"/bomb", "/gzip"}:
                self.send_header("Content-Encoding", "gzip")
                body = gzip.compress(b"a" * 100000 if self.path == "/bomb" else b'{"data":{}}')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/slow":
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            self.end_headers()
            self.wfile.write(b'{"data":{}}')

    monkeypatch.setattr(config, "AUTHORIZATION", "Bearer private-token")
    monkeypatch.setattr(config, "CUSTOM_HEADERS", {"X-API-Key": "private-key"})
    monkeypatch.setattr(config, "PROXY", "")
    monkeypatch.setattr(config, "REQUEST_TIMEOUT", 0.25)
    monkeypatch.setattr(config, "MAX_RESPONSE_BYTES", 4096)
    request_utils.reset_session()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if request.param == "https":
        pytest.importorskip("cryptography")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                       .not_valid_after(now + timedelta(days=1))
                       .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                       .sign(key, hashes.SHA256()))
        cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        monkeypatch.setattr(config, "VERIFY_TLS", str(cert_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"{request.param}://127.0.0.1:{server.server_port}", observed
    server.shutdown()
    server.server_close()
    thread.join()
    request_utils.reset_session()


def test_scan_redirect_never_forwards_custom_credentials(hostile_server, tmp_path):
    base, observed = hostile_server
    store = ResultStore(tmp_path, base, "run")
    with recording(store), pytest.raises(requests.RequestException, match="Cross-origin"):
        request_utils.send_graphql_request(base + "/redirect", "{ __typename }")
    assert observed == ["/redirect"]
    with store.connect() as db:
        row = db.execute("SELECT status_code,error FROM requests").fetchone()
        assert row[0] == 307 and "Cross-origin" in row[1]


def test_decoded_response_limit_rejects_compression_bomb_and_keeps_evidence(hostile_server, tmp_path):
    base, _ = hostile_server
    store = ResultStore(tmp_path, base, "run")
    with recording(store), pytest.raises(requests.RequestException, match="decoded bytes"):
        request_utils.send_graphql_request(base + "/bomb", "{ __typename }")
    with store.connect() as db:
        row = db.execute("SELECT status_code,response_body,error FROM requests").fetchone()
        assert row[0] == 200 and len(row[1]) == config.MAX_RESPONSE_BYTES and row[2]


def test_ordinary_gzip_response_still_parses(hostile_server):
    base, _ = hostile_server
    body, response = request_utils.send_graphql_request(base + "/gzip", "{ __typename }")
    assert body == {"data": {}}
    assert response.status_code == 200


@pytest.mark.parametrize("discovery", [False, True])
def test_slow_drip_cannot_extend_total_request_budget(hostile_server, tmp_path, discovery):
    base, _ = hostile_server
    store = ResultStore(tmp_path, base, "discover" if discovery else "run")
    started = time.monotonic()
    with recording(store), request_utils.create_new_session() as session:
        with pytest.raises((TimeoutError, requests.Timeout)):
            if discovery:
                _probe(session, base + "/slow", "POST", 2, time.monotonic() + 0.25)
            else:
                request_utils.send_graphql_request(base + "/slow", "{ __typename }")
    assert time.monotonic() - started < 1
    with store.connect() as db:
        row = db.execute("SELECT status_code,response_body,error FROM requests").fetchone()
        assert row[0] == 200 and row[1] and row[2]


def test_ambient_netrc_never_changes_scan_identity(monkeypatch):
    monkeypatch.setattr(config, "PROXY", "")
    monkeypatch.setattr("requests.sessions.get_netrc_auth", lambda *_: ("ambient-user", "ambient-password"))
    with request_utils._create_session_with_headers({}) as session:
        request = session.prepare_request(requests.Request("POST", "https://example.test/"))
    assert "Authorization" not in request.headers


@pytest.mark.parametrize("path", ["/slow-headers", "/slow-chunk"])
def test_partial_headers_and_chunk_framing_cannot_extend_deadline(hostile_server, path):
    base, _ = hostile_server
    started = time.monotonic()
    with pytest.raises(requests.Timeout):
        request_utils.send_graphql_request(base + path, "{ __typename }")
    assert time.monotonic() - started < 1


def test_discovery_keeps_query_authentication_on_candidate_paths():
    assert "https://example.test/graphql/v1?api_key=token" in candidates("https://example.test/?api_key=token")
