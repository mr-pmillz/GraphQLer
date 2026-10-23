"""Exercise subscription scope, budgets, protocols, and evidence on local sockets."""

import copy
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import ssl
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from websockets.exceptions import ConnectionClosed
from websockets.sync.server import serve
from websockets.typing import Subprotocol

from graphqler import config
from graphqler.fuzzer.engine.fengine import FEngine
from graphqler.output import ResultStore, recording
from graphqler.utils.websocket_utils import SubscriptionError, send_graphql_subscription


@pytest.fixture
def subscription_server(monkeypatch, request, tmp_path):
    for name, value in vars(config).copy().items():
        if name.isupper():
            monkeypatch.setattr(config, name, copy.deepcopy(value))
    config.PROXY = ""
    config.CUSTOM_HEADERS = {}
    config.AUTHORIZATION = ""
    config.PROFILES = {}
    config.REQUEST_TIMEOUT = 1
    config.SUBSCRIPTION_TIMEOUT = 0.2
    config.MAX_RESPONSE_BYTES = 2048
    monkeypatch.setenv("NO_PROXY", "*")
    seen = []

    def process_request(connection, request):
        seen.append({"path": request.path, "headers": dict(request.headers)})
        if request.path in {"/redirect", "/same-origin"}:
            response = connection.respond(302, "redirect")
            response.headers["Location"] = (f"ws://localhost:{server.socket.getsockname()[1]}/escaped"
                                            if request.path == "/redirect" else "/events")
            return response

    def handler(connection):
        try:
            connection.recv()
            if connection.request.path == "/no-ack":
                time.sleep(0.5)
                return
            if connection.request.path == "/ping":
                connection.send(json.dumps({"type": "ping", "payload": {"check": True}}))
                assert json.loads(connection.recv())["type"] == "pong"
            connection.send(json.dumps({"type": "connection_ack"}))
            message = json.loads(connection.recv())
            expected = "subscribe" if connection.subprotocol == "graphql-transport-ws" else "start"
            assert message["type"] == expected
            event_type = "next" if expected == "subscribe" else "data"
            if connection.request.path == "/invalid":
                connection.send("[]")
                return
            if connection.request.path == "/error":
                connection.send(json.dumps({"id": "1", "type": "error", "payload": [{"message": "forbidden"}]}))
                return
            if connection.request.path == "/idle":
                time.sleep(0.5)
                return
            for _ in range(100 if connection.request.path == "/flood" else 1):
                connection.send(json.dumps({"id": "1", "type": event_type, "payload": {"data": {"value": "private-secret"}}}))
            if connection.request.path == "/invalid-errors":
                connection.send(json.dumps({"id": "1", "type": event_type, "payload": {"errors": 42}}))
            connection.send(json.dumps({"id": "1", "type": "complete"}))
        except ConnectionClosed:
            pass

    tls = None
    scheme = "http"
    if getattr(request, "param", None) == "tls":
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
        cert_path, key_path = tmp_path / "certificate.pem", tmp_path / "key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        config.VERIFY_TLS = str(cert_path)
        scheme = "https"
    with serve(handler, "127.0.0.1", 0, ssl=tls, subprotocols=[Subprotocol("graphql-transport-ws"), Subprotocol("graphql-ws")], process_request=process_request) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"{scheme}://127.0.0.1:{server.socket.getsockname()[1]}", seen
        finally:
            server.shutdown()
            thread.join(2)


def test_subscription_cannot_redirect_custom_credentials_to_another_origin(subscription_server, tmp_path):
    base, seen = subscription_server
    store = ResultStore(tmp_path, base, "run")
    with recording(store), pytest.raises(SubscriptionError, match="outside the target origin"):
        send_graphql_subscription(base + "/redirect", {"query": "subscription { event }"}, headers={"X-API-Key": "private-secret"})
    assert [item["path"] for item in seen] == ["/redirect"]
    with store.connect() as db:
        row = db.execute("SELECT method,error FROM requests").fetchone()
    assert row["method"] == "WEBSOCKET"
    assert "outside the target origin" in row["error"]


@pytest.mark.parametrize("protocol", ["graphql-transport-ws", "graphql-ws", "subscriptions-transport-ws"])
def test_subscription_reads_live_protocol_configuration_and_keeps_evidence(subscription_server, tmp_path, protocol):
    base, seen = subscription_server
    config.SUBSCRIPTION_PROTOCOL = protocol
    store = ResultStore(tmp_path, base, "run")
    with recording(store):
        events = send_graphql_subscription(base + "/events", {"query": "subscription { event }"}, headers={"X-API-Key": "private-secret"})
    assert events == [{"data": {"value": "private-secret"}}]
    assert seen[0]["headers"]["sec-websocket-protocol"] == ("graphql-ws" if protocol == "subscriptions-transport-ws" else protocol)
    with store.connect() as db:
        row = db.execute("SELECT * FROM requests").fetchone()
    assert row["status_code"] == 101
    assert row["error"] is None
    assert "private-secret" not in row["response_body"]
    assert json.loads(row["response_body"])["messages"][1]["payload"]["data"] == {"value": "[REDACTED]"}


@pytest.mark.parametrize("path", ["/same-origin", "/ping"])
def test_subscriptions_support_same_origin_redirects_and_ping(subscription_server, path):
    base, _ = subscription_server
    assert send_graphql_subscription(base + path, {"query": "subscription { event }"})


@pytest.mark.parametrize("path", ["/invalid", "/error", "/no-ack"])
def test_subscription_failures_are_cataloged(subscription_server, tmp_path, path):
    base, _ = subscription_server
    store = ResultStore(tmp_path, base, "run")
    with recording(store), pytest.raises(SubscriptionError):
        send_graphql_subscription(base + path, {"query": "subscription { event }"})
    with store.connect() as db:
        row = db.execute("SELECT error FROM requests").fetchone()
    assert row["error"]


def test_subscription_collects_only_bounded_event_data(subscription_server, tmp_path):
    base, _ = subscription_server
    store = ResultStore(tmp_path, base, "run")
    with recording(store), pytest.raises(SubscriptionError, match="exceeded the byte or message limit") as failure:
        send_graphql_subscription(base + "/flood", {"query": "subscription { event }"})
    assert 0 < len(failure.value.events) < 100
    with store.connect() as db:
        row = db.execute("SELECT response_body,error FROM requests").fetchone()
    assert len(row["response_body"].encode()) < config.MAX_RESPONSE_BYTES + 100
    assert row["error"]


def test_subscription_uses_live_collection_timeout(subscription_server):
    base, _ = subscription_server
    config.SUBSCRIPTION_TIMEOUT = 0.05
    started = time.monotonic()
    assert send_graphql_subscription(base + "/idle", {"query": "subscription { event }"}) == []
    assert time.monotonic() - started < 0.4


def test_http_to_websocket_conversion_preserves_url_contents(subscription_server):
    base, seen = subscription_server
    send_graphql_subscription(base + "/events?next=https://example.test/", {"query": "subscription { event }"})
    assert seen[0]["path"] == "/events?next=https://example.test/"


@pytest.mark.parametrize("subscription_server", ["tls"], indirect=True)
def test_subscription_verifies_tls_with_the_configured_ca(subscription_server):
    base, _ = subscription_server
    ca = config.VERIFY_TLS
    config.VERIFY_TLS = True
    with pytest.raises(SubscriptionError, match="CERTIFICATE_VERIFY_FAILED"):
        send_graphql_subscription(base + "/events", {"query": "subscription { event }"})
    config.VERIFY_TLS = ca
    assert send_graphql_subscription(base + "/events", {"query": "subscription { event }"})


@pytest.mark.parametrize("path,success", [("/events", True), ("/idle", True), ("/error", False), ("/flood", False), ("/invalid-errors", False)])
def test_subscription_engine_preserves_results_and_partial_events(subscription_server, tmp_path, monkeypatch, path, success):
    base, _ = subscription_server
    engine_class = getattr(FEngine, "__wrapped__")
    engine = engine_class.__new__(engine_class)
    engine.api = Mock(url=base + path)
    engine.logger = logging.getLogger("subscription-engine-test")
    materializer = Mock(get_payload=Mock(return_value=("subscription { event }", {})))
    monkeypatch.setattr("graphqler.fuzzer.engine.fengine.SubscriptionMaterializer", Mock(return_value=materializer))
    store = ResultStore(tmp_path, base, "run")
    with recording(store):
        events, result = engine.run_subscription_payload("event", Mock())
        store.result(SimpleNamespace(name="event", graphql_type="Subscription"), result)
    assert result.success is success
    assert result.status_code == 101
    assert result.payload == {"query": "subscription { event }"}
    assert result.graphql_response == {"events": events}
    if path in {"/flood", "/invalid-errors"}:
        assert events
    assert bool(result.errors) is not success
    with store.connect() as db:
        row = db.execute("SELECT * FROM results").fetchone()
    assert json.loads(row["response_json"]) == {"events": events}
