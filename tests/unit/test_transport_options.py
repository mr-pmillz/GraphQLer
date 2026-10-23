"""Proxy and certificate options also apply to optional scanning transports."""

import logging
import ssl
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from graphqler import config
from graphqler.compiler.compiler import Compiler
from graphqler.utils.websocket_utils import send_graphql_subscription


def test_blind_introspection_uses_proxy_tls_and_bundled_wordlist(tmp_path, monkeypatch):
    """Fallback compilation works without the obsolete relative default wordlist."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "WORDLIST_PATH", "static/wordlist.txt")
    monkeypatch.setattr(config, "PROXY", "http://127.0.0.1:8080")
    monkeypatch.setattr(config, "VERIFY_TLS", False)
    blind = AsyncMock(return_value='{"data":{"__schema":{}}}')
    monkeypatch.setattr("graphqler.compiler.compiler.blind_introspection", blind)
    compiler = Compiler.__new__(Compiler)
    compiler.url = "https://example.test/graphql"
    compiler.logger = logging.getLogger("test-fallback")
    compiler.request_utils = Mock(get_headers=Mock(return_value={"X-Test": "value"}))
    compiler.introspection_result_save_path = tmp_path / "schema.json"
    assert compiler.get_clairvoyance_results() == {"data": {"__schema": {}}}
    options = blind.call_args.kwargs
    assert options["wordlist"] == []
    assert options["headers"] == {"X-Test": "value"}
    assert compiler.introspection_result_save_path.is_file()


def test_websocket_subscription_respects_explicit_proxy_and_tls(monkeypatch):
    """HTTPS subscriptions preserve authentication, proxy, TLS, and handshake timeout options."""
    monkeypatch.setattr(config, "PROXY", "http://127.0.0.1:8080")
    monkeypatch.setattr(config, "VERIFY_TLS", False)
    monkeypatch.setattr(config, "REQUEST_TIMEOUT", 7)
    observed = {}
    connection = AsyncMock()
    connection.response = SimpleNamespace(status_code=101, headers={})
    connection.recv.side_effect = ['{"type":"connection_ack"}', '{"id":"1","type":"complete"}']

    def connect(url, **options):
        observed.update(url=url, **options)
        context = AsyncMock()
        context.__aenter__.return_value = connection
        return context

    monkeypatch.setattr("graphqler.utils.websocket_utils._SameOriginConnect", connect)
    assert send_graphql_subscription("https://example.test/graphql", {"query": "subscription { update }"},
                                     headers={"Authorization": "Bearer test"}) == []
    assert observed["url"] == "wss://example.test/graphql"
    assert observed["proxy"] == config.PROXY
    assert observed["open_timeout"] == 7
    assert observed["additional_headers"] == {"Authorization": "Bearer test"}
    assert observed["ssl"].verify_mode == ssl.CERT_NONE
    assert observed["ssl"].check_hostname is False
