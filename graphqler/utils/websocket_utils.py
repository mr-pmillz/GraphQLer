"""Bounded GraphQL subscription transport with cataloged evidence."""

import asyncio
from dataclasses import dataclass, field
import json
import logging
import math
import ssl
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from websockets.asyncio.client import connect
from websockets.typing import Subprotocol
from websockets.uri import parse_uri

from graphqler import config
from graphqler.output import active_store
from graphqler.output.redaction import Redactor

logger = logging.getLogger(__name__)
MAX_SUBSCRIPTION_MESSAGES = 10000


class SubscriptionError(RuntimeError):
    """A failed subscription, retaining events received before the failure."""

    def __init__(self, message: str, events: list[dict], status_code: int | None):
        super().__init__(message)
        self.events = events
        self.status_code = status_code


class _SameOriginConnect(connect):
    def process_redirect(self, exc: Exception) -> Exception | str:
        destination = super().process_redirect(exc)
        if isinstance(destination, str):
            old, new = parse_uri(self.uri), parse_uri(destination)
            if (old.secure, old.host, old.port) != (new.secure, new.host, new.port) or new.user_info:
                return ValueError("WebSocket redirect outside the target origin refused")
        return destination


@dataclass
class _Observation:
    events: list[dict] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    status_code: int | None = None
    received_bytes: int = 0


async def _collect(websocket, payload: dict, timeout: float, protocol: str, observation: _Observation) -> list[dict]:
    deadline = asyncio.get_running_loop().time() + timeout

    async def receive():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError("Subscription acknowledgment time budget exhausted")
        raw = await asyncio.wait_for(websocket.recv(), timeout=remaining)
        observation.received_bytes += len(raw.encode("utf-8") if isinstance(raw, str) else raw)
        if observation.received_bytes > config.MAX_RESPONSE_BYTES or len(observation.messages) >= MAX_SUBSCRIPTION_MESSAGES:
            raise ValueError("Subscription response exceeded the byte or message limit")
        try:
            message = json.loads(raw)
        except (ValueError, RecursionError):
            observation.messages.append({"raw": raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw})
            raise ValueError("Subscription response is not a supported JSON message") from None
        observation.messages.append(message)
        if not isinstance(message, dict) or not isinstance(message.get("type"), str):
            raise ValueError("Subscription response must be a protocol message object")
        return message

    async def keepalive(message):
        if message["type"] == "ping":
            pong = {"type": "pong"}
            if "payload" in message:
                pong["payload"] = message["payload"]
            await asyncio.wait_for(websocket.send(json.dumps(pong)), timeout=max(0, deadline - asyncio.get_running_loop().time()))
            return True
        return message["type"] in {"pong", "ka"}

    async with asyncio.timeout(timeout):
        await websocket.send(json.dumps({"type": "connection_init", "payload": {}}))
        while True:
            message = await receive()
            if await keepalive(message):
                continue
            if message["type"] != "connection_ack":
                raise ValueError("Subscription server did not acknowledge the connection")
            break
        modern = protocol == "graphql-transport-ws"
        await websocket.send(json.dumps({"id": "1", "type": "subscribe" if modern else "start", "payload": payload}))

    while True:
        try:
            message = await receive()
        except TimeoutError:
            return observation.events
        if await keepalive(message):
            continue
        if message["type"] == "connection_error":
            raise ValueError("Subscription server rejected the connection")
        if message.get("id") != "1":
            continue
        if message["type"] == ("next" if modern else "data"):
            event = message.get("payload")
            if not isinstance(event, dict):
                raise ValueError("Subscription event must contain a GraphQL response object")
            if not any(key in event for key in ("data", "errors")) or ("data" in event and event["data"] is not None and not isinstance(event["data"], dict)):
                raise ValueError("Subscription event must contain GraphQL data or errors")
            if "errors" in event and (not isinstance(event["errors"], list) or any(
                not isinstance(error, dict) or not isinstance(error.get("message"), str) for error in event["errors"]
            )):
                raise ValueError("Subscription event contains malformed GraphQL errors")
            observation.events.append(event)
        elif message["type"] == "complete":
            return observation.events
        elif message["type"] == "error":
            raise ValueError("Subscription server returned an operation error; inspect recorded messages")


async def _run_subscription(url: str, payload: dict, timeout: float, protocol: str, headers: dict | None,
                            observation: _Observation) -> list[dict]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("Subscription URL must use HTTP(S) or WS(S) without embedded credentials")
    ws_url = urlunsplit(parsed._replace(scheme={"http": "ws", "https": "wss"}.get(parsed.scheme, parsed.scheme)))
    if protocol == "subscriptions-transport-ws":
        protocol = "graphql-ws"
    if protocol not in {"graphql-transport-ws", "graphql-ws"}:
        raise ValueError("Unsupported GraphQL WebSocket protocol")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Subscription timeout must be finite and positive")
    options: dict[str, Any] = {
        "proxy": config.PROXY or True, "open_timeout": config.REQUEST_TIMEOUT,
        "close_timeout": min(1, config.REQUEST_TIMEOUT, timeout), "max_size": config.MAX_RESPONSE_BYTES, "max_queue": 1,
    }
    if parsed.scheme in {"https", "wss"}:
        context = ssl.create_default_context(cafile=config.VERIFY_TLS if isinstance(config.VERIFY_TLS, str) else None)
        if config.VERIFY_TLS is False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        options["ssl"] = context
    async with _SameOriginConnect(ws_url, subprotocols=[Subprotocol(protocol)], additional_headers=headers or {}, **options) as websocket:
        assert websocket.response is not None
        observation.status_code = websocket.response.status_code
        observation.headers = dict(websocket.response.headers)
        return await _collect(websocket, payload, timeout, protocol, observation)


def send_graphql_subscription(url: str, payload: dict, timeout: float | None = None, protocol: str | None = None,
                              headers: dict | None = None) -> list[dict]:
    """Collect subscription events using live configuration and record the exchange.

    ``SubscriptionError`` preserves partial events when the connection, protocol,
    or response limit fails. An acknowledged subscription may return no events.
    """
    observation = _Observation()
    store = active_store()
    redactor = store.redactor if store else Redactor()
    redactor.capture()
    redactor.headers(headers or {})
    redactor.remember_url(url)
    started = time.monotonic()
    error = None
    try:
        return asyncio.run(_run_subscription(url, payload, config.SUBSCRIPTION_TIMEOUT if timeout is None else timeout,
                                             config.SUBSCRIPTION_PROTOCOL if protocol is None else protocol, headers, observation))
    except Exception as exc:
        error = redactor.text(f"{type(exc).__name__}: {exc}")
        logger.warning("Subscription failed: %s", error)
        raise SubscriptionError(error, observation.events, observation.status_code) from None
    finally:
        if store:
            response = SimpleNamespace(status_code=observation.status_code, headers=observation.headers,
                                       text=json.dumps({"messages": observation.messages}))
            store.request(url, "WEBSOCKET", payload, response, time.monotonic() - started, error)
