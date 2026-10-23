"""Interrupt slow HTTP headers and chunk framing at the request deadline."""

from contextlib import contextmanager
from contextvars import ContextVar
import socket
import threading
import time

from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import ConnectionPool, HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ReadTimeoutError

_deadline: ContextVar[float | None] = ContextVar("graphqler_http_deadline", default=None)


@contextmanager
def response_deadline(deadline: float):
    token = _deadline.set(deadline)
    try:
        yield
    finally:
        _deadline.reset(token)


def _get_response(connection, receive):
    deadline = _deadline.get()
    if deadline is None:
        return receive()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReadTimeoutError(ConnectionPool(connection.host, connection.port), connection.host, "HTTP request time budget exhausted")
    sock = connection.sock

    def interrupt():
        # Keep the actual socket: Connection: close can clear connection.sock while
        # the response reader still owns its file descriptor.
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    timer = threading.Timer(remaining, interrupt)
    timer.daemon = True
    timer.start()
    try:
        response = receive()
    except BaseException as exc:
        timer.cancel()
        if isinstance(exc, Exception) and time.monotonic() >= deadline:
            raise ReadTimeoutError(ConnectionPool(connection.host, connection.port), connection.host, "HTTP request time budget exhausted") from exc
        raise
    response._graphqler_deadline_timer = timer
    return response


class _HTTPConnection(HTTPConnection):
    def getresponse(self):
        return _get_response(self, super().getresponse)


class _HTTPSConnection(HTTPSConnection):
    def getresponse(self):
        return _get_response(self, super().getresponse)


class _HTTPPool(HTTPConnectionPool):
    # urllib3's connection protocol narrows its own inherited socket-option types.
    ConnectionCls = _HTTPConnection  # ty: ignore[invalid-assignment]


class _HTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _HTTPSConnection  # ty: ignore[invalid-assignment]


class DeadlineAdapter(HTTPAdapter):
    """Apply the same receive deadline to direct connections and proxy pools."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _HTTPPool, "https": _HTTPSPool}  # ty: ignore[invalid-assignment]

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        manager.pool_classes_by_scheme = {"http": _HTTPPool, "https": _HTTPSPool}
        return manager


def cancel_deadline(response) -> None:
    timer = getattr(response.raw, "_graphqler_deadline_timer", None)
    if timer is not None:
        timer.cancel()
