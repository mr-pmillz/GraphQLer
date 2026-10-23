import json
import time
import zlib
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

import requests
from requests.auth import AuthBase
from requests.structures import CaseInsensitiveDict
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib3.exceptions import HTTPError as Urllib3HTTPError
from urllib3.exceptions import ReadTimeoutError

from graphqler import config
from graphqler.output import active_store
from graphqler.output.redaction import SENSITIVE_NAME
from graphqler.utils.http_deadline import DeadlineAdapter, cancel_deadline, response_deadline

# The last time a request was made so that we can wait between requests
last_request_time = time.time()
session = None


class _ExplicitAuth(AuthBase):
    """Prevent ambient .netrc credentials from overriding an explicit scan profile."""

    def __call__(self, r):
        return r


def reset_session() -> None:
    """Reset the cached HTTP session so new config/auth headers take effect."""
    global session, last_request_time
    if session is not None:
        session.close()
    session = None
    last_request_time = time.time()


def get_headers() -> dict:
    """Get the headers for the request.
      Authorization will be used from the AUTHORIZATION variable first, then from the CUSTOM_HEADERS variable.

    Returns:
        dict: The headers for the request
    """
    headers = CaseInsensitiveDict({"Content-Type": "application/json"})
    if config.CUSTOM_HEADERS:
        headers.update(config.CUSTOM_HEADERS)

    if config.AUTHORIZATION:
        headers["Authorization"] = f"{config.AUTHORIZATION}"

    return dict(headers)


def get_proxies() -> dict:
    """Get the proxies for the request

    Returns:
        dict: The proxies for the request
    """
    if config.PROXY:
        return {"http": config.PROXY, "https": config.PROXY}
    else:
        return {}


def send_graphql_request(url: str, payload: str | dict | list, next: Callable[[dict], dict] | None = None) -> tuple[dict, requests.Response]:
    """Send GraphQL request to the specified endpoint

    Args:
        url (str): URL of the graphql server
        payload (str | dict | list): The payload to send to the GraphQL API. If dict or string, must provide the query and variables keys
        next (Callable[[dict], dict], optional): Callback function in case there is action to be done after. Defaults to None.

    Returns:
        tuple[dict, requests.Response]: Dictionary of the graphql response, and the request's response
    """
    global last_request_time

    # Make the body (if it's a string, add the key, if it's dict or list, assume the creator of the request knows what they are doing
    # (ie. added the query / variable keys themselves))
    if isinstance(payload, str):
        body = {"query": payload}
    else:
        body = payload

    # If the last request was made recently, wait for a bit
    time_since_last_request = time.time() - last_request_time
    if time_since_last_request < config.TIME_BETWEEN_REQUESTS:
        time.sleep(config.TIME_BETWEEN_REQUESTS - time_since_last_request)

    # Make the request and set the last request time
    session = get_or_create_session()
    response = _post(session, url, body)
    last_request_time = time.time()

    if response.status_code != 200:
        return parse_response(response.text), response

    # if next:
    #     return next(json.loads(response.text))

    return parse_response(response.text), response


def send_graphql_request_with_auth(url: str, payload: str | dict | list, auth_override: str) -> tuple[dict, requests.Response]:
    """Send a GraphQL request using a one-off session with a specific auth token.

    Unlike ``send_graphql_request``, this function does **not** touch the global
    session, so the primary token is never replaced.  Used by the IDOR fuzzer to
    test cross-user access with a secondary (attacker) token.

    Args:
        url (str): URL of the GraphQL server.
        payload (str | dict | list): GraphQL payload (same semantics as ``send_graphql_request``).
        auth_override (str): The Authorization header value to use (e.g. "Bearer <token>").

    Returns:
        tuple[dict, requests.Response]: Parsed GraphQL response dict, raw HTTP response.
    """
    return send_graphql_request_with_headers(url, payload, {"Authorization": auth_override} if auth_override else {})


def send_graphql_request_with_headers(url: str, payload: str | dict | list, headers: dict[str, str]) -> tuple[dict, requests.Response]:
    """Send a GraphQL request using a one-off session with an explicit headers dict.

    Inherits ordinary ``config.CUSTOM_HEADERS`` and overlays the provided *headers*.
    Credentials, including Authorization, cookies, and API keys, must be supplied
    explicitly so anonymous and secondary profiles retain their own identities.

    Args:
        url (str): URL of the GraphQL server.
        payload (str | dict | list): GraphQL payload.
        headers (dict[str, str]): Headers to include (merged on top of CUSTOM_HEADERS).

    Returns:
        tuple[dict, requests.Response]: Parsed GraphQL response dict, raw HTTP response.
    """
    global last_request_time

    if isinstance(payload, str):
        body = {"query": payload}
    else:
        body = payload

    time_since_last_request = time.time() - last_request_time
    if time_since_last_request < config.TIME_BETWEEN_REQUESTS:
        time.sleep(config.TIME_BETWEEN_REQUESTS - time_since_last_request)

    one_off_session = _create_session_with_headers(headers)
    try:
        response = _post(one_off_session, url, body)
    finally:
        one_off_session.close()
    last_request_time = time.time()

    return parse_response(response.text), response


def _post(client: requests.Session, url: str, body: Any) -> requests.Response:
    """Bound and catalog every hop without forwarding credentials to another origin."""
    from graphqler.discovery import _origin, validate_url
    original = validate_url(url)
    deadline = time.monotonic() + config.REQUEST_TIMEOUT
    for _ in range(4):
        started = time.monotonic()
        response = None
        store = active_store()
        try:
            remaining = deadline - started
            if remaining <= 0:
                raise requests.Timeout("HTTP request time budget exhausted")
            with response_deadline(deadline):
                response = client.post(url=url, json=body, timeout=remaining, allow_redirects=False, stream=True)
            read_response(response, config.MAX_RESPONSE_BYTES, deadline)
            target = None
            if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("Location"):
                target = validate_url(urljoin(url, response.headers["Location"]))
                if _origin(target) != _origin(original):
                    raise requests.RequestException("Cross-origin redirect was not followed")
                if response.status_code == 303:
                    raise requests.RequestException("Redirect requires GET; GraphQL POST was not replayed")
        except (requests.RequestException, ValueError) as exc:
            if store:
                store.request(url, "POST", body, response, elapsed=time.monotonic() - started, error=str(exc))
            raise
        else:
            if store:
                store.request(url, "POST", body, response, time.monotonic() - started)
            if target is None:
                return response
            url = target
        finally:
            if response is not None:
                cancel_deadline(response)
                response.close()
    raise requests.TooManyRedirects("GraphQL redirect limit reached")


def read_response(response: requests.Response, limit: int, deadline: float) -> None:
    """Bound wire bytes, decompression, and time between individual socket reads.

    Partial evidence remains available when a response is rejected. Unlike a full
    iter_content chunk, each read returns promptly when a slow peer sends bytes.
    """
    if response._content is not False:
        if len(response.content) > limit:
            response._content = response.content[:limit]
            raise requests.RequestException(f"HTTP response exceeds {limit} bytes")
        return
    content = bytearray()
    wire_size = 0
    encoding = response.headers.get("Content-Encoding", "identity").lower().strip()
    decoder = None
    completed = False
    try:
        if encoding in {"gzip", "x-gzip", "deflate"}:
            decoder = zlib.decompressobj(31 if encoding != "deflate" else 15)
        elif encoding not in {"", "identity"}:
            raise requests.RequestException(f"Unsupported HTTP content encoding: {encoding}")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise requests.Timeout("HTTP request time budget exhausted")
            connection = getattr(response.raw, "_connection", None)
            sock = getattr(connection, "sock", None)
            if sock is None:
                fp = getattr(getattr(response.raw, "_fp", None), "fp", None)
                sock = getattr(getattr(fp, "raw", None), "_sock", None)
            if sock is not None:
                sock.settimeout(remaining)
            chunk = response.raw.read1(min(65536, limit + 1), decode_content=False)
            if not chunk:
                if decoder is not None and not decoder.eof:
                    raise requests.RequestException("Truncated compressed HTTP response")
                break
            wire_size += len(chunk)
            if wire_size > limit:
                if decoder is None:
                    content.extend(chunk[:limit - len(content)])
                raise requests.RequestException(f"HTTP response exceeds {limit} wire bytes")
            if decoder is not None:
                chunk = decoder.decompress(chunk, limit + 1 - len(content))
                if decoder.unused_data:
                    raise requests.RequestException("Trailing data in compressed HTTP response")
            if len(content) + len(chunk) > limit:
                content.extend(chunk[:limit - len(content)])
                raise requests.RequestException(f"HTTP response exceeds {limit} decoded bytes")
            content.extend(chunk)
        if time.monotonic() >= deadline:
            raise requests.Timeout("HTTP request time budget exhausted")
        completed = True
    except ReadTimeoutError as exc:
        raise requests.Timeout(str(exc)) from exc
    except Urllib3HTTPError as exc:
        if time.monotonic() >= deadline:
            raise requests.Timeout("HTTP request time budget exhausted") from exc
        raise requests.ConnectionError(str(exc)) from exc
    except zlib.error as exc:
        raise requests.exceptions.ContentDecodingError(str(exc)) from exc
    finally:
        response._content = bytes(content)
        response._content_consumed = True
        cancel_deadline(response)
        if not completed:
            response.raw.close()


def parse_response(response_text: str) -> dict:
    """Parse the response and try to jsonify it

    Args:
        response_text (str): The response text

    Returns:
        dict: A dictionary of the response
    """
    json_text = ""
    try:
        def invalid_constant(value):
            raise ValueError(f"Invalid JSON constant: {value}")
        json_text = json.loads(response_text, parse_constant=invalid_constant)
        return json_text
    except (ValueError, RecursionError):
        return {"errors": [response_text]}


def get_or_create_session() -> requests.Session:
    """Gets an existing session or creates a new one

    Returns:
        requests.Session: The session
    """
    global session

    if session and isinstance(session, requests.Session):
        return session
    else:
        session = create_new_session()
        return session


def create_new_session() -> requests.Session:
    """Create a new session

    Returns:
        requests.Session: The session
    """
    session = requests.Session()
    session.mount("http://", DeadlineAdapter())
    session.mount("https://", DeadlineAdapter())
    session.auth = _ExplicitAuth()
    session.headers["Accept-Encoding"] = "gzip, deflate"
    session.headers.update(get_headers())
    session.verify = config.VERIFY_TLS

    # Set proxy if available
    if config.PROXY:
        session.trust_env = False
        session.proxies.update(get_proxies())
    if not config.VERIFY_TLS:
        disable_warnings(InsecureRequestWarning)
    return session


def _create_session_with_headers(extra_headers: dict[str, str]) -> requests.Session:
    """Create a one-off session inheriting only non-credential custom headers.

    Authorization is only included when it is present in *extra_headers* and
    non-empty, so callers that do not supply a token do not accidentally send
    a blank Authorization header which can alter server behaviour.

    Args:
        extra_headers (dict[str, str]): Per-request headers (e.g. from a RuntimeProfile).

    Returns:
        requests.Session: A fresh session that is NOT stored globally.
    """
    one_off = requests.Session()
    one_off.mount("http://", DeadlineAdapter())
    one_off.mount("https://", DeadlineAdapter())
    one_off.auth = _ExplicitAuth()
    one_off.headers["Accept-Encoding"] = "gzip, deflate"
    headers = CaseInsensitiveDict({"Content-Type": "application/json"})
    if config.CUSTOM_HEADERS:
        headers.update({key: value for key, value in config.CUSTOM_HEADERS.items() if not SENSITIVE_NAME.search(key)})
    for key, value in extra_headers.items():
        if value:
            headers[key] = value
        else:
            headers.pop(key, None)
    one_off.headers.update(headers)
    one_off.verify = config.VERIFY_TLS

    if config.PROXY:
        one_off.trust_env = False
        one_off.proxies.update(get_proxies())
    if not config.VERIFY_TLS:
        disable_warnings(InsecureRequestWarning)
    return one_off


def _create_session_with_auth(auth_token: str) -> requests.Session:
    """Create a one-off session with an explicit Authorization header.

    Delegates to :func:`_create_session_with_headers`.  Authorization is only
    set when *auth_token* is non-empty.

    Args:
        auth_token (str): The Authorization header value (e.g. "Bearer <token>").

    Returns:
        requests.Session: A fresh session that is NOT stored globally.
    """
    return _create_session_with_headers({"Authorization": auth_token} if auth_token else {})
