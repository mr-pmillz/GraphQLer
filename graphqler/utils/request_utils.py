import json
import time
from collections.abc import Callable
from typing import Any

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from graphqler import config
from graphqler.output import active_store

# The last time a request was made so that we can wait between requests
last_request_time = time.time()
session = None


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
    headers = {"Content-Type": "application/json"}
    if config.CUSTOM_HEADERS:
        headers.update(config.CUSTOM_HEADERS)

    if config.AUTHORIZATION:
        headers["Authorization"] = f"{config.AUTHORIZATION}"

    return headers


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

    Merges ``config.CUSTOM_HEADERS`` with the provided *headers* dict, so callers
    can supply any combination of Authorization and additional per-request headers
    without losing API-specific config headers.  Authorization is only set when
    explicitly present in *headers*.

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
    """Send and record one request, including transport failures."""
    started = time.monotonic()
    store = active_store()
    try:
        response = client.post(url=url, json=body, timeout=config.REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        if store:
            store.request(url, "POST", body, elapsed=time.monotonic() - started, error=str(exc))
        raise
    if store:
        store.request(url, "POST", body, response, time.monotonic() - started)
    return response


def parse_response(response_text: str) -> dict:
    """Parse the response and try to jsonify it

    Args:
        response_text (str): The response text

    Returns:
        dict: A dictionary of the response
    """
    json_text = ""
    try:
        json_text = json.loads(response_text)
        return json_text
    except (json.JSONDecodeError, ValueError):
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
    session.headers.update(get_headers())
    session.verify = config.VERIFY_TLS

    # Set proxy if available
    if config.PROXY:
        session.proxies.update(get_proxies())
    if not config.VERIFY_TLS:
        disable_warnings(InsecureRequestWarning)
    return session


def _create_session_with_headers(extra_headers: dict[str, str]) -> requests.Session:
    """Create a one-off session merging config.CUSTOM_HEADERS with *extra_headers*.

    Authorization is only included when it is present in *extra_headers* and
    non-empty, so callers that do not supply a token do not accidentally send
    a blank Authorization header which can alter server behaviour.

    Args:
        extra_headers (dict[str, str]): Per-request headers (e.g. from a RuntimeProfile).

    Returns:
        requests.Session: A fresh session that is NOT stored globally.
    """
    one_off = requests.Session()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if config.CUSTOM_HEADERS:
        headers.update(config.CUSTOM_HEADERS)
    for key, value in extra_headers.items():
        if value:
            headers[key] = value
    one_off.headers.update(headers)
    one_off.verify = config.VERIFY_TLS

    if config.PROXY:
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
