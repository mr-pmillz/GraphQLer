"""Base class and shared helpers for DoS detectors.

DoS detectors share a common vulnerability-signal heuristic: they look for server-side signals
that indicate the request was not gracefully rejected — server errors, timeouts, or explicit error
messages about resource limits being exceeded.
"""

import json

import requests

from graphqler.fuzzer.engine.detectors.detector import Detector
from graphqler.fuzzer.engine.materializers.materializer import Materializer

# HTTP status codes that indicate the server was overwhelmed rather than returning a controlled error
DOS_VULNERABLE_HTTP_CODES: set[int] = set()
DOS_POTENTIALLY_VULNERABLE_HTTP_CODES = {500, 502, 503, 504}

# Patterns in the response body that suggest the request was not safely rejected
DOS_ERROR_PATTERNS = [
    "stack overflow",
    "out of memory",
    "maximum call stack size exceeded",
]

# Patterns whose *presence* indicates the server caught the issue — not vulnerable
DOS_SAFE_REJECTION_PATTERNS = [
    "cannot spread fragment",           # Apollo / graphql-js circular-fragment rejection
    "fragment would form a cycle",      # graphql-js >=16
    "fragment cycle detected",
    "contains a cycle",
    "fragment cycle",
    "maximum depth",
    "max depth",
    "query depth",
    "depth limit",
    "complexity",
    "too complex",
    "cost limit",
    "rate limit",
    "query too large",
    "field limit",
]


def _error_text(graphql_response: dict, response: requests.Response) -> str:
    """Inspect errors, never arbitrary GraphQL data that may echo attack strings."""
    body = graphql_response
    if not body:
        try:
            body = json.loads(response.text)
        except ValueError:
            return response.text.lower()
    if not isinstance(body, dict) or not isinstance(body.get("errors"), list):
        return ""
    return " ".join(str(e.get("message", "")) if isinstance(e, dict) else str(e) for e in body["errors"]).lower()


class DOSDetector(Detector):
    """Shared base for DoS-style detectors.

    Subclasses only need to provide:
    - DETECTION_NAME (property)
    - materializer (property)

    The default _is_vulnerable / _is_potentially_vulnerable logic checks for the shared
    DoS signal patterns.  Subclasses may override for specialised logic.
    """

    @property
    def DETECTION_NAME(self) -> str:
        raise NotImplementedError

    @property
    def materializer(self) -> type[Materializer]:
        raise NotImplementedError

    def _is_vulnerable(self, graphql_response: dict, request_response: requests.Response) -> bool:
        """Require explicit resource-exhaustion evidence; an isolated 5xx is insufficient."""
        text_lower = _error_text(graphql_response, request_response)
        # If the server safely rejected (e.g. "fragment would form a cycle"), it is NOT vulnerable
        if any(pat in text_lower for pat in DOS_SAFE_REJECTION_PATTERNS):
            return False
        return any(pat in text_lower for pat in DOS_ERROR_PATTERNS)

    def _is_potentially_vulnerable(self, graphql_response: dict, request_response: requests.Response) -> bool:
        text_lower = _error_text(graphql_response, request_response)
        if request_response.status_code == 429 or any(pat in text_lower for pat in DOS_SAFE_REJECTION_PATTERNS):
            return False
        if request_response.status_code in DOS_POTENTIALLY_VULNERABLE_HTTP_CODES:
            return True
        return "timeout" in text_lower or "timed out" in text_lower

    def _get_evidence(self, graphql_response: dict, request_response: requests.Response | None) -> str:
        if request_response is None:
            return ""
        if request_response.status_code in DOS_VULNERABLE_HTTP_CODES | DOS_POTENTIALLY_VULNERABLE_HTTP_CODES:
            return f"HTTP {request_response.status_code}"
        text_lower = _error_text(graphql_response, request_response)
        for pat in DOS_ERROR_PATTERNS + ["timeout", "timed out"]:
            if pat in text_lower:
                return f"matched DoS error pattern: '{pat}'"
        return ""
