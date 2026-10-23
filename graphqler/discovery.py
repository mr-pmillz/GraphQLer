"""Bounded GraphQL endpoint discovery using read-only protocol probes."""

import json
import math
import re
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from graphqler.output import active_store
from graphqler.utils import request_utils

DEFAULT_PATHS = (
    "graphql", "graphql/v1", "graphql/v2", "v1/graphql", "v2/graphql", "api/graphql",
    "api/v1/graphql", "api/v2/graphql", "api/graphql/v1", "api/graphql/v2", "graphql/v3",
    "v3/graphql", "gql", "query", "api", "graphiql", "graphql/", "graphql.php",
)
MAX_CANDIDATES = 256
MAX_RESPONSE_BYTES = 1024 * 1024


@dataclass
class Endpoint:
    """One verified endpoint or unsuccessful probe."""

    url: str
    method: str
    status_code: int | None
    confirmed: bool
    evidence: str


def validate_url(value: str) -> str:
    """Accept absolute HTTP URLs with a host and no embedded credentials."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Target URL must use http(s), include a host, and contain no credentials")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Target URL port must be between 1 and 65535")
    if any(ord(c) < 32 or c.isspace() for c in value) or "\\" in value:
        raise ValueError("Target URL contains whitespace or a backslash")
    return urlunsplit(parsed._replace(fragment=""))


def candidates(base_url: str, wordlist: str | None = None) -> list[str]:
    """Try the exact URL first, then paths beneath its prefix and the origin."""
    base_url = validate_url(base_url)
    parsed = urlsplit(base_url)
    paths = DEFAULT_PATHS
    if wordlist:
        entries = []
        with Path(wordlist).open(encoding="utf-8") as source:
            for line in source:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if len(line) > 2048 or len(entries) >= MAX_CANDIDATES:
                    raise ValueError("Discovery wordlist exceeds candidate/line limits")
                if urlsplit(line).scheme or line.startswith("//") or "\\" in line or ".." in line.split("/") or "?" in line or "#" in line:
                    raise ValueError("Discovery wordlist must contain paths on the target origin")
                entries.append(line.lstrip("/"))
        paths = tuple(entries)
    origin = urlunsplit(parsed._replace(path="", query="", fragment=""))
    prefix = parsed.path.rstrip("/")
    urls = [base_url]
    for root in dict.fromkeys((origin + prefix, origin)):
        for path in paths:
            candidate = validate_url(root.rstrip("/") + "/" + path)
            if candidate not in urls:
                urls.append(candidate)
                if len(urls) > MAX_CANDIDATES:
                    raise ValueError(f"Discovery exceeds {MAX_CANDIDATES} candidate URLs")
    return urls


def _origin(url: str) -> tuple[str, str | None, int]:
    """Normalize an origin for redirect credential isolation."""
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def _recognize(body: object, alias: str) -> tuple[bool, str]:
    """Require a query-dependent response or a specific GraphQL validation error."""
    if not isinstance(body, dict):
        return False, "Response is not a GraphQL object"
    data = body.get("data")
    if isinstance(data, dict) and isinstance(data.get(alias), str) and data[alias]:
        return True, "GraphQL __typename probe returned the requested alias"
    errors = body.get("errors")
    if isinstance(errors, list):
        for error in errors:
            if not isinstance(error, dict) or not isinstance(error.get("message"), str):
                continue
            message = error["message"].lower()
            locations = error.get("locations")
            code = (error.get("extensions") or {}).get("code") if isinstance(error.get("extensions", {}), dict) else None
            structured = (isinstance(locations, list) and any(isinstance(loc, dict) and "line" in loc and "column" in loc for loc in locations))
            specific = bool(re.search(r"cannot query field|unknown (field|operation)|syntax error|introspection.*(disabled|not allowed)|__typename", message))
            if specific and (structured or code in {"GRAPHQL_VALIDATION_FAILED", "GRAPHQL_PARSE_FAILED"}):
                return True, "GraphQL validation response: " + error["message"]
        return False, "Unverified errors response (possibly authentication required)"
    return False, "No query-dependent GraphQL response"


def _probe(session: requests.Session, url: str, method: str, timeout: float, deadline: float) -> Endpoint:
    """Probe with bounded response reads and same-origin redirects only."""
    alias = "graphqler_" + uuid.uuid4().hex
    payload = {"query": f"query GraphQLerDiscovery {{ {alias}: __typename }}"}
    original = url
    for _ in range(4):
        started = time.monotonic()
        remaining = min(timeout, deadline - started)
        if remaining <= 0:
            raise TimeoutError("Discovery time budget exhausted")
        response = None
        try:
            response = session.request(method, url, json=payload if method == "POST" else None,
                                       params=payload if method == "GET" else None, timeout=remaining,
                                       allow_redirects=False, stream=True)
            content = bytearray()
            for chunk in response.iter_content(8192):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Discovery time budget exhausted")
                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError("Discovery response exceeds 1 MiB")
                content.extend(chunk)
            response._content = bytes(content)
            store = active_store()
            if store:
                store.request(url, method, payload, response, time.monotonic() - started)
            if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("Location"):
                target = validate_url(urljoin(url, response.headers["Location"]))
                if _origin(target) != _origin(original):
                    return Endpoint(url, method, response.status_code, False, "Cross-origin redirect was not followed")
                url = target
                continue
            try:
                body = json.loads(response.content)
            except (ValueError, UnicodeDecodeError):
                body = None
            confirmed, evidence = _recognize(body, alias)
            # A GraphQL-shaped unavailable response is still an unavailable endpoint.
            confirmed = confirmed and response.status_code in {200, 400, 401, 403, 422}
            return Endpoint(url, method, response.status_code, confirmed, evidence)
        except (requests.RequestException, ValueError) as exc:
            if store := active_store():
                store.request(url, method, payload, elapsed=time.monotonic() - started, error=str(exc))
            return Endpoint(url, method, response.status_code if response is not None else None, False, str(exc))
        finally:
            if response is not None:
                response.close()
    return Endpoint(url, method, None, False, "Redirect limit reached")


def discover(base_url: str, wordlist: str | None = None, timeout: float = 5, max_time: float = 60,
             first: bool = False) -> list[Endpoint]:
    """Discover endpoints, keeping every probe in SQLite; first selects a POST endpoint for scanning."""
    if timeout <= 0 or max_time <= 0 or not math.isfinite(timeout) or not math.isfinite(max_time):
        raise ValueError("Discovery timeouts must be finite and positive")
    urls = candidates(base_url, wordlist)
    deadline = time.monotonic() + max_time
    observations = []
    with request_utils.create_new_session() as session:
        for url in urls:
            for method in ("POST", "GET"):
                endpoint = _probe(session, url, method, timeout, deadline)
                observations.append(endpoint)
                if store := active_store():
                    store.endpoint(endpoint.url, endpoint.method, endpoint.status_code, endpoint.confirmed, endpoint.evidence)
                if endpoint.confirmed:
                    if first and method == "POST":
                        return observations
                    break
    if observations and not any(item.status_code is not None for item in observations):
        raise RuntimeError("Discovery failed: no HTTP responses received; inspect recorded transport errors")
    return observations


def write_discovery(directory: str | Path, observations: list[Endpoint]) -> None:
    """Write a compact discovery report in addition to the canonical catalog."""
    store = active_store()
    report = {"schema_version": "graphqler/v1", "run_id": store.run_id if store else None,
              "endpoints": [asdict(item) for item in observations]}
    if store:
        store.write_json(Path(directory) / "discovery.json", report)
    else:
        Path(directory, "discovery.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
