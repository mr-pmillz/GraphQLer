"""Credential redaction for evidence, independent of export schema metadata."""

import html
import json
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from graphqler import config

SENSITIVE_NAME = re.compile(r"authorization|cookie|token|api[-_]?key|secret|password|passwd", re.IGNORECASE)


class Redactor:
    """Remember this run's configured secrets, including common serialized forms."""

    def __init__(self):
        self.secrets: set[str] = set()

    def add(self, value) -> None:
        if not isinstance(value, str) or not value:
            return
        values = {value}
        if value.lower().startswith(("bearer ", "basic ")) and len(value.split(None, 1)) == 2:
            values.add(value.split(None, 1)[1])
        for item in values:
            self.secrets.update((item, json.dumps(item, ensure_ascii=False)[1:-1], json.dumps(item)[1:-1], quote(item, safe=""), html.escape(item)))

    def headers(self, headers: dict) -> None:
        for name, value in (headers or {}).items():
            if SENSITIVE_NAME.search(name):
                self.add(value)
                if "cookie" in name.lower() and isinstance(value, str):
                    for part in value.split(";"):
                        if "=" in part:
                            self.add(part.split("=", 1)[1].strip())

    def capture(self) -> None:
        for value in (config.AUTHORIZATION, config.IDOR_SECONDARY_AUTH, config.LLM_API_KEY):
            self.add(value)
        self.headers(config.CUSTOM_HEADERS)
        for profile in (config.PROFILES or {}).values():
            if isinstance(profile, str):
                self.add(profile)
            elif isinstance(profile, dict):
                self.add(profile.get("auth_token"))
                self.headers(profile.get("headers", {}))
        if config.PROXY:
            try:
                parsed = urlsplit(config.PROXY)
                self.add(unquote(parsed.password or ""))
            except ValueError:
                self.add(config.PROXY)

    def remember_url(self, url: str) -> None:
        for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if SENSITIVE_NAME.search(key):
                self.add(value)

    def text(self, value: str) -> str:
        for secret in sorted(self.secrets, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value

    def body(self, value: str) -> str:
        """Decode JSON escapes before scrubbing credentials from serialized evidence."""
        try:
            parsed = json.loads(value)
        except (ValueError, RecursionError):
            return self.text(value)
        cleaned = self.data(parsed)
        return json.dumps(cleaned, ensure_ascii=False) if cleaned != parsed else self.text(value)

    def data(self, value):
        if not isinstance(value, (dict, list, tuple)):
            return self.text(value) if isinstance(value, str) else value
        result = {} if isinstance(value, dict) else []
        memo = {id(value): result}
        pending = [(value, result)]
        while pending:
            source, target = pending.pop()
            for key, item in source.items() if isinstance(source, dict) else enumerate(source):
                key = self.text(str(key)) if isinstance(source, dict) else key
                if isinstance(item, (dict, list, tuple)):
                    if id(item) not in memo:
                        memo[id(item)] = {} if isinstance(item, dict) else []
                        pending.append((item, memo[id(item)]))
                    cleaned = memo[id(item)]
                else:
                    cleaned = self.text(item) if isinstance(item, str) else item
                if isinstance(target, dict):
                    target[key] = cleaned
                else:
                    target.append(cleaned)
        return result

    def url(self, value: str) -> str:
        """Keep URL authority intact while masking credentials in query parameters."""
        parsed = urlsplit(value)
        if not parsed.query:
            return value
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        cleaned = [(key, "[REDACTED]" if SENSITIVE_NAME.search(key) else self.text(item)) for key, item in pairs]
        return urlunsplit(parsed._replace(query=urlencode(cleaned))) if cleaned != pairs else value
