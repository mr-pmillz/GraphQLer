"""Credential redaction for evidence, independent of export schema metadata."""

import html
import json
import re
from collections.abc import Mapping
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from graphqler import config

SENSITIVE_NAME = re.compile(r"authorization|cookie|token|api[-_]?key|secret|password|passwd", re.IGNORECASE)
_URL = re.compile(r"(?:https?|wss?)://[^\s<>\"'\\]+", re.IGNORECASE)


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
            self.secrets.update((item, json.dumps(item, ensure_ascii=False)[1:-1], json.dumps(item)[1:-1],
                                 quote(item, safe="", errors="surrogatepass"), html.escape(item)))

    def headers(self, headers: dict) -> None:
        if not isinstance(headers, Mapping):
            return
        for name, value in headers.items():
            if isinstance(name, str) and SENSITIVE_NAME.search(name):
                self.add(value)
                if "cookie" in name.lower() and isinstance(value, str):
                    for part in value.split(";"):
                        if "=" in part:
                            self.add(part.split("=", 1)[1].strip())

    def capture(self) -> None:
        for value in (config.AUTHORIZATION, config.IDOR_SECONDARY_AUTH, config.LLM_API_KEY):
            self.add(value)
        self.headers(config.CUSTOM_HEADERS)
        profiles = config.PROFILES if isinstance(config.PROFILES, Mapping) else {}
        for profile in profiles.values():
            if isinstance(profile, str):
                self.add(profile)
            elif isinstance(profile, dict):
                self.add(profile.get("auth_token"))
                self.headers(profile.get("headers", {}))
        if isinstance(config.PROXY, str) and config.PROXY:
            try:
                parsed = urlsplit(config.PROXY)
                self.add(unquote(parsed.password or ""))
            except ValueError:
                self.add(config.PROXY)

    def remember_url(self, url: str) -> None:
        for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if SENSITIVE_NAME.search(key):
                self.add(value)

    def _replace(self, value: str) -> str:
        for secret in sorted(self.secrets, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value

    def text(self, value: str) -> str:
        def scrub_url(match):
            try:
                return self.url(match.group())
            except ValueError:
                return "[REDACTED: invalid URL]"
        return _URL.sub(scrub_url, self._replace(value))

    def body(self, value: str) -> str:
        """Scrub JSON string tokens without depending on the document's nesting depth."""
        value = self.text(value)
        if not value.lstrip().startswith(("{", "[", '"')):
            return value
        parts = []
        offset = 0
        decoder = json.JSONDecoder(strict=False)
        while (start := value.find('"', offset)) != -1:
            parts.append(value[offset:start])
            try:
                decoded, end = decoder.raw_decode(value, start)
            except ValueError:
                # Do not retry at every escaped quote in an unterminated string.
                # Encoded secrets in an invalid string cannot be reliably decoded.
                parts.append('"[REDACTED: malformed JSON string]"' if self.secrets else value[start:])
                offset = len(value)
                break
            token = value[start:end]
            cleaned = self.text(decoded) if "\\" in token else decoded
            # ASCII escaping also keeps lone surrogate code points out of UTF-8 files.
            parts.append(json.dumps(cleaned) if cleaned != decoded else token)
            offset = end
        parts.append(value[offset:])
        return "".join(parts)

    def data(self, value):
        if not isinstance(value, (dict, list, tuple)):
            return self.body(value) if isinstance(value, str) else value
        result = {} if isinstance(value, dict) else []
        memo = {id(value): result}
        pending = [(value, result)]
        while pending:
            source, target = pending.pop()
            for key, item in source.items() if isinstance(source, dict) else enumerate(source):
                key = self.body(str(key)) if isinstance(source, dict) else key
                if isinstance(item, (dict, list, tuple)):
                    if id(item) not in memo:
                        memo[id(item)] = {} if isinstance(item, dict) else []
                        pending.append((item, memo[id(item)]))
                    cleaned = memo[id(item)]
                else:
                    cleaned = self.body(item) if isinstance(item, str) else item
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
        cleaned = [(key, "[REDACTED]" if SENSITIVE_NAME.search(key) else self._replace(item)) for key, item in pairs]
        return urlunsplit(parsed._replace(query=urlencode(cleaned))) if cleaned != pairs else value
