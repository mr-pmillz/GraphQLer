"""Run Clairvoyance's schema inference through the cataloged HTTP transport."""

import asyncio
import json
import logging
import time

from clairvoyance import graphql, oracle
from clairvoyance.cli import load_default_wordlist
from clairvoyance.config import Config
from clairvoyance.entities import GraphQLPrimitive
from clairvoyance.entities.context import client_ctx, logger_ctx
from clairvoyance.entities.interfaces import IClient

from graphqler import config
from graphqler.utils.request_utils import send_graphql_request_with_headers


class BoundedClient(IClient):
    """Use independent sessions with shared scan deadlines and at most eight requests."""

    def __init__(self, url: str, headers: dict, deadline: float):
        self._url = url
        self._headers = headers
        self._semaphore = asyncio.Semaphore(8)
        self.deadline = deadline

    async def post(self, document: str | None, retries: int = 0) -> dict:
        async with self._semaphore:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Blind introspection time budget exhausted")
            result, response = await asyncio.to_thread(send_graphql_request_with_headers, self._url,
                                                       {"query": document} if document else {}, self._headers, timeout=remaining)
            if response.status_code >= 500 or response.status_code in {401, 403, 429}:
                raise RuntimeError(f"Blind introspection failed with HTTP {response.status_code}")
            if not isinstance(result, dict) or not any(key in result for key in ("data", "errors")):
                raise ValueError("Blind introspection received a non-GraphQL response")
            if "errors" in result and (not isinstance(result["errors"], list) or any(
                not isinstance(error, dict) or not isinstance(error.get("message"), str) for error in result["errors"]
            )):
                raise ValueError("Blind introspection received malformed GraphQL errors")
            # The inference engine indexes errors even for successful field probes.
            return {**result, "errors": result.get("errors", [])}

    async def close(self) -> None:
        """Each HTTP exchange closes its own session."""


async def _infer(url: str, logger: logging.Logger, wordlist: list[str], headers: dict) -> str:
    Config()
    client_ctx.set(BoundedClient(url, headers, time.monotonic() + config.MAX_TIME))
    logger_ctx.set(logger)
    words = wordlist or load_default_wordlist()
    ignored = {primitive.value for primitive in GraphQLPrimitive}
    document, schema = "query { FUZZ }", None
    async with asyncio.timeout(config.MAX_TIME):
        while True:
            serialized = await oracle.clairvoyance(words, input_document=document, input_schema=schema)
            schema = json.loads(serialized)
            parsed = graphql.Schema(schema=schema)
            next_type = parsed.get_type_without_fields(ignored)
            if not next_type:
                return serialized
            ignored.add(next_type)
            document = parsed.convert_path_to_document(parsed.get_path_from_root(next_type))


async def blind_introspection(*, url: str, logger: logging.Logger, wordlist: list[str], headers: dict) -> str:
    """Isolate dependency context variables without changing its process-wide classes."""
    return await asyncio.create_task(_infer(url, logger, wordlist, headers))
