"""SQLite is authoritative; JSONL exports are portable snapshots of one run.

Connections are short lived so workers never inherit an open SQLite connection.
Every observation commits independently, including during interrupted scans.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import wraps
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from graphqler import config

SCHEMA_VERSION = "graphqler/v1"
DATABASE_VERSION = 1
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_active: ResultStore | None = None
_SENSITIVE_HEADER = re.compile(r"authorization|cookie|token|api[-_]?key|secret", re.IGNORECASE)
DETECTOR_SEVERITY = {
    "Introspection Enabled": "info",
    "Field Suggestions Enabled": "info",
    "SQL Injection (SQLi) Injection": "high",
    "Time-based SQL Injection (Blind SQLi)": "high",
    "NoSQL Injection (NoSQLi)": "high",
    "OS Command Injection": "high",
    "Path Injection": "high",
    "IDOR / ID Enumeration": "high",
    "IDOR_CHAIN": "high",
}

DDL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, schema_version TEXT NOT NULL, tool_version TEXT NOT NULL,
    target TEXT NOT NULL, mode TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
    status TEXT NOT NULL, error TEXT, customer_id TEXT, job_id TEXT, summary_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), url TEXT NOT NULL,
    method TEXT NOT NULL, status_code INTEGER, confirmed INTEGER NOT NULL, evidence TEXT NOT NULL,
    observed_at TEXT NOT NULL, UNIQUE(run_id, url, method)
);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), url TEXT NOT NULL,
    method TEXT NOT NULL, payload_json TEXT NOT NULL, status_code INTEGER,
    response_headers_json TEXT NOT NULL, response_body TEXT NOT NULL,
    elapsed_seconds REAL NOT NULL, error TEXT, observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), node TEXT NOT NULL,
    graphql_type TEXT NOT NULL, result_type TEXT NOT NULL, success INTEGER NOT NULL,
    status_code INTEGER, payload_json TEXT NOT NULL, response_json TEXT NOT NULL,
    errors_json TEXT NOT NULL, raw_response TEXT NOT NULL, observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), detector TEXT NOT NULL,
    node TEXT NOT NULL, status TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL,
    payload_json TEXT NOT NULL, evidence TEXT NOT NULL, result_id INTEGER REFERENCES results(id),
    observed_at TEXT NOT NULL, UNIQUE(run_id, detector, node)
);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id), path TEXT NOT NULL,
    role TEXT NOT NULL, media_type TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
    stored_bytes INTEGER NOT NULL, truncated INTEGER NOT NULL, content BLOB NOT NULL,
    UNIQUE(run_id, path)
);
CREATE INDEX IF NOT EXISTS results_by_run_node ON results(run_id, node);
CREATE INDEX IF NOT EXISTS requests_by_run ON requests(run_id);
CREATE INDEX IF NOT EXISTS findings_by_run ON findings(run_id);
"""


def utc_now() -> str:
    """Return an RFC3339 UTC timestamp."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def active_store() -> ResultStore | None:
    """Return the current execution's catalog, if recording is enabled."""
    return _active


@contextmanager
def recording(store: ResultStore) -> Generator[ResultStore]:
    """Bind a catalog for CLI, Python API, or worker execution."""
    global _active
    previous, _active = _active, store
    try:
        yield store
    finally:
        _active = previous


@contextmanager
def scan_run(directory: str | Path, target: str, mode: str, customer_id: str | None = None, job_id: str | None = None) -> Generator[ResultStore]:
    """Catalog a complete CLI or embedded pipeline, reusing an enclosing run."""
    if existing := active_store():
        if existing.directory != Path(directory).resolve():
            raise ValueError("An active scan cannot write to a different output directory")
        yield existing
        return
    store = ResultStore(directory, target, mode, customer_id, job_id)
    with recording(store):
        try:
            yield store
        except KeyboardInterrupt:
            store.finish("interrupted", "Interrupted by user")
            raise
        except TimeoutError as exc:
            store.finish("timed_out", str(exc))
            raise
        except BaseException as exc:
            store.finish("failed", str(exc))
            raise
        else:
            store.finish()


def cataloged(mode: str):
    """Give standalone compiler/fuzzer methods the same catalog contract as the CLI."""
    def decorate(method):
        @wraps(method)
        def run(self, *args, **kwargs):
            with scan_run(self.save_path, self.url, mode):
                return method(self, *args, **kwargs)
        return run
    return decorate


class ResultStore:
    """Own one run in a multi-run SQLite catalog without retaining connections."""

    def __init__(self, directory: str | Path, target: str, mode: str, customer_id: str | None = None, job_id: str | None = None,
                 database: str | Path | None = None, formats: set[str] | None = None, output_root: str | Path | None = None):
        if bool(customer_id) != bool(job_id):
            raise ValueError("--customer-id and --job-id must be supplied together")
        if customer_id is not None and (not customer_id.strip() or not job_id or not job_id.strip()):
            raise ValueError("Provenance identifiers must not be blank")
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.output_root = Path(output_root).resolve() if output_root else self.directory
        self.path = Path(database).resolve() if database else self.directory / "results.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.formats = formats if formats is not None else {"sqlite", "jsonl", "markdown"} | ({"universal"} if customer_id and job_id else set())
        self.run_id = str(uuid.uuid4())
        self.target = target
        self.mode = mode
        self.customer_id, self.job_id = customer_id, job_id
        self._before = self._artifact_snapshot()
        try:
            self.tool_version = version("GraphQLer")
        except PackageNotFoundError:
            self.tool_version = "unknown"
        with self.connect() as db:
            schema = db.execute("PRAGMA user_version").fetchone()[0]
            if schema not in (0, DATABASE_VERSION):
                raise ValueError(f"Unsupported results database version: {schema}")
            if schema == 0 and db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                raise ValueError("Refusing to initialize an unrelated SQLite database")
            db.executescript(DDL)
            db.execute(f"PRAGMA user_version = {DATABASE_VERSION}")
            db.execute(
                "INSERT INTO runs (run_id,schema_version,tool_version,target,mode,started_at,status,customer_id,job_id) VALUES (?,?,?,?,?,?,?,?,?)",
                (self.run_id, SCHEMA_VERSION, self.tool_version, self.clean(target), mode, utc_now(), "running", customer_id, job_id),
            )

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection]:
        """Commit or roll back a bounded transaction and always close its connection."""
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def clean(self, value: str) -> str:
        """Remove configured credentials from evidence without removing target data by field name."""
        secrets = [config.AUTHORIZATION, config.IDOR_SECONDARY_AUTH, config.LLM_API_KEY]
        secrets.extend(v for k, v in (config.CUSTOM_HEADERS or {}).items() if _SENSITIVE_HEADER.search(k))
        for profile in config.PROFILES.values():
            if isinstance(profile, str):
                secrets.append(profile)
            elif isinstance(profile, dict):
                secrets.append(profile.get("auth_token", ""))
                secrets.extend(v for k, v in profile.get("headers", {}).items() if _SENSITIVE_HEADER.search(k))
        for secret in sorted({str(s) for s in secrets if s}, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value

    def json(self, value: Any) -> str:
        """Serialize JSON after redacting string values (including escaped secrets)."""
        def scrub(item: Any) -> Any:
            if isinstance(item, str):
                return self.clean(item)
            if isinstance(item, dict):
                return {self.clean(str(k)): scrub(v) for k, v in item.items()}
            if isinstance(item, (list, tuple)):
                return [scrub(v) for v in item]
            return item
        return json.dumps(scrub(value), ensure_ascii=False, sort_keys=True, allow_nan=False)

    def set_target(self, target: str) -> None:
        """Select the discovered endpoint while retaining all discovery probes."""
        self.target = target
        with self.connect() as db:
            db.execute("UPDATE runs SET target=? WHERE run_id=?", (self.clean(target), self.run_id))

    def endpoint(self, url: str, method: str, status: int | None, confirmed: bool, evidence: str) -> None:
        """Record a positive or negative endpoint probe; confirmation is monotonic."""
        with self.connect() as db:
            db.execute(
                """INSERT INTO endpoints (run_id,url,method,status_code,confirmed,evidence,observed_at) VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(run_id,url,method) DO UPDATE SET status_code=excluded.status_code,
                confirmed=MAX(endpoints.confirmed,excluded.confirmed),
                evidence=CASE WHEN excluded.confirmed OR NOT endpoints.confirmed THEN excluded.evidence ELSE endpoints.evidence END""",
                (self.run_id, self.clean(url), method, status, confirmed, self.clean(evidence), utc_now()),
            )

    def request(self, url: str, method: str, payload: Any, response: Any = None, elapsed: float = 0, error: str | None = None) -> None:
        """Persist one transport observation, including errors and non-GraphQL responses."""
        headers = {k: "[REDACTED]" if _SENSITIVE_HEADER.search(k) else v for k, v in response.headers.items()} if response is not None else {}
        with self.connect() as db:
            db.execute(
                """INSERT INTO requests (run_id,url,method,payload_json,status_code,response_headers_json,response_body,elapsed_seconds,error,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (self.run_id, self.clean(url), method, self.json(payload), response.status_code if response is not None else None,
                 self.json(headers), self.clean(response.text) if response is not None else "", elapsed, self.clean(error) if error else None, utc_now()),
            )

    def result(self, node: Any, result: Any) -> None:
        """Persist every engine observation once, independent of legacy snapshot saves."""
        with self.connect() as db:
            db.execute(
                """INSERT INTO results (run_id,node,graphql_type,result_type,success,status_code,payload_json,response_json,errors_json,raw_response,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (self.run_id, node.name, node.graphql_type, result.type, result.success, result.status_code or None,
                 self.json(result.payload), self.json(result.graphql_response), self.json(result.errors), self.clean(result.raw_response_text), utc_now()),
            )

    def finding(self, detector: str, node: str, confirmed: bool, potential: bool, payload: Any, evidence: str) -> None:
        """Upsert a positive finding without downgrading previously confirmed evidence."""
        if not (confirmed or potential):
            return
        severity = DETECTOR_SEVERITY.get(detector, "medium")
        confidence = "confirmed" if confirmed else "low"
        payload_json = self.json(payload)
        with self.connect() as db:
            result = db.execute(
                "SELECT id FROM results WHERE run_id=? AND node=? AND payload_json=? ORDER BY id DESC LIMIT 1",
                (self.run_id, node, payload_json),
            ).fetchone()
            db.execute(
                """INSERT INTO findings (run_id,detector,node,status,severity,confidence,payload_json,evidence,result_id,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id,detector,node) DO UPDATE SET
                status=excluded.status,confidence=excluded.confidence,payload_json=excluded.payload_json,
                evidence=excluded.evidence,result_id=excluded.result_id
                WHERE findings.status != 'confirmed' OR excluded.status = 'confirmed'""",
                (self.run_id, detector, node, "confirmed" if confirmed else "potential", severity, confidence,
                 payload_json, self.clean(evidence), result[0] if result else None, utc_now()),
            )

    def summary(self, report: dict) -> None:
        """Checkpoint aggregate statistics separately from append-only observations."""
        with self.connect() as db:
            db.execute("UPDATE runs SET summary_json=? WHERE run_id=?", (self.json(report), self.run_id))

    def run_info(self) -> dict:
        """Read authoritative completion state, including rows written by a child process."""
        with self.connect() as db:
            return self._decode_row(db.execute("SELECT * FROM runs WHERE run_id=?", (self.run_id,)).fetchone())

    def _artifact_snapshot(self) -> dict[str, tuple[int, int]]:
        """List only known output locations, never credentials, pickles, or exports."""
        candidates = []
        for name in ("compiled", "extracted", "logs", "detections", "endpoint_results", "eval", "graphs"):
            root = self.directory / name
            if root.exists() and not root.is_symlink():
                candidates.extend(root.rglob("*"))
        candidates.extend(self.directory.glob("*.json"))
        candidates.extend(self.directory.glob("*.txt"))
        candidates.extend(self.directory.glob("*.png"))
        candidates.extend(self.directory.glob("*.pdf"))
        candidates.extend(self.directory.glob("*.md"))
        result = {}
        for path in candidates:
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(self.directory):
                continue
            if path.name in {"manifest.json", "discovery.json", "findings.md"}:
                continue
            stat = path.stat()
            result[path.relative_to(self.directory).as_posix()] = (stat.st_mtime_ns, stat.st_size)
        return result

    def catalog_artifacts(self) -> None:
        """Embed bounded artifacts with full-source hashes, sizes, and explicit truncation."""
        for name, fingerprint in self._artifact_snapshot().items():
            unchanged = self._before.get(name) == fingerprint
            uses_existing_schema = self.mode in {"fuzz", "single", "idor", "chain", "compile-chains"}
            is_input = uses_existing_schema and (name.startswith(("compiled/", "extracted/")) or name == "introspection_result.json")
            if unchanged and not is_input:
                continue
            path = self.directory / name
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                source.seek(0)
                content = source.read(MAX_ARTIFACT_BYTES)
            media_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            try:
                content = self.clean(content.decode("utf-8")).encode("utf-8")
            except UnicodeDecodeError:
                pass
            with self.connect() as db:
                db.execute(
                    """INSERT OR REPLACE INTO artifacts (run_id,path,role,media_type,sha256,size_bytes,stored_bytes,truncated,content)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (self.run_id, name, "input" if unchanged else "output", media_type, digest.hexdigest(), fingerprint[1],
                     len(content), fingerprint[1] > MAX_ARTIFACT_BYTES, content),
                )

    def finish(self, status: str = "completed", error: str | None = None) -> None:
        """Finalize a run and export it, preserving failure status and prior committed rows."""
        with self.connect() as db:
            db.execute("UPDATE runs SET status=?,error=?,finished_at=? WHERE run_id=?",
                       (status, self.clean(error) if error else None, utc_now(), self.run_id))
        try:
            self.catalog_artifacts()
            self.export()
        except Exception as exc:
            with self.connect() as db:
                db.execute("UPDATE runs SET status='failed',error=? WHERE run_id=?", (self.clean(f"Result export failed: {exc}"), self.run_id))
            raise

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> dict:
        """Expose JSON columns as objects in the portable format."""
        data = dict(row)
        for key in list(data):
            if key.endswith("_json"):
                data[key[:-5]] = json.loads(data.pop(key))
        for key in ("success", "confirmed", "truncated"):
            if key in data:
                data[key] = bool(data[key])
        return data

    def export(self) -> None:
        """Atomically replace current-run JSONL and publish its manifest last."""
        counts = {}
        output = self.directory / "results.jsonl"
        temporary = output.with_suffix(".jsonl.tmp")
        with self.connect() as db, temporary.open("w", encoding="utf-8") as stream:
            for table, kind in (("runs", "run"), ("endpoints", "endpoint"), ("requests", "request"),
                                ("results", "result"), ("findings", "finding"), ("artifacts", "artifact")):
                columns = "id,run_id,path,role,media_type,sha256,size_bytes,stored_bytes,truncated" if table == "artifacts" else "*"
                counts[kind] = 0
                for row in db.execute(f"SELECT {columns} FROM {table} WHERE run_id=? ORDER BY rowid", (self.run_id,)):
                    record = {"schema_version": SCHEMA_VERSION, "run_id": self.run_id, "record_type": kind, "data": self._decode_row(row)}
                    stream.write(self.json(record) + "\n")
                    counts[kind] += 1
            run = dict(db.execute("SELECT * FROM runs WHERE run_id=?", (self.run_id,)).fetchone())
        records_hash = None
        if "jsonl" in self.formats:
            temporary.replace(output)
            with output.open("rb") as source:
                records_hash = hashlib.file_digest(source, "sha256").hexdigest()
        else:
            temporary.unlink()
            output.unlink(missing_ok=True)
        if "universal" in self.formats:
            from .universal import export_universal
            export_universal(self)
        else:
            # An invocation without provenance must not expose a previous run's export.
            for name in ("manifest.json", "records.jsonl"):
                (self.directory / "universal" / name).unlink(missing_ok=True)
        from .reports import write_findings
        write_findings(self.directory, [self], self.formats)
        manifest = {"schema_version": SCHEMA_VERSION, "database_version": DATABASE_VERSION, "run_id": self.run_id,
                    "tool": "graphqler", "tool_version": self.tool_version, "status": run["status"], "error": run["error"],
                    "target": run["target"], "started_at": run["started_at"], "finished_at": run["finished_at"],
                    "counts": counts, "formats": sorted(self.formats),
                    "database": self.path.relative_to(self.directory, walk_up=True).as_posix() if "sqlite" in self.formats else None,
                    "records": "results.jsonl" if "jsonl" in self.formats else None,
                    "records_sha256": records_hash}
        self.write_json(self.directory / "manifest.json", manifest)

    def write_json(self, path: Path, data: dict) -> None:
        """Publish a JSON document with atomic replacement."""
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(self.json(data) + "\n", encoding="utf-8")
        temporary.replace(path)
