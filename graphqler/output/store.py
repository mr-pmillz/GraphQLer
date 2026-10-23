"""SQLite is authoritative; JSONL exports are portable snapshots of one run.

Connections are short lived so workers never inherit an open SQLite connection.
Every observation commits independently, including during interrupted scans.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
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
from .files import atomic_writer, ensure_directory, prepare_database, remove_output
from .redaction import Redactor, SENSITIVE_NAME

SCHEMA_VERSION = "graphqler/v1"
DATABASE_VERSION = 1
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_active: ResultStore | None = None
_SENSITIVE_HEADER = SENSITIVE_NAME
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

TABLES = (("runs", "run"), ("endpoints", "endpoint"), ("requests", "request"),
          ("results", "result"), ("findings", "finding"), ("artifacts", "artifact"))


class ResultExportError(RuntimeError):
    """Keep access to durable rows when a selected report cannot be published."""

    def __init__(self, store: "ResultStore", error: Exception):
        self.store = store
        super().__init__(store.clean(f"Result export failed: {error}"))


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
        if target and existing.target and target != existing.target:
            raise ValueError("An active scan cannot record a different target")
        yield existing
        return
    store = ResultStore(directory, target, mode, customer_id, job_id)
    with recording(store):
        try:
            yield store
        except KeyboardInterrupt as exc:
            try:
                store.finish("interrupted", "Interrupted by user")
            except Exception as export_error:
                exc.add_note(store.clean(f"Interrupted results could not be exported: {export_error}"))
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
        self.output_root = Path(output_root).resolve() if output_root else Path(directory).resolve()
        self.output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        candidate = Path(os.path.abspath(directory)) if output_root else self.output_root
        ensure_directory(candidate, self.output_root)
        self.directory = candidate.resolve()
        self.path = Path(os.path.abspath(database)) if database else self.directory / "results.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        from .reports import parse_formats
        self.formats = parse_formats(list(formats) if formats is not None else None, bool(customer_id and job_id))
        prepare_database(self.path)
        self.redactor = Redactor()
        self.redactor.capture()
        self.redactor.remember_url(target)
        self._finalized = False
        self.run_id = str(uuid.uuid4())
        self.target = target
        self.requested_target = target
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
                (self.run_id, SCHEMA_VERSION, self.tool_version, self.redactor.url(target), mode, utc_now(), "running", customer_id, job_id),
            )
        try:
            self.write_manifest()
        except Exception as exc:
            self.mark_failed(f"Cannot initialize output manifest: {exc}")
            raise ResultExportError(self, exc) from exc

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
        if not self._finalized:
            self.redactor.capture()
        return self.redactor.text(value)

    def json(self, value: Any) -> str:
        """Serialize JSON after redacting string values (including escaped secrets)."""
        if not self._finalized:
            self.redactor.capture()
        return self.encode(self.redactor.data(value))

    @staticmethod
    def encode(value: Any) -> str:
        """Encode already-scrubbed data without altering schema keys, enums, or IDs."""
        return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)

    def set_target(self, target: str) -> None:
        """Select the discovered endpoint while retaining all discovery probes."""
        self.target = target
        self.redactor.remember_url(target)
        with self.connect() as db:
            db.execute("UPDATE runs SET target=? WHERE run_id=?", (self.redactor.url(target), self.run_id))

    def endpoint(self, url: str, method: str, status: int | None, confirmed: bool, evidence: str) -> None:
        """Record a positive or negative endpoint probe; confirmation is monotonic."""
        with self.connect() as db:
            db.execute(
                """INSERT INTO endpoints (run_id,url,method,status_code,confirmed,evidence,observed_at) VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(run_id,url,method) DO UPDATE SET
                status_code=CASE WHEN excluded.confirmed OR NOT endpoints.confirmed THEN excluded.status_code ELSE endpoints.status_code END,
                confirmed=MAX(endpoints.confirmed,excluded.confirmed),
                observed_at=CASE WHEN excluded.confirmed OR NOT endpoints.confirmed THEN excluded.observed_at ELSE endpoints.observed_at END,
                evidence=CASE WHEN excluded.confirmed OR NOT endpoints.confirmed THEN excluded.evidence ELSE endpoints.evidence END""",
                (self.run_id, self.redactor.url(url), method, status, confirmed, self.clean(evidence), utc_now()),
            )

    def request(self, url: str, method: str, payload: Any, response: Any = None, elapsed: float = 0, error: str | None = None) -> None:
        """Persist one transport observation, including errors and non-GraphQL responses."""
        headers = {k: "[REDACTED]" if _SENSITIVE_HEADER.search(k) else v for k, v in response.headers.items()} if response is not None else {}
        self.redactor.remember_url(url)
        with self.connect() as db:
            db.execute(
                """INSERT INTO requests (run_id,url,method,payload_json,status_code,response_headers_json,response_body,elapsed_seconds,error,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (self.run_id, self.redactor.url(url), method, self.json(payload), response.status_code if response is not None else None,
                 self.json(headers), self.redactor.body(response.text) if response is not None else "", elapsed, self.clean(error) if error else None, utc_now()),
            )

    def result(self, node: Any, result: Any) -> None:
        """Persist every engine observation once, independent of legacy snapshot saves."""
        with self.connect() as db:
            db.execute(
                """INSERT INTO results (run_id,node,graphql_type,result_type,success,status_code,payload_json,response_json,errors_json,raw_response,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (self.run_id, self.clean(node.name), node.graphql_type, result.type, result.success, result.status_code or None,
                 self.json(result.payload), self.json(result.graphql_response), self.json(result.errors), self.redactor.body(result.raw_response_text), utc_now()),
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
                (self.run_id, self.clean(node), payload_json),
            ).fetchone()
            db.execute(
                """INSERT INTO findings (run_id,detector,node,status,severity,confidence,payload_json,evidence,result_id,observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id,detector,node) DO UPDATE SET
                status=excluded.status,confidence=excluded.confidence,payload_json=excluded.payload_json,
                evidence=excluded.evidence,result_id=excluded.result_id,observed_at=excluded.observed_at
                WHERE findings.status != 'confirmed' OR excluded.status = 'confirmed'""",
                (self.run_id, detector, self.clean(node), "confirmed" if confirmed else "potential", severity, confidence,
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
        root_names = {"stats.json", "stats.txt", "unique_responses.txt", "objects_bucket.txt", "introspection_result.json", "report.md"}
        for key in ("STATS_FILE_NAME", "OBJECTS_BUCKET_TEXT_FILE_NAME", "UNIQUE_RESPONSES_FILE_NAME", "INTROSPECTION_RESULT_FILE_NAME", "GRAPH_VISUALIZATION_OUTPUT"):
            value = getattr(config, key, "")
            if isinstance(value, str) and value:
                root_names.add(value)
                if key == "GRAPH_VISUALIZATION_OUTPUT":
                    root_names.add(str(Path(value).with_suffix(".pdf")))
        candidates.extend(self.directory / name for name in root_names)
        result = {}
        for path in candidates:
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(self.directory):
                continue
            if path.name in {"manifest.json", "discovery.json", "findings.md"}:
                continue
            if path.suffix.lower() not in {".txt", ".json", ".yaml", ".yml", ".log", ".png", ".pdf", ".md", ".svg", ".csv"}:
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
                lookahead = max((len(value.encode("utf-8")) for value in self.redactor.secrets), default=0)
                content = source.read(MAX_ARTIFACT_BYTES + lookahead)
            media_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            is_text = media_type.startswith("text/") or path.suffix.lower() in {".json", ".yaml", ".yml", ".log", ".md", ".txt", ".csv", ".svg"}
            if is_text:
                content = self.redactor.body(content.decode("utf-8", errors="replace")).encode("utf-8")
            truncated = fingerprint[1] > MAX_ARTIFACT_BYTES or len(content) > MAX_ARTIFACT_BYTES
            content = content[:MAX_ARTIFACT_BYTES]
            if is_text:
                content = content.decode("utf-8", errors="ignore").encode("utf-8")
            with self.connect() as db:
                db.execute(
                    """INSERT OR REPLACE INTO artifacts (run_id,path,role,media_type,sha256,size_bytes,stored_bytes,truncated,content)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (self.run_id, name, "input" if unchanged else "output", media_type, digest.hexdigest(), fingerprint[1],
                     len(content), truncated, content),
                )

    def finish(self, status: str = "completed", error: str | None = None) -> None:
        """Finalize a run and export it, preserving failure status and prior committed rows."""
        with self.connect() as db:
            db.execute("UPDATE runs SET status=?,error=?,finished_at=? WHERE run_id=?",
                       (status, self.clean(error) if error else None, utc_now(), self.run_id))
        self.redactor.capture()
        self._finalized = True
        try:
            self.catalog_artifacts()
            self.export()
        except Exception as exc:
            export_error = ResultExportError(self, exc)
            self.mark_failed(f"{error}; {export_error}" if error else str(export_error))
            try:
                self.write_manifest()
            except (OSError, ValueError):
                pass
            raise export_error from exc

    def mark_failed(self, error: str) -> None:
        """Retain a terminal failure even when its report directory is unavailable."""
        with self.connect() as db:
            db.execute("UPDATE runs SET status='failed',error=?,finished_at=? WHERE run_id=?", (self.clean(error), utc_now(), self.run_id))

    def counts(self) -> dict[str, int]:
        with self.connect() as db:
            return {kind: db.execute(f"SELECT COUNT(*) FROM {table} WHERE run_id=?", (self.run_id,)).fetchone()[0] for table, kind in TABLES}

    def records(self):
        """Stream authoritative native rows, without depending on other export files."""
        with self.connect() as db:
            for table, kind in TABLES:
                columns = "id,run_id,path,role,media_type,sha256,size_bytes,stored_bytes,truncated" if table == "artifacts" else "*"
                for row in db.execute(f"SELECT {columns} FROM {table} WHERE run_id=? ORDER BY rowid", (self.run_id,)):
                    yield {"schema_version": SCHEMA_VERSION, "run_id": self.run_id, "record_type": kind, "data": self._decode_row(row)}

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
        output = self.directory / "results.jsonl"
        records_hash = None
        if "jsonl" in self.formats:
            with atomic_writer(output, self.output_root) as stream:
                for record in self.records():
                    stream.write(self.encode(record) + "\n")
            with output.open("rb") as source:
                records_hash = hashlib.file_digest(source, "sha256").hexdigest()
        else:
            remove_output(output, self.output_root)
        if "universal" in self.formats:
            from .universal import export_universal
            export_universal(self)
        else:
            # An invocation without provenance must not expose a previous run's export.
            for name in ("manifest.json", "records.jsonl"):
                remove_output(self.directory / "universal" / name, self.output_root)
        from .reports import write_findings
        write_findings(self.directory, [self], self.formats)
        self.write_manifest(records_hash, exported=True)

    def write_manifest(self, records_hash: str | None = None, exported: bool = False) -> None:
        """Invalidate old reports on start/failure and advertise only complete exports."""
        run = self.run_info()
        manifest = {"schema_version": SCHEMA_VERSION, "database_version": DATABASE_VERSION, "run_id": self.run_id,
                    "tool": "graphqler", "tool_version": self.tool_version, "status": run["status"], "error": run["error"],
                    "target": run["target"], "started_at": run["started_at"], "finished_at": run["finished_at"],
                    "counts": self.counts(), "formats": sorted(self.formats),
                    "database": self.path.relative_to(self.directory, walk_up=True).as_posix() if "sqlite" in self.formats else None,
                    "records": "results.jsonl" if exported and "jsonl" in self.formats else None,
                    "records_sha256": records_hash}
        self.write_json(self.directory / "manifest.json", manifest)

    def write_json(self, path: Path, data: dict) -> None:
        """Publish a JSON document with atomic replacement."""
        with atomic_writer(path, self.output_root) as stream:
            stream.write(self.encode(data) + "\n")
