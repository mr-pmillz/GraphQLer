"""Input validation, isolated target execution, and automation exit codes."""

import copy
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import sys
import sqlite3
import shutil
import tempfile
import uuid

from graphqler import config
from graphqler.discovery import validate_url
from graphqler.output.reports import batch_report, parse_formats
from graphqler.output.store import ResultExportError, ResultStore, SCHEMA_VERSION
from graphqler.output.files import atomic_writer
from graphqler.output.redaction import Redactor
from graphqler.utils.config_handler import parse_config
from graphqler.utils.request_utils import reset_session


@dataclass
class _ScratchCatalog:
    path: Path
    retain: bool = False


@contextmanager
def _temporary_catalog():
    scratch = _ScratchCatalog(Path(tempfile.mkdtemp(prefix="graphqler-results-")))
    try:
        yield scratch
    finally:
        database = scratch.path / "results.sqlite3"
        if scratch.retain and database.is_file():
            print(f"(E) Export failed; recovery catalog retained at {database}", file=sys.stderr)
        else:
            shutil.rmtree(scratch.path)


def collect_targets(args: dict) -> list[str]:
    """Read, validate, and deduplicate inputs before making any requests."""
    inputs = args.get("url") or []
    inputs = [inputs] if isinstance(inputs, str) else list(inputs)
    if args.get("input"):
        with Path(args["input"]).open(encoding="utf-8-sig") as source:
            for line in iter(lambda: source.readline(8193), ""):
                if len(line) > 8192:
                    raise ValueError("Input target line exceeds 8192 characters")
                if line.strip() and not line.lstrip().startswith("#"):
                    inputs.append(line.strip())
                if len(inputs) > 10000:
                    raise ValueError("Input file exceeds 10000 targets")
    targets = []
    for group in inputs:
        for value in group.split(","):
            if value.strip():
                target = validate_url(value.strip())
                if target not in targets:
                    targets.append(target)
                if len(targets) > 10000:
                    raise ValueError("Input exceeds 10000 targets")
    if args.get("mode") == "compile-chains" and not targets:
        return [""]
    if not targets:
        raise ValueError("Provide --url or --input")
    return targets


def result_exit(stores: list, threshold: str | None = None) -> int:
    """Keep scan failures distinct from the optional finding threshold."""
    statuses = [store.run_info()["status"] for store in stores]
    completed = statuses.count("completed")
    if completed and completed < len(statuses):
        return 3
    if not completed:
        return 124 if statuses and all(status == "timed_out" for status in statuses) else 1
    if threshold:
        severities = ["info", "low", "medium", "high", "critical"]
        minimum = severities.index(threshold)
        for store in stores:
            with store.connect() as db:
                if any(severities.index(row[0]) >= minimum for row in db.execute(
                    "SELECT severity FROM findings WHERE run_id=? AND status='confirmed'", (store.run_id,)
                )):
                    return 4
    return 0


def run_batch(args: dict, run_target) -> int:
    """Execute a sequential batch with one shared database and isolated target artifacts."""
    try:
        targets = collect_targets(args)
        provenance = bool(args.get("customer_id") and args.get("job_id"))
        if bool(args.get("customer_id")) != bool(args.get("job_id")):
            raise ValueError("--customer-id and --job-id must be supplied together")
        if provenance and (not args["customer_id"].strip() or not args["job_id"].strip()):
            raise ValueError("Provenance identifiers must not be blank")
        formats = parse_formats(args.get("format"), provenance)
        if args.get("mode") not in {"discover", "compile", "compile-graph", "compile-chains", "run", "fuzz", "single", "idor"}:
            raise ValueError("Provide a valid --mode")
        if args.get("mode") == "single" and not args.get("node"):
            raise ValueError("--node is required in single mode")
        for option in ("request_timeout", "max_time", "discovery_timeout", "discovery_max_time"):
            if args.get(option) is not None and (args[option] <= 0 or not math.isfinite(args[option])):
                raise ValueError(f"--{option.replace('_', '-')} must be finite and positive")
        for option in ("max_iterations", "max_response_bytes"):
            if args.get(option) is not None and args[option] <= 0:
                raise ValueError(f"--{option.replace('_', '-')} must be positive")
        if args.get("llm_max_retries") is not None and args["llm_max_retries"] < 0:
            raise ValueError("--llm-max-retries must be nonnegative")
        for header in args.get("header") or []:
            if ":" not in header or not header.split(":", 1)[0].strip() or "\n" in header or "\r" in header:
                raise ValueError("--header must be a single Name: value header")
        if args.get("config"):
            parse_config(args["config"])
    except (ValueError, OSError) as exc:
        print(f"(E) {exc}", file=sys.stderr)
        return 2
    directory = Path(args.get("path") or config.OUTPUT_DIRECTORY).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    baseline = {key: copy.deepcopy(value) for key, value in vars(config).items() if key.isupper()}
    stores = []
    batch_id = str(uuid.uuid4())
    redactor = Redactor()
    redactor.capture()
    batch_error = None
    interrupted = False
    export_failed = False

    def write_state(status: str, error: str | None = None):
        with atomic_writer(directory / "manifest.json", directory) as stream:
            stream.write(ResultStore.encode({"schema_version": SCHEMA_VERSION, "batch_id": batch_id, "status": status,
                                            "error": error, "targets": [], "records": None, "formats": sorted(formats),
                                            "unprocessed_targets": [redactor.url(url) for url in targets]}) + "\n")

    write_state("running")
    with _temporary_catalog() as scratch:
        database = directory / "results.sqlite3" if "sqlite" in formats else scratch.path / "results.sqlite3"
        try:
            for index, target in enumerate(targets, 1):
                for key, value in baseline.items():
                    setattr(config, key, copy.deepcopy(value))
                path = directory if len(targets) == 1 else directory / "targets" / hashlib.sha256(target.encode()).hexdigest()[:16]
                options = {**args, "url": target, "path": str(path), "_database": database, "_formats": formats, "_output_root": directory}
                if len(targets) > 1 or stores and stores[0].directory != directory:
                    print(f"(B) Target {index}/{len(targets)}: {redactor.url(target)}")
                try:
                    stores.append(run_target(options))
                except ResultExportError as exc:
                    export_failed = True
                    stores.append(exc.store)
                    print(f"(E) {exc}", file=sys.stderr)
                except (OSError, ValueError, sqlite3.Error) as exc:
                    # A blocked target directory must not prevent later targets from running.
                    fallback = directory / "failures" / f"{hashlib.sha256(target.encode()).hexdigest()[:16]}-{uuid.uuid4().hex[:8]}"
                    store = ResultStore(fallback, target, args["mode"], args.get("customer_id"), args.get("job_id"),
                                        database=database, formats=formats, output_root=directory)
                    store.finish("failed", str(exc))
                    stores.append(store)
                    print(f"(E) {store.clean(str(exc))}", file=sys.stderr)
                except KeyboardInterrupt as exc:
                    export_failed = export_failed or getattr(exc, "export_failed", False)
                    if current := getattr(exc, "result_store", None):
                        stores.append(current)
                    raise
            return result_exit(stores, args.get("fail_on_findings"))
        except BaseException as exc:
            interrupted = isinstance(exc, KeyboardInterrupt)
            export_failed = export_failed or isinstance(exc, ResultExportError)
            batch_error = redactor.text(str(exc))
            raise
        finally:
            try:
                if len(targets) > 1:
                    if stores:
                        try:
                            report = batch_report(directory, stores, batch_id, formats, targets, "interrupted" if interrupted else None)
                            print(f"(RESULTS): {report['succeeded']} target(s) completed; {report['failed']} failed. Manifest: {directory / 'manifest.json'}")
                        except Exception as exc:
                            export_failed = True
                            error = redactor.text(f"Batch export failed: {exc}")
                            try:
                                write_state("interrupted" if interrupted else "failed", error)
                            except (OSError, ValueError):
                                pass
                            if not interrupted:
                                raise
                            print(f"(E) {error}", file=sys.stderr)
                    else:
                        write_state("interrupted" if interrupted else "failed", batch_error)
                elif not stores:
                    write_state("interrupted" if interrupted else "failed", batch_error)
            finally:
                scratch.retain = export_failed and "sqlite" not in formats
                for key, value in baseline.items():
                    setattr(config, key, value)
                reset_session()
