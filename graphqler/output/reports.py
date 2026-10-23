"""Portable finding reports, suitable for humans and automated consumers."""

from collections import Counter
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re

from .store import SCHEMA_VERSION, ResultStore, utc_now
from .files import atomic_writer, remove_output

FORMATS = {"sqlite", "jsonl", "markdown", "universal"}


def parse_formats(values: list[str] | str | None, provenance: bool = False) -> set[str]:
    """Normalize repeated/comma-separated format options without silently ignoring errors."""
    if not values:
        return {"sqlite", "jsonl", "markdown"} | ({"universal"} if provenance else set())
    if isinstance(values, str):
        values = [values]
    formats = {value.strip().lower() for group in values for value in group.split(",")}
    if "all" in formats:
        formats = (formats - {"all"}) | {"sqlite", "jsonl", "markdown"} | ({"universal"} if provenance else set())
    if unknown := formats - FORMATS:
        raise ValueError(f"Unknown output format(s): {', '.join(sorted(unknown))}; choose sqlite,jsonl,markdown,universal,all")
    if "universal" in formats:
        if not provenance:
            raise ValueError("Universal output requires both --customer-id and --job-id")
        formats.add("jsonl")  # source_ref back-pointers always remain resolvable.
    return formats


def _fence(value: str, language: str = "text") -> str:
    """Quote evidence without allowing an embedded backtick run to close its fence."""
    fence = "`" * max(3, max((len(match) + 1 for match in re.findall(r"`+", value)), default=3))
    return f"{fence}{language}\n{value}\n{fence}\n"


def _inline(value: str) -> str:
    """Escape untrusted report headings and table cells."""
    return re.sub(r"([\\`*_{}\[\]()#+.!|<>])", r"\\\1", value.replace("\n", " ").replace("\r", " "))


def write_findings(directory: Path, stores: list[ResultStore], formats: set[str]) -> None:
    """Stream positive findings as JSONL and Markdown, grouped by target/run."""
    json_path, markdown_path = directory / "findings.jsonl", directory / "findings.md"
    for name, path in (("jsonl", json_path), ("markdown", markdown_path)):
        if name not in formats:
            remove_output(path, stores[0].output_root)
    if not formats & {"jsonl", "markdown"}:
        return
    with ExitStack() as stack:
        json_out = stack.enter_context(atomic_writer(json_path, stores[0].output_root) if "jsonl" in formats else open(os.devnull, "w"))
        markdown = stack.enter_context(atomic_writer(markdown_path, stores[0].output_root) if "markdown" in formats else open(os.devnull, "w"))
        markdown.write("# GraphQLer findings\n\n")
        for store in stores:
            with store.connect() as db:
                run = db.execute("SELECT * FROM runs WHERE run_id=?", (store.run_id,)).fetchone()
                markdown.write(f"## {_inline(run['target'] or 'Offline compilation')}\n\n")
                markdown.write(f"Run: `{store.run_id}`  \nStatus: **{run['status']}**  \nMode: `{run['mode']}`\n\n")
                if run["error"]:
                    markdown.write(_fence(run["error"]) + "\n")
                findings = db.execute("SELECT * FROM findings WHERE run_id=? ORDER BY id", (store.run_id,))
                count = 0
                for row in findings:
                    count += 1
                    data = store._decode_row(row)
                    data["target"] = run["target"]
                    json_out.write(store.encode({"schema_version": SCHEMA_VERSION, "record_type": "finding", "run_id": store.run_id, "data": data}) + "\n")
                    markdown.write(f"### {_inline(data['detector'])} — {_inline(data['node'])}\n\n")
                    markdown.write(f"Severity: **{data['severity']}**  \nStatus: **{data['status']}**  \nConfidence: **{data['confidence']}**  \nFinding ID: `{data['id']}`\n\n")
                    markdown.write("Evidence:\n\n" + _fence(data["evidence"]) + "\n")
                    payload = data["payload"] if isinstance(data["payload"], str) else json.dumps(data["payload"], indent=2)
                    markdown.write("Payload:\n\n" + _fence(payload, "graphql") + "\n")
                    if data["result_id"]:
                        result = db.execute("SELECT status_code,response_json FROM results WHERE id=?", (data["result_id"],)).fetchone()
                        if result:
                            body = result["response_json"]
                            suffix = "\n[Preview truncated; full response is in the raw results.]" if len(body) > 16384 else ""
                            markdown.write(f"Response (HTTP {result['status_code']}):\n\n" + _fence(body[:16384] + suffix, "json") + "\n")
                if not count:
                    markdown.write("No positive findings recorded. Consult run status and raw results for scan completeness.\n\n")
        markdown.write("Severity is a tool classification; confirmed describes detector evidence, not human triage.\n")


def batch_report(directory: Path, stores: list[ResultStore], batch_id: str, formats: set[str], requested_targets: list[str] | None = None,
                 status_override: str | None = None) -> dict:
    """Publish a batch manifest and selected aggregate exports after every target finishes."""
    reports = [store.run_info() for store in stores]
    completed = sum(report["status"] == "completed" for report in reports)
    status = "completed" if completed == len(reports) else "partial" if completed else "failed"
    if any(report["status"] == "interrupted" for report in reports):
        status = "interrupted"
    elif requested_targets and len(stores) < len(requested_targets):
        status = "partial" if completed else "failed"
    status = status_override or status
    counts: Counter[str] = Counter()
    targets = []
    for store, run in zip(stores, reports):
        run_counts = store.counts()
        counts.update(run_counts)
        targets.append({"run_id": store.run_id, "target": run["target"], "status": run["status"], "error": run["error"],
                        "directory": store.directory.relative_to(directory).as_posix(), "counts": run_counts})
    output = directory / "results.jsonl"
    records_hash = None
    if "jsonl" in formats:
        with atomic_writer(output, directory) as destination:
            for store in stores:
                for record in store.records():
                    destination.write(store.encode(record) + "\n")
        with output.open("rb") as source:
            records_hash = hashlib.file_digest(source, "sha256").hexdigest()
    else:
        remove_output(output, directory)
    if "universal" in formats:
        from .universal import export_universal
        export_universal(stores[0], directory, stores)
    else:
        for name in ("records.jsonl", "manifest.json"):
            remove_output(directory / "universal" / name, directory)
    write_findings(directory, stores, formats)
    manifest = {"schema_version": SCHEMA_VERSION, "batch_id": batch_id, "tool": "graphqler", "tool_version": stores[0].tool_version,
                "status": status, "generated_at": utc_now(), "targets": targets, "counts": dict(counts),
                "succeeded": completed, "failed": len(reports) - completed, "formats": sorted(formats),
                "unprocessed_targets": [stores[0].redactor.url(url) for url in requested_targets[len(stores):]] if requested_targets else [],
                "database": "results.sqlite3" if "sqlite" in formats else None,
                "records": "results.jsonl" if "jsonl" in formats else None, "records_sha256": records_hash}
    stores[0].write_json(directory / "manifest.json", manifest)
    return manifest
