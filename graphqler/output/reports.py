"""Portable finding reports, suitable for humans and automated consumers."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from .store import SCHEMA_VERSION, ResultStore, utc_now

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
    json_temp, markdown_temp = json_path.with_suffix(".jsonl.tmp"), markdown_path.with_suffix(".md.tmp")
    with json_temp.open("w", encoding="utf-8") as json_out, markdown_temp.open("w", encoding="utf-8") as markdown:
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
                    json_out.write(store.json({"schema_version": SCHEMA_VERSION, "record_type": "finding", "run_id": store.run_id, "data": data}) + "\n")
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
    for name, temporary, path in (("jsonl", json_temp, json_path), ("markdown", markdown_temp, markdown_path)):
        if name in formats:
            temporary.replace(path)
        else:
            temporary.unlink()
            path.unlink(missing_ok=True)


def batch_report(directory: Path, stores: list[ResultStore], batch_id: str, formats: set[str], requested_targets: list[str] | None = None) -> dict:
    """Publish a batch manifest and selected aggregate exports after every target finishes."""
    reports = [store.run_info() for store in stores]
    completed = sum(report["status"] == "completed" for report in reports)
    status = "completed" if completed == len(reports) else "partial" if completed else "failed"
    if any(report["status"] == "interrupted" for report in reports):
        status = "interrupted"
    elif requested_targets and len(stores) < len(requested_targets):
        status = "partial" if completed else "failed"
    counts: Counter[str] = Counter()
    targets = []
    for store, run in zip(stores, reports):
        manifest = json.loads((store.directory / "manifest.json").read_text(encoding="utf-8"))
        counts.update(manifest["counts"])
        targets.append({"run_id": store.run_id, "target": run["target"], "status": run["status"], "error": run["error"],
                        "directory": store.directory.relative_to(directory).as_posix(), "counts": manifest["counts"]})
    output = directory / "results.jsonl"
    records_hash = None
    if "jsonl" in formats:
        temporary = output.with_suffix(".jsonl.tmp")
        with temporary.open("wb") as destination:
            for store in stores:
                with (store.directory / "results.jsonl").open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        destination.write(chunk)
        temporary.replace(output)
        with output.open("rb") as source:
            records_hash = hashlib.file_digest(source, "sha256").hexdigest()
    else:
        output.unlink(missing_ok=True)
    if "universal" in formats:
        universal = directory / "universal"
        universal.mkdir(exist_ok=True)
        entity_counts: Counter[str] = Counter()
        source_files = []
        temporary = universal / "records.jsonl.tmp"
        with temporary.open("w", encoding="utf-8") as destination:
            for store in stores:
                data = json.loads((store.directory / "universal/manifest.json").read_text())
                entity_counts.update(data["counts_by_entity"])
                source_files.extend(data["source_files"])
                with (store.directory / "universal/records.jsonl").open(encoding="utf-8") as source:
                    for line in source:
                        destination.write(line)
        temporary.replace(universal / "records.jsonl")
        stores[0].write_json(universal / "manifest.json", {
            "schema_version": "v1", "customer_id": stores[0].customer_id, "job_id": stores[0].job_id,
            "tool": "graphqler", "tool_version": stores[0].tool_version, "generated_at": utc_now(),
            "counts_by_entity": dict(entity_counts), "total_records": sum(entity_counts.values()), "source_files": source_files,
        })
    else:
        for name in ("records.jsonl", "manifest.json"):
            (directory / "universal" / name).unlink(missing_ok=True)
    write_findings(directory, stores, formats)
    manifest = {"schema_version": SCHEMA_VERSION, "batch_id": batch_id, "tool": "graphqler", "tool_version": stores[0].tool_version,
                "status": status, "generated_at": utc_now(), "targets": targets, "counts": dict(counts),
                "succeeded": completed, "failed": len(reports) - completed, "formats": sorted(formats),
                "unprocessed_targets": requested_targets[len(stores):] if requested_targets else [],
                "database": "results.sqlite3" if "sqlite" in formats else None,
                "records": "results.jsonl" if "jsonl" in formats else None, "records_sha256": records_hash}
    stores[0].write_json(directory / "manifest.json", manifest)
    return manifest
