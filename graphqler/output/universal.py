"""Map native observations to universal v1 entities with caller-supplied provenance."""

import hashlib
import json
from collections import Counter
from urllib.parse import urlsplit

from .store import ResultStore, utc_now


def export_universal(store: ResultStore) -> None:
    """Write endpoints and positive findings with native JSONL back-pointers."""
    directory = store.directory / "universal"
    directory.mkdir(exist_ok=True)
    temporary = directory / "records.jsonl.tmp"
    counts: Counter[str] = Counter()
    source_file = (store.directory / "results.jsonl").relative_to(store.output_root).as_posix()
    with (store.directory / "results.jsonl").open(encoding="utf-8") as source, temporary.open("w", encoding="utf-8") as destination:
        for line_number, line in enumerate(source, 1):
            native = json.loads(line)
            data = native["data"]
            kind = native["record_type"]
            if kind == "endpoint" and data["confirmed"]:
                url = urlsplit(data["url"])
                record = {"entity_type": "HTTPEndpoint", "url": data["url"], "host": url.hostname,
                          "port": url.port or (443 if url.scheme == "https" else 80), "scheme": url.scheme,
                          "method": data["method"], "endpoint_classification": "graphql"}
                if data["status_code"] and 100 <= data["status_code"] <= 599:
                    record["status_code"] = data["status_code"]
                natural_key = ["http_endpoint", data["method"], data["url"]]
            elif kind == "finding":
                record = {"entity_type": "Vulnerability", "detector": "custom", "tool_result_id": data["detector"],
                          "title": f"{data['detector']}: {data['node']}", "severity": data["severity"],
                          "confidence": data["confidence"], "confidence_reason": data["evidence"],
                          "affected_url": store.clean(store.target), "affected_host": urlsplit(store.target).hostname,
                          "affected_parameter": data["node"], "parameter_location": "graphql_operation",
                          "http_method": "POST", "finding_type": data["status"], "evidence": data["evidence"],
                          "payload": data["payload"] if isinstance(data["payload"], str) else json.dumps(data["payload"]),
                          "tags": ["graphql", "graphqler", data["status"]]}
                natural_key = ["vulnerability", store.clean(store.target), data["detector"], data["node"]]
            else:
                continue
            # Stable, customer-scoped natural keys deliberately exclude the job ID.
            identity = "|".join([store.customer_id or "", "graphqler", *natural_key])
            record.update({"record_id": hashlib.sha256(identity.encode()).hexdigest(), "customer_id": store.customer_id,
                           "job_id": store.job_id, "tool": "graphqler", "tool_version": store.tool_version,
                           "schema_version": "v1", "collected_at": data["observed_at"],
                           "source_ref": {"file": source_file, "line": line_number}})
            destination.write(store.json(record) + "\n")
            counts[record["entity_type"]] += 1
    temporary.replace(directory / "records.jsonl")
    store.write_json(directory / "manifest.json", {
        "schema_version": "v1", "customer_id": store.customer_id, "job_id": store.job_id,
        "tool": "graphqler", "tool_version": store.tool_version, "generated_at": utc_now(),
        "total_records": sum(counts.values()), "counts_by_entity": dict(counts), "source_files": [source_file],
    })
