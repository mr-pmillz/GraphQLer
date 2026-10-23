# Output files

GraphQLer writes a versioned result catalog and reports for automation. The default
formats are `sqlite,jsonl,markdown`; select formats with `--format` and the output
directory with `--output` (`--path` remains an alias):

```sh
uv run graphqler --mode run --url https://example.com/ \
  --output results --format sqlite,jsonl,markdown
uv run graphqler --mode discover --input targets.txt --output discovery --format jsonl
```

## Structured results

| File | Contract |
|---|---|
| `manifest.json` | Version, completion status, counts, run/batch identity, selected formats, and export checksum. Always written. |
| `results.sqlite3` | Durable history of every run in this output directory, including raw evidence and artifact contents. |
| `results.jsonl` | All current-run records, or all runs in the current batch. Each line is a JSON object. |
| `findings.jsonl` | Positive findings only, with target URL, detector, operation, status, severity, confidence, payload, evidence, and linked raw result ID. Empty when there are no findings. |
| `findings.md` | Human-readable report grouped by target, including failed runs, evidence, payloads, and response previews. |
| `universal/records.jsonl` | Optional normalized `HTTPEndpoint` and `Vulnerability` entities with caller-supplied provenance. |
| `universal/manifest.json` | Counts and source files for the optional universal export. |

`--format sqlite` retains the catalog without JSONL/Markdown reports. `--format
jsonl` and `--format markdown` use a temporary database during execution and retain
only the chosen reports, the manifest, and legacy working files. Selecting
`universal` also selects `jsonl` so source references remain resolvable. `all`
selects all native formats, plus universal output when provenance is supplied.
Existing catalogs are never deleted when a later invocation omits `sqlite`.

The native schema is `graphqler/v1`; its machine-readable definition ships as
[`graphqler/output/native.schema.json`](https://github.com/mr-pmillz/GraphQLer/blob/main/graphqler/output/native.schema.json).
Every JSONL line has this envelope:

```json
{"schema_version":"graphqler/v1","run_id":"...","record_type":"finding","data":{"id":1,"run_id":"...","target":"https://example.com/graphql","detector":"Introspection Enabled","node":"https://example.com/graphql","status":"confirmed","severity":"info","confidence":"confirmed","payload":"...","evidence":"...","result_id":72,"observed_at":"2026-01-01T00:00:00Z"}}
```

Record types are `run`, `endpoint`, `request`, `result`, `finding`, and `artifact`.
JSON payloads and responses remain JSON values; SQL columns ending in `_json`
become decoded values without that suffix in JSONL. Findings that were tested and
found negative do not appear in `findings`; their requests/results remain available.
An observation's integer ID is local to its catalog. Use `(run_id, id)` as an
external reference. Repeated `save()` calls do not duplicate observations.

Severity is a provisional tool classification: introspection and field suggestions
are `info`; SQL/NoSQL/command injection, path injection, and IDOR are `high`;
remaining detectors default to `medium`. Findings are not assigned `critical`
without additional context. Confidence
is `confirmed` when detector-specific evidence matched and `low` for potential
findings. These describe machine assertions, not human triage or a CVSS score.
Generic DoS server errors/timeouts are potential findings; fragment-cycle validation,
complexity/depth limits, and rate limiting are safe rejection signals.

## SQLite catalog

`PRAGMA user_version` is `1`. Consumers should reject unknown database/schema
versions. Tables are joined through `run_id`:

| Table | Contents |
|---|---|
| `runs` | Target, mode, tool version, UTC timestamps, status/error, provenance, aggregate statistics |
| `endpoints` | Positive and negative discovery probes, method, status code, evidence |
| `requests` | HTTP or WebSocket payload, response status/headers/body, elapsed time, transport error |
| `results` | Every engine observation: operation/type, success, payload, response, errors |
| `findings` | Confirmed/potential findings with a `result_id` when matching evidence is available |
| `artifacts` | Relative path, role, media type, original SHA-256, original/stored sizes, truncation flag, content BLOB |

```sql
SELECT run_id, target, status, error FROM runs ORDER BY started_at DESC;
SELECT f.detector, f.node, f.status, f.severity, f.evidence, r.target
FROM findings f JOIN runs r USING (run_id);
SELECT f.detector, e.payload_json, e.response_json
FROM findings f JOIN results e ON e.id = f.result_id;
```

Each observation commits independently. A normal failure, timeout, or Ctrl-C
finalizes the available evidence with `failed`, `timed_out`, or `interrupted` status.
A forcibly killed parent can leave a `running` row: treat it as incomplete, not
successful-empty. Each new invocation replaces the old manifest with `running`
state before executing. Export errors fail the affected run and remaining batch
targets continue. Aggregate reports read committed rows directly, including
evidence from targets whose individual report export failed.
JSON files are atomically replaced with private permissions; the final native
manifest is published last and carries the `results.jsonl` SHA-256.
Copy a closed catalog, or use SQLite's backup API while a scan is running.
If an export fails when `sqlite` was not selected, GraphQLer retains its private
temporary catalog and prints its recovery path to stderr. Ctrl-C remains exit
`130` even if publishing the interrupted results also fails.

Operation-specific finding names include the root type, such as `Query|account`
or `Mutation|account`, so fields with the same name keep separate findings and
result links. API-wide findings retain their endpoint URL as the node name.

Artifacts include changed outputs and the compiled schema inputs used for the run.
Each embedded file is limited to 16 MiB; the stored size and `truncated` flag make
this explicit. The hash describes the original file, before configured-credential
redaction and truncation. Config files, serialized Python objects, exports, and
symlinks are excluded. Raw HTTP/result records are separate from these artifact
previews. Custom request plugins must use the built-in transport to populate the
`requests` table; engine-level results still record plugin executions.
Artifact paths containing credentials use unique logical names under `redacted/`;
read their embedded `content` from SQLite instead of treating these aliases as
filesystem paths. New detection directories use bounded names with hash suffixes
when sanitizing or redacting a node name.
Blind introspection uses Clairvoyance's inference engine with GraphQLer's HTTP
transport, so its exchanges are also cataloged and follow the same proxy, TLS,
redirect, and response-size rules. `MAX_TIME` bounds this fallback; it sends at most
eight concurrent requests, each limited by the remaining time and `REQUEST_TIMEOUT`.

Configured authentication values are redacted from structured output, and sensitive
response headers are masked. Captured application data may still be sensitive.
Redaction covers escaped credentials and sensitive URL query parameters while
preserving schema keys, IDs, and status values. Output writes reject nested
directory symlinks; database files must be regular files with a single link.
When credentials are configured, an undecodable JSON string suffix is omitted
with a redaction marker so malformed encoding cannot expose those credentials.
Do not run concurrent scans against the same output directory: compilation and
legacy working files are mutable. Use different directories for concurrent jobs.

## Multiple targets

Repeated `--url`, comma-separated URLs, and `--input` can be combined. Files accept
one URL per line and `#` comments. Targets are validated and deduplicated before
network activity. Literal commas in URLs must be percent-encoded.

```sh
uv run graphqler --mode run --input targets.txt \
  --url https://additional.example/ --output batch-results
```

A batch shares one root `results.sqlite3`; each target uses an isolated
`targets/<URL-hash>/` working directory. The root manifest lists target directories,
run IDs, errors, counts, and overall status. Root JSONL/Markdown reports aggregate
the current batch; prior runs remain in SQLite. The native catalog contains each
target's final selected endpoint after discovery.
The native manifest's `database` and `records` paths are relative to that manifest's
directory, including each target's reference to the shared root database.
An interrupted batch also reports `unprocessed_targets` and exports evidence
from the targets already attempted.

| Exit code | Meaning |
|---|---|
| `0` | Every target completed. Findings do not change the default exit code. |
| `1` | All targets failed, or a required output could not be published. |
| `2` | Invalid arguments, formats, provenance, or target input. No scan starts. |
| `3` | At least one target completed and at least one failed or timed out. |
| `4` | All targets completed and a confirmed finding met `--fail-on-findings [severity]`. |
| `124` | Every target timed out. |
| `130` | Interrupted by the user. |

Mixed execution failures take priority over the optional findings threshold. A
responsive host with no GraphQL endpoints is a valid empty discovery result; a
target that returns no HTTP responses is a failed discovery.
Fuzzing that receives only transport errors also fails rather than reporting an
empty successful scan.

## HTTP boundaries

Normal scanning and discovery follow only same-origin redirects, retaining a
request record for each hop. Redirects that require changing a POST to GET are
not treated as confirmed POST endpoints. `--request-timeout` bounds a complete
scan request, including redirect hops and streamed response reads. Discovery also
has its own total time budget. Responses are limited to 16 MiB for scanning and
1 MiB for discovery, including decompressed bytes; use `--max-response-bytes` or
`MAX_RESPONSE_BYTES` in the config for larger scan responses. Partial response evidence is retained
when a limit is exceeded.

An explicit `--proxy` takes precedence over environment proxy settings. Ambient
`.netrc` credentials are never used. Secondary and anonymous profiles inherit
ordinary custom headers; credentials such as Authorization, cookies, and API keys
must be supplied explicitly for each profile. The post-delete profile uses the
primary identity so use-after-delete checks retain the original authentication.

Subscriptions also restrict redirects to the same origin and honor the proxy and
TLS configuration, including a custom CA certificate path. The modern protocol is
`graphql-transport-ws`; legacy Apollo uses `graphql-ws` (the configuration alias
`subscriptions-transport-ws` is accepted). `SUBSCRIPTION_TIMEOUT` bounds the combined
acknowledgment and event collection window after the handshake. Collection is
limited to `MAX_RESPONSE_BYTES` decoded message bytes and 10,000 messages.
The `requests` table uses method `WEBSOCKET`, status `101` for an accepted upgrade,
and a JSON `messages` array in `response_body`. A protocol or limit failure records
an error and retains earlier messages; subscription results include their payload
and collected events. An acknowledged subscription can successfully return no events.

## Universal export

```sh
uv run graphqler --mode run --url https://example.com/ --output results \
  --format universal,sqlite,markdown --customer-id customer-123 --job-id job-456
```

The universal schema version is `v1`; `tool` is `graphqler`. Endpoint records use
`entity_type: HTTPEndpoint` and `endpoint_classification: graphql`. Finding records
use `entity_type: Vulnerability`, `detector: custom`, affected URL/operation,
severity/confidence, evidence, and payload. Headers contain `customer_id`, `job_id`,
`tool_version`, `collected_at`, a deterministic `record_id`, and `source_ref` pointing
to an actual native JSONL line relative to the output root. Identifiers are never
invented. Downstream consumers with closed tool enums must register `graphqler`.

Record IDs are lowercase SHA-256 of pipe-joined components. Endpoint keys are
`customer_id|graphqler|http_endpoint|method|url`; finding keys are
`customer_id|graphqler|vulnerability|url|detector|operation`. Job ID is deliberately
excluded so repeated jobs can deduplicate observations for the same customer.

## Legacy working files

Everything is written under `--path` (default `graphqler-output`):

```text
graphqler-output/
├── config.toml                  # resolved configuration for this run
├── introspection_result.json    # raw introspection response
├── extracted/                   # parsed schema: queries, mutations, objects, enums, …
├── compiled/
│   ├── compiled_queries.yml
│   ├── compiled_mutations.yml
│   ├── compiled_objects.yml
│   ├── compiled_subscriptions.yml
│   ├── target.json              # compilation status and original/selected target
│   └── chains/
│       ├── regular.yml          # dependency-ordered fuzzing chains
│       ├── idor.yml             # IDOR candidate chains (with a secondary token)
│       └── uaf.yml              # use-after-delete candidate chains
├── dependency_graph.png         # visualised dependency graph
├── stats.txt / stats.json       # coverage, status codes, vulnerabilities
├── objects_bucket.txt           # objects collected while fuzzing
├── unique_responses.txt         # distinct responses seen
├── endpoint_results/            # per-endpoint results (SAVE_ENDPOINT_RESULTS)
├── detections/                  # one folder per finding
├── logs/
│   ├── compiler.log
│   ├── fuzzer.log               # every request and response
│   ├── detector.log
│   ├── idor.log
│   └── chain_logs/
├── serialized/                  # pickled stats and objects bucket
├── eval/                        # LLM resolver comparison, when enabled
└── report.md                    # LLM vulnerability report (--llm-report)
```

## Compiled files

The files under `compiled/` are human-readable YAML and can be edited before running `--mode fuzz`. Nodes whose dependencies could not be resolved are marked as `UNKNOWNS`; you may fill them in manually, otherwise they are fuzzed without a dependency chain. Regenerate chains after edits with `--mode compile-chains`.

New compilations bind their artifacts to the original URL and discovered endpoint.
Reusing the original base URL in fuzz mode selects that saved endpoint. A different
target requires a new compilation or output directory. Starting compilation
invalidates previous chains; incomplete compilation cannot be reused. Legacy
artifacts without a target marker remain supported when the required files are nonempty.

## Dependency graph

![Example dependency graph](images/example_graph.png)

## Detections

Each confirmed or potential vulnerability gets its own folder:

```text
detections/<VULNERABILITY>/<NODE>/
├── summary.txt   # vulnerability, status, evidence, final payload and response
└── raw_log.txt   # full request/response chain
```

For chain-based findings (`IDOR_CHAIN`, `UAF_CHAIN`), `summary.txt` lists every chain step with the profile it ran under, plus the chain's reason and confidence.
