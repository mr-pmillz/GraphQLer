"""Output boundaries remain intact during malformed input and concurrent use."""

import asyncio
import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from graphqler import config
from graphqler import __main__ as cli
from graphqler.batch import run_batch
from graphqler.output import ResultStore, active_store, recording
from graphqler.output.files import atomic_writer, remove_output
from graphqler.output.redaction import Redactor
from graphqler.utils.file_utils import open_output, recreate_path
from graphqler.utils.cli_utils import compiled_target, write_compilation_target
from graphqler.utils.detection_writer import write_from_detector
from graphqler.fuzzer.engine.types import Result, ResultEnum
from graphqler.graph.node import Node
from graphqler.utils.request_utils import parse_response


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    for key, value in vars(config).copy().items():
        if key.isupper():
            monkeypatch.setattr(config, key, copy.deepcopy(value))
    config.AUTHORIZATION = ""
    config.IDOR_SECONDARY_AUTH = ""
    config.LLM_API_KEY = ""
    config.CUSTOM_HEADERS = {}
    config.PROFILES = {}


def test_atomic_writer_rejects_parent_traversal(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "sentinel.txt"
    outside.write_text("sentinel")
    with pytest.raises(ValueError):
        with atomic_writer(output / ".." / outside.name, output) as stream:
            stream.write("overwritten")
    assert outside.read_text() == "sentinel"


def test_cleanup_rejects_parent_traversal(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "sentinel.txt"
    outside.write_text("sentinel")
    with pytest.raises(ValueError):
        remove_output(output / ".." / outside.name, output)
    assert outside.read_text() == "sentinel"


@pytest.mark.parametrize("operation", ["write", "recreate"])
def test_legacy_io_uses_the_path_that_was_validated(tmp_path, operation):
    output = tmp_path / "output"
    outside = tmp_path / "outside"
    (outside / "child").mkdir(parents=True)
    (outside / "directory").mkdir()
    sentinel = outside / "directory" / "sentinel.txt"
    sentinel.write_text("sentinel")
    store = ResultStore(output, "https://example.test/", "run")
    (output / "alias").symlink_to(outside / "child", target_is_directory=True)
    with recording(store):
        path = output / "alias" / ".." / "directory"
        if operation == "write":
            with open_output(path / "sentinel.txt") as stream:
                stream.write("overwritten")
        else:
            recreate_path(path)
    assert sentinel.read_text() == "sentinel"


def test_recording_is_isolated_between_threads(tmp_path):
    first = ResultStore(tmp_path / "first", "https://first.test/", "run")
    second = ResultStore(tmp_path / "second", "https://second.test/", "run")
    first_entered, second_entered, first_exited = (threading.Event() for _ in range(3))

    def one():
        with recording(first):
            first_entered.set()
            assert second_entered.wait(5)
            selected = active_store()
        first_exited.set()
        return selected, active_store()

    def two():
        assert first_entered.wait(5)
        with recording(second):
            second_entered.set()
            assert first_exited.wait(5)
            selected = active_store()
        return selected, active_store()

    with ThreadPoolExecutor(max_workers=2) as executor:
        one_result, two_result = executor.submit(one), executor.submit(two)
        assert one_result.result() == (first, None)
        assert two_result.result() == (second, None)
    assert active_store() is None


def test_recording_is_isolated_between_async_tasks(tmp_path):
    first = ResultStore(tmp_path / "first", "https://first.test/", "run")
    second = ResultStore(tmp_path / "second", "https://second.test/", "run")

    async def exercise():
        ready, done = asyncio.Event(), asyncio.Event()

        async def one():
            with recording(first):
                await ready.wait()
                selected = active_store()
            done.set()
            return selected

        async def two():
            with recording(second):
                ready.set()
                await done.wait()
                return active_store()

        return await asyncio.gather(one(), two())

    assert asyncio.run(exercise()) == [first, second]
    assert active_store() is None


def test_single_target_initialization_failure_finalizes_root_manifest(tmp_path):
    def fail(_options):
        raise OSError("temporary initialization failure")

    assert run_batch({"url": "https://example.test/", "mode": "run", "path": str(tmp_path)}, fail) == 1
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["status"] == "failed"
    assert manifest["failed"] == 1
    assert manifest["unprocessed_targets"] == []
    assert manifest["targets"][0]["directory"].startswith("failures/")


@pytest.mark.parametrize("settings", [
    {"CUSTOM_HEADERS": ["invalid"]},
    {"PROFILES": ["invalid"]},
    {"PROFILES": {"primary": {"headers": ["invalid"]}}},
    {"PROXY": ["invalid"]},
    {"AUTHORIZATION": 123},
])
def test_invalid_configuration_still_produces_terminal_results(tmp_path, settings):
    code = cli.main({"url": "https://example.test/", "mode": "discover", "path": str(tmp_path), "config": settings})
    assert code != 0
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["status"] == "failed"
    assert manifest["records"] == "results.jsonl"
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert records[0]["data"]["status"] == "failed"


def test_redaction_handles_json_beyond_decoder_nesting_limit():
    redactor = Redactor()
    redactor.add("secret")
    encoded = "".join(f"\\u{ord(char):04x}" for char in "secret")
    value = "[" * 10000 + '"' + encoded + '"' + "]" * 10000
    assert redactor.body(value) == "[" * 10000 + '"[REDACTED]"' + "]" * 10000


def test_redaction_preserves_json_escapes_and_lone_surrogates():
    redactor = Redactor()
    redactor.add("secret")
    value = '{"echo":"secret\\ud800","other":"\\\\secret"}'
    cleaned = redactor.body(value)
    assert json.loads(cleaned) == {"echo": "[REDACTED]\ud800", "other": "\\[REDACTED]"}
    cleaned.encode("utf-8")


def test_redaction_covers_quoted_secrets_in_log_lines_starting_with_brackets():
    redactor = Redactor()
    secret = 'secret-"quoted"-value'
    redactor.add(secret)
    assert redactor.body("[INFO] " + secret) == "[INFO] [REDACTED]"


def test_unterminated_json_string_is_scanned_once_and_cannot_leak_encoded_secrets():
    redactor = Redactor()
    redactor.add("secret")
    encoded = "".join(f"\\u{ord(char):04x}" for char in "secret")
    value = '["' + '\\"' * 100000 + encoded
    assert redactor.body(value) == '["[REDACTED: malformed JSON string]"'


def test_catalog_can_export_unpaired_surrogates_in_server_evidence(tmp_path):
    store = ResultStore(tmp_path, "https://example.test/", "run")
    store.request(store.target, "POST", {"field": "\ud800"})
    store.finding("test", "node", True, False, {"field": "\ud800"}, "evidence \ud800")
    store.finish()
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert records[0]["data"]["status"] == "completed"
    request = next(record for record in records if record["record_type"] == "request")
    assert request["data"]["payload"] == {"field": "\ud800"}


def test_failure_report_export_error_does_not_abort_remaining_targets(tmp_path, monkeypatch):
    original = ResultStore.export

    def export(store):
        if store.target == "https://broken.test/":
            raise OSError("cannot publish individual failure report")
        original(store)

    def execute(options):
        if options["url"] == "https://broken.test/":
            raise OSError("initialization failure")
        store = ResultStore(options["path"], options["url"], options["mode"], database=options["_database"], output_root=options["_output_root"])
        store.finish()
        return store

    monkeypatch.setattr(ResultStore, "export", export)
    assert run_batch({"url": ["https://broken.test/", "https://good.test/"], "mode": "run", "path": str(tmp_path)}, execute) == 3
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["succeeded"] == 1
    assert manifest["failed"] == 1


def test_reused_endpoint_retains_discovered_routing_parameters(tmp_path):
    store = ResultStore(tmp_path, "https://example.test/?api_key=old", "compile")
    with recording(store):
        write_compilation_target(tmp_path, "https://example.test/graphql?version=2&api_key=old", "completed")
    assert compiled_target(tmp_path, "https://example.test/?api_key=new") == "https://example.test/graphql?version=2&api_key=new"


def test_reused_endpoint_never_sends_unrecoverable_redacted_credentials(tmp_path):
    store = ResultStore(tmp_path, "https://example.test/", "compile")
    with recording(store):
        write_compilation_target(tmp_path, "https://example.test/graphql?api_key=discovered-secret", "completed")
    with pytest.raises(ValueError, match="fresh query credentials"):
        compiled_target(tmp_path, "https://example.test/")


def test_detection_filenames_never_expose_url_credentials(tmp_path):
    config.OUTPUT_DIRECTORY = str(tmp_path)
    target = "https://example.test/graphql?token=private-secret"
    store = ResultStore(tmp_path, target, "run")
    with recording(store):
        write_from_detector(vuln_name="Introspection Enabled", node_name=target, is_vulnerable=True,
                            potentially_vulnerable=False, payload="{ __schema { queryType { name } } }",
                            graphql_response={"data": {}}, status_code=200, evidence="introspection succeeded")
        store.finish()
    assert not any("private-secret" in str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    assert "private-secret" not in (tmp_path / "results.jsonl").read_text()


def test_sensitive_artifact_paths_are_redacted_without_merging_files(tmp_path):
    config.AUTHORIZATION = "private-first"
    config.IDOR_SECONDARY_AUTH = "private-second"
    store = ResultStore(tmp_path, "https://example.test/", "run")
    (tmp_path / "logs").mkdir()
    for name in ("private-first", "private-second"):
        (tmp_path / "logs" / f"{name}.txt").write_text(name)
    store.finish()
    contents = (tmp_path / "results.jsonl").read_text()
    assert "private-first" not in contents and "private-second" not in contents
    with store.connect() as db:
        rows = db.execute("SELECT path,content FROM artifacts").fetchall()
    assert len(rows) == 2
    assert all(row["path"].startswith("redacted/") and row["content"] == b"[REDACTED]" for row in rows)


def test_long_detection_names_fit_in_filesystem_components(tmp_path):
    config.OUTPUT_DIRECTORY = str(tmp_path)
    store = ResultStore(tmp_path, "https://example.test/", "run")
    with recording(store):
        write_from_detector(vuln_name="test", node_name="Query|" + "a" * 400, is_vulnerable=True,
                            potentially_vulnerable=False, payload="query { field }", graphql_response={}, status_code=200, evidence="test")
    assert len(list((tmp_path / "detections").rglob("summary.txt"))) == 1


@pytest.mark.parametrize("body", [
    "[NODE] https://example.test/?token=p%72ivate-secret",
    '{"node":"https://example.test/?t%6fken=p%72ivate-secret"}',
    '{"node":"https:\\/\\/example.test/?token=p%72ivate-secret"}',
])
def test_redaction_handles_percent_encoded_query_credentials_in_evidence(body):
    redactor = Redactor()
    redactor.add("private-secret")
    cleaned = redactor.body(body)
    assert "p%72ivate-secret" not in cleaned
    assert "REDACTED" in cleaned


def test_malformed_response_is_scrubbed_when_embedded_in_parser_errors(tmp_path):
    config.AUTHORIZATION = "private-secret"
    encoded = "".join(f"\\u{ord(char):04x}" for char in "private-secret")
    raw = '{"echo":"' + encoded
    parsed = parse_response(raw)
    result = Result(ResultEnum.EXTERNAL_FAILURE, payload="query { field }", graphql_response=parsed,
                    errors=parsed["errors"], raw_response_text=raw)
    store = ResultStore(tmp_path, "https://example.test/", "run")
    store.result(Node("Query", "field", {}), result)
    store.finish()
    with store.connect() as db:
        row = db.execute("SELECT response_json,errors_json,raw_response FROM results").fetchone()
    for value in (json.loads(row["response_json"])["errors"][0], json.loads(row["errors_json"])[0], row["raw_response"]):
        assert encoded not in value
        assert "REDACTED" in value
