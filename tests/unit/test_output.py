"""Regression coverage for durable, isolated, machine-readable scan output."""

import hashlib
import json
import multiprocessing
import sqlite3
from types import SimpleNamespace

import pytest

from graphqler import config
from graphqler.fuzzer.engine.types import Result, ResultEnum
from graphqler.output import ResultStore, recording
from graphqler.utils.stats import Stats


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Create an isolated catalog with no ambient authentication."""
    for name in ("AUTHORIZATION", "IDOR_SECONDARY_AUTH", "LLM_API_KEY"):
        monkeypatch.setattr(config, name, "")
    monkeypatch.setattr(config, "CUSTOM_HEADERS", {})
    monkeypatch.setattr(config, "PROFILES", {})
    monkeypatch.setattr(config, "OUTPUT_DIRECTORY", str(tmp_path))
    getattr(Stats, "reset")()
    yield ResultStore(tmp_path, "https://example.test/graphql", "run", "customer-1", "job-1")
    getattr(Stats, "reset")()


def test_observations_and_findings_are_durable_and_monotonic(store):
    """Repeated saves never duplicate observations or downgrade confirmed evidence."""
    stats = Stats()
    stats.set_file_paths(str(store.directory))
    node = SimpleNamespace(name="getUser", graphql_type="Query")
    result = Result(ResultEnum.GENERAL_SUCCESS, payload="{getUser{id}}", status_code=200, graphql_response={"data": {"getUser": {"id": 1}}})
    with recording(store):
        stats.update_stats_from_result(node, result)
        stats.add_vulnerability("IDOR", node.name, False, True, result.payload, "possible")
        stats.add_vulnerability("IDOR", node.name, True, False, result.payload, "confirmed evidence")
        stats.add_vulnerability("IDOR", node.name, False, True, "worse", "weaker evidence")
        stats.add_vulnerability("SQL Injection", node.name, False, False, "safe", "rejected")
        stats.save()
        stats.save()
    # Read before finalization to verify per-observation commits.
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 1
        finding = dict(db.execute("SELECT * FROM findings").fetchone())
        assert finding["status"] == "confirmed"
        assert finding["evidence"] == "confirmed evidence"
        assert finding["result_id"] is not None
        assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert (store.directory / "endpoint_results/getUser/success/200").read_text().count("Payload:") == 1
    store.finish()
    manifest = json.loads((store.directory / "manifest.json").read_text())
    assert manifest["status"] == "completed"
    assert manifest["counts"]["finding"] == 1
    assert manifest["records_sha256"] == hashlib.sha256((store.directory / "results.jsonl").read_bytes()).hexdigest()
    native = [json.loads(line) for line in (store.directory / "results.jsonl").read_text().splitlines()]
    from pathlib import Path
    import jsonschema
    schema = json.loads(Path("graphqler/output/native.schema.json").read_text())
    for record in native:
        jsonschema.validate(record, schema)
    universal = [json.loads(line) for line in (store.directory / "universal/records.jsonl").read_text().splitlines()]
    assert universal[0]["confidence"] == "confirmed"
    assert native[universal[0]["source_ref"]["line"] - 1]["record_type"] == "finding"
    assert all(item["run_id"] == store.run_id for item in native)


def test_snapshot_throttling_keeps_observations_durable_and_final_save_complete(store, monkeypatch):
    """Fast scans commit every result without repeatedly rewriting their entire history."""
    stats = Stats()
    stats.set_file_paths(str(store.directory))
    clock = [100.0]
    stats._last_snapshot = clock[0]
    monkeypatch.setattr("graphqler.utils.stats.time.monotonic", lambda: clock[0])
    node = SimpleNamespace(name="sample", graphql_type="Query")
    with recording(store):
        for index in range(50):
            result = Result(ResultEnum.GENERAL_SUCCESS, payload=str(index), status_code=200, graphql_response={"data": {"sample": index}})
            stats.add_http_status_code(node.name, 200)
            stats.update_stats_from_result(node, result)
        with store.connect() as db:
            assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 50
        assert not stats.pickle_save_path.exists()
        clock[0] += 2
        stats.update_stats_from_result(node, result)
        snapshot = json.loads(stats.json_file_path.read_text())
        assert snapshot["number_of_successes"] == 51
        assert stats.pickle_save_path.is_file()
        stats.update_stats_from_result(node, result)
        assert json.loads(stats.json_file_path.read_text())["number_of_successes"] == 51
        stats.save()
        assert json.loads(stats.json_file_path.read_text())["number_of_successes"] == 52
        with store.connect() as db:
            assert db.execute("SELECT COUNT(*) FROM results").fetchone()[0] == 52


def test_single_chain_api_flushes_even_before_the_next_checkpoint(store, monkeypatch):
    """The public chain API must finish its reports even for sub-second operations."""
    from graphqler.chains import Chain
    from graphqler.fuzzer import Fuzzer

    fuzzer = Fuzzer.__new__(Fuzzer)
    fuzzer.save_path, fuzzer.url = str(store.directory), store.target
    fuzzer.stats = Stats()
    fuzzer.stats.set_file_paths(str(store.directory))
    fuzzer.stats._last_snapshot = 100.0
    monkeypatch.setattr("graphqler.utils.stats.time.monotonic", lambda: 100.0)
    node = SimpleNamespace(name="sample", graphql_type="Query")
    result = Result(ResultEnum.GENERAL_SUCCESS, payload="{sample}", status_code=200, graphql_response={"data": {"sample": "ok"}})
    monkeypatch.setattr(fuzzer, "_Fuzzer__run_chain", lambda chain: fuzzer.stats.update_stats_from_result(node, result))
    with recording(store):
        fuzzer.run_chain(Chain())
    assert json.loads(fuzzer.stats.json_file_path.read_text())["number_of_successes"] == 1
    assert fuzzer.stats.pickle_save_path.exists()
    assert store.run_info()["summary"]["number_of_successes"] == 1


def test_multiple_runs_preserve_history_and_export_only_current_run(store):
    """An empty subsequent run cannot inherit findings or a provenance export."""
    store.finding("Introspection Enabled", store.target, True, False, "__schema", "schema returned")
    store.finish()
    second = ResultStore(store.directory, "https://second.test/", "discover")
    second.finish()
    with second.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM findings WHERE run_id=?", (second.run_id,)).fetchone()[0] == 0
    manifest = json.loads((store.directory / "manifest.json").read_text())
    assert manifest["run_id"] == second.run_id
    assert manifest["counts"]["finding"] == 0
    assert not (store.directory / "universal/records.jsonl").exists()


def test_credentials_are_redacted_before_json_encoding(store, monkeypatch):
    """Quoted credentials cannot survive JSON escaping in persisted evidence."""
    secret = 'Bearer secret-"quoted"-value'
    monkeypatch.setattr(config, "AUTHORIZATION", secret)
    store.finding("test", "node", True, False, {"token": secret}, "response " + secret)
    store.request(store.target, "POST", {"query": secret}, error=secret)
    store.finish("failed", secret)
    with store.connect() as db:
        assert secret not in db.execute("SELECT error FROM runs").fetchone()[0]
        assert json.loads(db.execute("SELECT payload_json FROM findings").fetchone()[0]) == {"token": "[REDACTED]"}
    assert "secret-" not in (store.directory / "results.jsonl").read_text()


def test_catalog_artifacts_retains_bytes_but_excludes_secrets_and_stale_output(store, monkeypatch):
    """Artifact truncation is explicit and symlinks cannot import unrelated files."""
    monkeypatch.setattr("graphqler.output.store.MAX_ARTIFACT_BYTES", 4)
    (store.directory / "logs").mkdir()
    (store.directory / "logs/fuzzer.log").write_text("12345678")
    (store.directory / "config.toml").write_text('AUTHORIZATION="do-not-catalog"')
    (store.directory / "logs/outside.log").symlink_to("/etc/passwd")
    store.finish()
    with store.connect() as db:
        rows = db.execute("SELECT * FROM artifacts").fetchall()
        assert len(rows) == 1
        assert rows[0]["content"] == b"1234"
        assert rows[0]["truncated"] == 1
        assert rows[0]["size_bytes"] == 8
    second = ResultStore(store.directory, store.target, "discover")
    second.finish()
    with second.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM artifacts WHERE run_id=?", (second.run_id,)).fetchone()[0] == 0


def test_schema_artifacts_are_inputs_only_for_modes_that_reuse_them(tmp_path):
    """A discovery or failed compilation cannot claim another run's cached schema as its input."""
    (tmp_path / "compiled").mkdir()
    (tmp_path / "compiled/compiled_queries.yml").write_text("old: schema\n")
    for mode, count in (("discover", 0), ("compile-graph", 0), ("fuzz", 1)):
        run = ResultStore(tmp_path, "https://example.test/", mode)
        run.finish()
        with run.connect() as db:
            assert db.execute("SELECT COUNT(*) FROM artifacts WHERE run_id=?", (run.run_id,)).fetchone()[0] == count


def _commit_and_exit(store):
    """Simulate a worker crash after committing evidence."""
    import os
    store.finding("test", "node", True, False, "payload", "evidence")
    os._exit(9)


def test_worker_crash_preserves_committed_evidence(store):
    """No SQLite connection is shared across a spawned worker boundary."""
    process = multiprocessing.get_context("spawn").Process(target=_commit_and_exit, args=(store,))
    process.start()
    process.join(10)
    assert process.exitcode == 9
    store.finish("failed", "worker failed")
    with store.connect() as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        assert db.execute("SELECT status FROM runs").fetchone()[0] == "failed"
    assert not (store.directory / "results.sqlite3-wal").exists()


def test_reject_incompatible_database_and_incomplete_provenance(tmp_path):
    """Unknown schemas and missing provenance must fail rather than invent identities."""
    with pytest.raises(ValueError, match="together"):
        ResultStore(tmp_path, "https://example.test", "run", "customer")
    with sqlite3.connect(tmp_path / "results.sqlite3") as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(ValueError, match="version"):
        ResultStore(tmp_path, "https://example.test", "run")


def test_universal_ids_are_stable_for_same_customer_across_jobs(store):
    """Repeated jobs deduplicate findings while another customer has distinct identities."""
    ids = []
    for customer, job in (("one", "job1"), ("one", "job2"), ("two", "job1")):
        run = ResultStore(store.directory, store.target, "run", customer, job)
        run.finding("SQL Injection", "getUser", True, False, "payload", "evidence")
        run.finish()
        ids.append(json.loads((store.directory / "universal/records.jsonl").read_text())["record_id"])
    assert ids[0] == ids[1]
    assert ids[0] != ids[2]
