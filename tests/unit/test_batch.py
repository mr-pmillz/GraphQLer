"""Automation contracts for batch input, partial results, and selected formats."""

import json
import hashlib
import multiprocessing
import time

import pytest

from graphqler import config
from graphqler.batch import collect_targets, result_exit, run_batch
from graphqler.fuzzer import Fuzzer
from graphqler.output import ResultStore, active_store, recording
from graphqler.output.reports import parse_formats
from graphqler.utils import request_utils


def test_interrupted_batch_exports_completed_evidence_and_unprocessed_targets(tmp_path, monkeypatch):
    """Ctrl-C publishes the aggregate manifest before the caller exits 130."""
    from graphqler import __main__ as cli

    def execute(args, store):
        if "interrupt" in args["url"]:
            raise KeyboardInterrupt
        store.finding("test", "node", True, False, "payload", "evidence")

    monkeypatch.setattr(cli, "_execute", execute)
    with pytest.raises(KeyboardInterrupt):
        cli.main({"mode": "run", "url": "https://one.test/,https://interrupt.test/,https://three.test/", "path": str(tmp_path)})
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["status"] == "interrupted"
    assert manifest["succeeded"] == 1
    assert manifest["unprocessed_targets"] == ["https://three.test/"]
    assert len((tmp_path / "findings.jsonl").read_text().splitlines()) == 1
    assert [target["status"] for target in manifest["targets"]] == ["completed", "interrupted"]


def test_target_configuration_failure_does_not_abort_batch(tmp_path, monkeypatch):
    """A broken saved config fails only that target and leaves earlier evidence readable."""
    from graphqler import __main__ as cli
    target = "https://bad.test/"
    directory = tmp_path / "targets" / hashlib.sha256(target.encode()).hexdigest()[:16]
    directory.mkdir(parents=True)
    (directory / "config.toml").write_text("invalid TOML content")
    monkeypatch.setattr(cli, "_execute", lambda args, store: None)
    assert cli.main({"mode": "run", "url": ["https://good.test/", target], "path": str(tmp_path)}) == 3
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["succeeded"] == manifest["failed"] == 1
    assert manifest["targets"][1]["error"]


def test_input_forms_are_validated_and_deduplicated(tmp_path):
    """Repeated URLs, CSV, and files share one stable input order."""
    source = tmp_path / "targets.txt"
    source.write_text("# Input comment\nhttps://two.test/\nhttps://three.test/\n")
    assert collect_targets({"url": ["https://one.test/,https://two.test/", "https://one.test/"], "input": str(source)}) == [
        "https://one.test/", "https://two.test/", "https://three.test/",
    ]
    assert collect_targets({"mode": "compile-chains"}) == [""]
    with pytest.raises(ValueError):
        collect_targets({"url": "https://one.test/,file:///tmp/example"})


def test_mixed_batch_preserves_all_runs_and_returns_three(tmp_path):
    """Failed targets cannot erase successful findings and all rows share one catalog."""
    def target(args):
        store = ResultStore(args["path"], args["url"], args["mode"], database=args["_database"],
                            formats=args["_formats"], output_root=args["_output_root"])
        if "bad" in args["url"]:
            store.finish("failed", "Connection failed")
        else:
            store.finding("test", "node", True, False, "payload", "evidence")
            store.finish()
        return store

    code = run_batch({"url": "https://good.test/,https://bad.test/", "mode": "run", "path": str(tmp_path)}, target)
    assert code == 3
    report = json.loads((tmp_path / "manifest.json").read_text())
    assert report["status"] == "partial"
    assert report["succeeded"] == report["failed"] == 1
    assert len(list(tmp_path.rglob("*.sqlite3"))) == 1
    for target in report["targets"]:
        directory = tmp_path / target["directory"]
        manifest = json.loads((directory / "manifest.json").read_text())
        assert (directory / manifest["database"]).resolve() == tmp_path / "results.sqlite3"
    findings = [json.loads(line) for line in (tmp_path / "findings.jsonl").read_text().splitlines()]
    assert len(findings) == 1
    assert findings[0]["data"]["target"] == "https://good.test/"
    assert "Connection failed" in (tmp_path / "findings.md").read_text()


@pytest.mark.parametrize("formats,expected", [("sqlite", {"results.sqlite3"}), ("jsonl", {"results.jsonl", "findings.jsonl"}), ("markdown", {"findings.md"})])
def test_format_selection_controls_retained_outputs(tmp_path, formats, expected):
    """Unselected formats are not emitted; JSON/Markdown-only runs use a temporary catalog."""
    def target(args):
        store = ResultStore(args["path"], args["url"], args["mode"], database=args["_database"], formats=args["_formats"])
        store.finish()
        return store

    assert run_batch({"url": "https://example.test", "mode": "discover", "path": str(tmp_path), "format": [formats]}, target) == 0
    assert {path.name for path in tmp_path.iterdir()} == expected | {"manifest.json"}


def test_exit_codes_distinguish_failure_timeout_and_findings(tmp_path):
    """The findings gate is opt-in and partial failures take priority over it."""
    store = ResultStore(tmp_path, "https://example.test/", "run")
    store.finding("Introspection Enabled", "endpoint", True, False, "payload", "evidence")
    store.finish()
    assert result_exit([store]) == 0
    assert result_exit([store], "info") == 4
    assert result_exit([store], "high") == 0
    store.finding("OS Command Injection", "node", True, False, "payload", "evidence")
    assert result_exit([store], "high") == 4
    assert result_exit([store], "critical") == 0
    failed = ResultStore(tmp_path, "https://bad.test/", "run")
    failed.finish("failed", "transport failure")
    assert result_exit([failed]) == 1
    assert result_exit([store, failed], "info") == 3
    failed.finish("timed_out", "timeout")
    assert result_exit([failed]) == 124


def test_invalid_batch_input_makes_no_requests(tmp_path):
    """Reject the entire input before a valid first target can start."""
    def forbidden(args):
        raise AssertionError("target must not be called")
    assert run_batch({"url": "https://example.test,file:///bad", "mode": "run", "path": str(tmp_path)}, forbidden) == 2
    with pytest.raises(ValueError):
        parse_formats(["nonsense"])
    with pytest.raises(ValueError):
        parse_formats(["universal"])


def _failing_worker(queue):
    """Simulate an exception from a fuzzing child process."""
    raise RuntimeError("worker failed")


def _slow_worker(queue):
    """Commit evidence before exceeding the worker time budget."""
    store = active_store()
    assert store is not None
    store.finding("test", "node", True, False, "payload", "evidence")
    time.sleep(30)


def test_worker_failures_and_timeout_propagate_and_keep_evidence(tmp_path, monkeypatch):
    """Worker termination is joined and cannot discard previously committed results."""
    monkeypatch.setattr(config, "DEBUG", False)
    monkeypatch.setattr(config, "MAX_TIME", 2)
    store = ResultStore(tmp_path, "https://example.test", "run")
    fuzzer = Fuzzer.__new__(Fuzzer)
    with recording(store), pytest.raises(RuntimeError, match="worker failed"):
        fuzzer._run_worker(_failing_worker)
    with recording(store), pytest.raises(TimeoutError):
        fuzzer._run_worker(_slow_worker)
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert not any(process.is_alive() for process in multiprocessing.active_children())


def test_proxy_applies_to_both_schemes_and_tls_is_explicit(monkeypatch):
    """HTTP CONNECT proxies work for HTTPS, without implicitly disabling TLS checks."""
    monkeypatch.setattr(config, "PROXY", "http://127.0.0.1:8080")
    monkeypatch.setattr(config, "VERIFY_TLS", True)
    assert request_utils.get_proxies() == {"http": config.PROXY, "https": config.PROXY}
    with request_utils.create_new_session() as session:
        assert session.verify is True
        assert session.proxies["https"] == config.PROXY
    monkeypatch.setattr(config, "VERIFY_TLS", False)
    with request_utils._create_session_with_headers({}) as session:
        assert session.verify is False
