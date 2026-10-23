"""Adversarial regressions for catalog integrity and credential isolation."""

import copy
import hashlib
import json
import sqlite3

import pytest
import requests

from graphqler import config
from graphqler import __main__ as cli
from graphqler.discovery import _recognize, validate_url
from graphqler.output import ResultStore
from graphqler.utils import request_utils


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
    request_utils.reset_session()
    yield
    request_utils.reset_session()


def test_short_credentials_cannot_corrupt_schema_metadata(tmp_path):
    config.AUTHORIZATION = "run"
    store = ResultStore(tmp_path, "https://example.test/", "run")
    store.finding("test", "node", True, False, "run", "run")
    store.finish()
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert records[0]["record_type"] == "run"
    assert records[0]["data"]["run_id"] == store.run_id
    assert records[0]["data"]["mode"] == "run"
    assert records[1]["data"]["payload"] == "[REDACTED]"


def test_raw_json_and_invalid_utf8_artifacts_redact_credentials(tmp_path):
    secret = 'secret-"quoted"-value'
    config.AUTHORIZATION = "Bearer " + secret
    store = ResultStore(tmp_path, "https://example.test/", "run")
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"echo": secret}).encode()
    response.encoding = "utf-8"
    store.request(store.target, "POST", {}, response)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs/fuzzer.log").write_bytes(secret.encode() + b"\xff")
    store.finish()
    with store.connect() as db:
        assert "secret-" not in db.execute("SELECT response_body FROM requests").fetchone()[0]
        assert b"secret-" not in db.execute("SELECT content FROM artifacts").fetchone()[0]


def test_later_targets_cannot_redact_an_earlier_runs_metadata(tmp_path):
    store = ResultStore(tmp_path, "https://example.test/", "run")
    store.finding("test", "node", True, False, "payload", "evidence")
    store.finish()
    config.AUTHORIZATION = "confirmed"
    store.export()
    finding = json.loads((tmp_path / "findings.jsonl").read_text())
    assert finding["data"]["status"] == "confirmed"


def test_unicode_escaped_credentials_are_redacted_before_json_export(tmp_path):
    secret = "private-value"
    config.AUTHORIZATION = "Bearer " + secret
    response = requests.Response()
    response.status_code = 200
    escaped = "".join(f"\\u{ord(char):04x}" for char in secret)
    response._content = ('{"echo":"' + escaped + '"}').encode()
    store = ResultStore(tmp_path, "https://example.test/", "run")
    store.request(store.target, "POST", {}, response)
    with store.connect() as db:
        body = db.execute("SELECT response_body FROM requests").fetchone()[0]
    assert json.loads(body) == {"echo": "[REDACTED]"}


def test_starting_a_new_run_invalidates_previous_success_manifest(tmp_path):
    old = ResultStore(tmp_path, "https://old.test/", "discover")
    old.finish()
    current = ResultStore(tmp_path, "https://new.test/", "discover")
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["status"] == "running"
    assert manifest["run_id"] == current.run_id


def test_database_initialization_failure_cannot_leave_old_success_manifest(tmp_path):
    old = ResultStore(tmp_path, "https://old.test/", "discover")
    old.finish()
    (tmp_path / "results.sqlite3").write_text("invalid database")
    with pytest.raises(sqlite3.DatabaseError):
        cli.main({"url": "https://new.test/", "mode": "discover", "path": str(tmp_path)})
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["status"] == "failed"
    assert manifest["records"] is None
    assert manifest["unprocessed_targets"] == ["https://new.test/"]


def test_export_does_not_follow_predictable_temporary_symlink(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("sentinel")
    (output / "results.jsonl.tmp").symlink_to(outside)
    store = ResultStore(output, "https://example.test/", "discover")
    store.finish()
    assert outside.read_text() == "sentinel"


def test_database_symlink_is_rejected(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "results.sqlite3").symlink_to(tmp_path / "unrelated.sqlite3")
    with pytest.raises((ValueError, OSError), match="[Ss]ymlink"):
        ResultStore(output, "https://example.test/", "discover")


def test_export_failure_preserves_batch_and_continues_targets(tmp_path, monkeypatch):
    original = ResultStore.export

    def fail_one(store):
        if "broken" in store.target:
            raise OSError("simulated target report failure")
        original(store)

    monkeypatch.setattr(ResultStore, "export", fail_one)
    monkeypatch.setattr(cli, "_execute", lambda args, store: store.finding("test", "node", True, False, "payload", "evidence"))
    code = cli.main({"url": "https://good.test/,https://broken.test/,https://last.test/", "mode": "run", "path": str(tmp_path)})
    assert code == 3
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["succeeded"] == 2
    assert manifest["failed"] == 1
    assert len((tmp_path / "findings.jsonl").read_text().splitlines()) == 3


def test_target_directory_failure_does_not_abort_remaining_targets(tmp_path, monkeypatch):
    bad = "https://broken.test/"
    directory = tmp_path / "targets"
    directory.mkdir()
    (directory / hashlib.sha256(bad.encode()).hexdigest()[:16]).write_text("blocked")
    monkeypatch.setattr(cli, "_execute", lambda args, store: None)
    assert cli.main({"url": ["https://good.test/", bad, "https://last.test/"], "mode": "run", "path": str(tmp_path)}) == 3
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert len(manifest["targets"]) == 3
    assert manifest["succeeded"] == 2


def test_export_only_failure_retains_recoverable_catalog(tmp_path, monkeypatch, capsys):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr("graphqler.batch.tempfile.mkdtemp", lambda **_: str(scratch))

    def fail_export(store):
        raise OSError("report unavailable")

    monkeypatch.setattr(ResultStore, "export", fail_export)
    monkeypatch.setattr(cli, "_execute", lambda args, store: store.finding("test", "node", True, False, "payload", "evidence"))
    assert cli.main({"url": "https://example.test/", "mode": "run", "path": str(tmp_path / "output"), "format": ["jsonl"]}) == 1
    with sqlite3.connect(scratch / "results.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert str(scratch / "results.sqlite3") in capsys.readouterr().err


def test_interrupt_stops_batch_even_when_export_also_fails(tmp_path, monkeypatch):
    seen = []

    def interrupt(args, store):
        seen.append(args["url"])
        raise KeyboardInterrupt()

    def fail_export(store):
        raise OSError("report unavailable")

    monkeypatch.setattr(cli, "_execute", interrupt)
    monkeypatch.setattr(ResultStore, "export", fail_export)
    with pytest.raises(KeyboardInterrupt):
        cli.main({"url": ["https://first.test/", "https://second.test/"], "mode": "run", "path": str(tmp_path)})
    assert seen == ["https://first.test/"]
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["status"] == "interrupted"
    assert manifest["unprocessed_targets"] == ["https://second.test/"]


@pytest.mark.parametrize("code", [["GRAPHQL_VALIDATION_FAILED"], {"nested": "value"}])
def test_hostile_discovery_error_codes_are_not_hashable_assumptions(code):
    body = {"errors": [{"message": "Unknown field", "extensions": {"code": code}}]}
    assert _recognize(body, "probe") == (False, "Unverified errors response (possibly authentication required)")


def test_empty_url_userinfo_is_rejected():
    with pytest.raises(ValueError):
        validate_url("https://@example.test/graphql")


@pytest.mark.parametrize("token", ["abc==", "Bearer abc==", "Basic dXNlcjpwYXNz=="])
def test_padded_auth_tokens_are_not_profile_assignments(tmp_path, token):
    cli._configure_target({"mode": "discover", "url": "https://example.test/", "path": str(tmp_path), "auth": [token]})
    assert config.AUTHORIZATION == (token if " " in token else "Bearer " + token)


def test_anonymous_profile_does_not_inherit_primary_custom_credentials():
    config.CUSTOM_HEADERS = {"authorization": "Bearer primary", "Cookie": "session=primary", "X-API-Key": "primary", "X-Version": "v1"}
    with request_utils._create_session_with_headers({}) as session:
        assert not any(name in session.headers for name in ("Authorization", "Cookie", "X-API-Key"))
        assert session.headers["X-Version"] == "v1"


def test_explicit_proxy_wins_over_environment_proxy(monkeypatch):
    config.PROXY = "http://127.0.0.1:8080"
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    with request_utils.create_new_session() as session:
        settings = session.merge_environment_settings("https://example.test/", {}, False, None, None)
        assert settings["proxies"]["https"] == config.PROXY
