"""Same-named fields on different operation roots remain separate findings."""

import copy
from types import SimpleNamespace
from unittest.mock import Mock

import requests

from graphqler import config
from graphqler.fuzzer.engine.dengine import DEngine
from graphqler.fuzzer.engine.detectors.detector import Detector
from graphqler.fuzzer.engine.materializers import GeneralPayloadMaterializer
from graphqler.graph.node import Node
from graphqler.output import ResultStore, recording
from graphqler.utils.logging_utils import reset_loggers
from graphqler.utils.stats import Stats


def test_query_and_mutation_with_same_field_are_both_checked_and_linked(tmp_path, monkeypatch):
    for key, value in vars(config).copy().items():
        if key.isupper():
            monkeypatch.setattr(config, key, copy.deepcopy(value))
    config.SKIP_INJECTION_ATTACKS = False
    config.SKIP_MISC_ATTACKS = True
    config.SKIP_ENUMERATION_ATTACKS = True
    config.OUTPUT_DIRECTORY = str(tmp_path)
    calls = []

    class FixtureDetector(Detector):
        DETECTION_NAME = "Fixture finding"
        materializer = GeneralPayloadMaterializer

        def get_payload(self):
            return f"{self.graphql_type.lower()} {{ shared }}"

        def _is_vulnerable(self, graphql_response, request_response):
            return True

        def _is_potentially_vulnerable(self, graphql_response, request_response):
            return False

    def send(_url, payload):
        calls.append(payload)
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"data":{"shared":"value"}}'
        return response.json(), response

    monkeypatch.setattr("graphqler.fuzzer.engine.dengine.injection_detectors", [FixtureDetector])
    monkeypatch.setattr("graphqler.utils.plugins_handler.get_request_utils", lambda: SimpleNamespace(send_graphql_request=send))
    getattr(Stats, "reset")()
    reset_loggers()
    try:
        store = ResultStore(tmp_path, "https://example.test/graphql", "run")
        with recording(store):
            Stats().set_file_paths(str(tmp_path))
            engine = DEngine(Mock(url=store.target))
            for kind in ("Query", "Mutation", "Query", "Mutation"):
                engine.run_detections_on_graphql_object(Node(kind, "shared", {}), Mock(), kind)
            store.finish()
        assert calls == ["query { shared }", "mutation { shared }"]
        with store.connect() as db:
            rows = db.execute("SELECT f.node,r.graphql_type FROM findings f JOIN results r ON r.id=f.result_id ORDER BY f.id").fetchall()
        assert [tuple(row) for row in rows] == [("Query|shared", "Query"), ("Mutation|shared", "Mutation")]
        assert len(Stats().vulnerabilities["Fixture finding"]) == 2
    finally:
        reset_loggers()
        getattr(Stats, "reset")()
