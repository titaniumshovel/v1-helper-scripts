from __future__ import annotations
import csv
import json
import os
from uet.collect import merge_results, settle_and_verify, verify_console, write_final_report
from uet.worklist import WorklistItem


def wi(host, swp_id, bucket="NEEDS_REPAIR"):
    return WorklistItem(hostname=host, swp_id=swp_id, agent_guid="", bucket=bucket)


def setup_results(tmp_path):
    d = tmp_path / "results"
    d.mkdir()
    (d / "a.json").write_text(json.dumps(
        {"schema": "uet-result/1", "host": "a", "outcome": "FIXED",
         "actions": ["service_start"], "blockers": []}))
    (d / "b.error.txt").write_text("rc=255\nssh: no route")
    return str(d)


def test_merge_results(tmp_path):
    rows = merge_results([wi("a", 1), wi("b", 2), wi("c", 3)], setup_results(tmp_path))
    by = {r["hostname"]: r for r in rows}
    assert by["a"]["outcome"] == "FIXED" and by["a"]["actions"] == ["service_start"]
    assert by["b"]["outcome"] == "TRANSPORT_ERROR"
    assert by["c"]["outcome"] == "NOT_RUN"


class StubSwp:
    def list_computers(self):
        return [{"ID": 1, "computerStatus": {"agentStatus": "active"}},
                {"ID": 2, "computerStatus": {"agentStatus": "inactive"}}]


def test_verify_console(tmp_path):
    rows = merge_results([wi("a", 1), wi("b", 2), wi("c", 3)], setup_results(tmp_path))
    rows = verify_console(rows, StubSwp())
    by = {r["hostname"]: r for r in rows}
    assert by["a"]["console_status"] == "active" and by["a"]["verified"] is True
    assert by["b"]["console_status"] == "inactive" and by["b"]["verified"] is False
    assert by["c"]["console_status"] == "gone"


def test_write_final_report(tmp_path):
    rows = merge_results([wi("a", 1)], setup_results(tmp_path))
    rows = verify_console(rows, StubSwp())
    path = write_final_report(rows, str(tmp_path))
    got = list(csv.DictReader(open(path, encoding="utf-8")))
    assert got[0]["hostname"] == "a" and got[0]["verified"] == "True"


def setup_results_with_corrupt(tmp_path):
    d = tmp_path / "results"
    d.mkdir()
    (d / "a.json").write_text(json.dumps(
        {"schema": "uet-result/1", "host": "a", "outcome": "FIXED",
         "actions": ["service_start"], "blockers": []}))
    (d / "b.json").write_text("{truncated")
    return str(d)


def test_merge_results_corrupt_json_never_aborts(tmp_path):
    rows = merge_results([wi("a", 1), wi("b", 2), wi("c", 3)],
                          setup_results_with_corrupt(tmp_path))
    by = {r["hostname"]: r for r in rows}
    assert by["a"]["outcome"] == "FIXED"
    assert by["b"]["outcome"] == "CORRUPT_RESULT"
    assert by["b"]["actions"] == [] and by["b"]["blockers"] == []
    assert by["c"]["outcome"] == "NOT_RUN"


class StatefulSettleStubSwp:
    """First call reports id 1 inactive; second call onward reports active."""

    def __init__(self):
        self.calls = 0

    def list_computers(self):
        self.calls += 1
        status = "inactive" if self.calls == 1 else "active"
        return [{"ID": 1, "computerStatus": {"agentStatus": status}}]


def test_settle_and_verify_early_exit_once_settled(tmp_path):
    rows = merge_results([wi("a", 1)], setup_results(tmp_path))
    stub = StatefulSettleStubSwp()
    rows = settle_and_verify(rows, stub, attempts=3, delay=60, sleep=lambda _: None)
    assert rows[0]["verified"] is True
    assert stub.calls == 2


def test_settle_and_verify_gives_up_after_attempts(tmp_path):
    class AlwaysInactiveStub:
        def __init__(self):
            self.calls = 0

        def list_computers(self):
            self.calls += 1
            return [{"ID": 1, "computerStatus": {"agentStatus": "inactive"}}]

    rows = merge_results([wi("a", 1)], setup_results(tmp_path))
    stub = AlwaysInactiveStub()
    rows = settle_and_verify(rows, stub, attempts=3, delay=60, sleep=lambda _: None)
    assert rows[0]["verified"] is False
    assert stub.calls == 3
