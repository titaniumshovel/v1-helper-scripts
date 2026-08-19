from __future__ import annotations
import glob
import json
import pytest
from uet.delete import load_approved, run_delete


def make_csv(tmp_path, rows, header="hostname,swp_id,bucket,approved"):
    p = tmp_path / "stale.csv"
    p.write_text(header + "\n" + "\n".join(rows) + "\n")
    return str(p)


class StubSwp:
    def __init__(self):
        self.deleted = []

    def get_computer(self, cid):
        return {"ID": cid, "hostName": f"host{cid}"}

    def delete_computer(self, cid):
        self.deleted.append(cid)


def test_load_approved_filters(tmp_path):
    p = make_csv(tmp_path, ["a,1,STALE,yes", "b,2,STALE,no",
                            "c,3,STALE,YES", "d,4,STALE,"])
    rows = load_approved(p)
    assert [r["swp_id"] for r in rows] == ["1", "3"]


def test_load_approved_requires_column(tmp_path):
    p = make_csv(tmp_path, ["a,1"], header="hostname,swp_id")
    with pytest.raises(SystemExit):
        load_approved(p)


def test_approved_non_stale_row_is_refused(tmp_path):
    # The guard that matters: one 'yes' on a repair candidate must not delete it.
    p = make_csv(tmp_path, ["a,1,STALE,yes", "b,7687347,NEEDS_REPAIR,yes"])
    with pytest.raises(SystemExit) as exc:
        load_approved(p)
    msg = str(exc.value)
    assert "NEEDS_REPAIR" in msg and "7687347" in msg
    assert "--allow-non-stale" in msg


def test_allow_non_stale_permits_it(tmp_path):
    p = make_csv(tmp_path, ["a,1,STALE,yes", "b,2,NEEDS_REPAIR,yes"])
    rows = load_approved(p, allow_non_stale=True)
    assert [r["swp_id"] for r in rows] == ["1", "2"]


def test_investigate_and_empty_bucket_are_refused(tmp_path):
    for bucket in ("INVESTIGATE", ""):
        p = make_csv(tmp_path, [f"a,1,{bucket},yes"])
        with pytest.raises(SystemExit):
            load_approved(p)


def test_bucket_check_is_case_insensitive(tmp_path):
    p = make_csv(tmp_path, ["a,1,stale,yes", "b,2, STALE ,yes"])
    assert len(load_approved(p)) == 2


def test_missing_bucket_column_is_refused_by_default(tmp_path):
    p = make_csv(tmp_path, ["a,1,yes"], header="hostname,swp_id,approved")
    with pytest.raises(SystemExit) as exc:
        load_approved(p)
    assert "bucket" in str(exc.value)


def test_missing_bucket_column_is_fine_when_overridden(tmp_path):
    p = make_csv(tmp_path, ["a,1,yes"], header="hostname,swp_id,approved")
    assert len(load_approved(p, allow_non_stale=True)) == 1


def test_no_approved_rows_skips_the_bucket_check(tmp_path):
    # Nothing approved means nothing to delete; don't error on a missing column.
    p = make_csv(tmp_path, ["a,1,no"], header="hostname,swp_id,approved")
    assert load_approved(p) == []


def test_refusal_message_truncates_long_lists(tmp_path):
    rows = [f"h{i},{i},NEEDS_REPAIR,yes" for i in range(15)]
    p = make_csv(tmp_path, rows)
    with pytest.raises(SystemExit) as exc:
        load_approved(p)
    assert "and 5 more" in str(exc.value)


def test_dry_run_makes_no_delete_calls(tmp_path):
    swp = StubSwp()
    out = run_delete([{"hostname": "a", "swp_id": "1"}], swp, str(tmp_path), execute=False)
    assert swp.deleted == []
    assert out["deleted"] == 0 and out["backed_up"] == 1
    backups = glob.glob(str(tmp_path / "delete-backup-*.json"))
    assert len(backups) == 1
    assert json.load(open(backups[0]))[0]["hostName"] == "host1"


def test_execute_deletes_and_collects_errors(tmp_path):
    class Flaky(StubSwp):
        def delete_computer(self, cid):
            if cid == 2:
                raise RuntimeError("boom")
            super().delete_computer(cid)

    swp = Flaky()
    out = run_delete([{"hostname": "a", "swp_id": "1"},
                      {"hostname": "b", "swp_id": "2"},
                      {"hostname": "c", "swp_id": "3"}], swp, str(tmp_path), execute=True)
    assert swp.deleted == [1, 3]
    assert out["deleted"] == 2 and len(out["errors"]) == 1


def test_backup_failure_skips_that_hosts_delete(tmp_path):
    class BackupFlaky(StubSwp):
        def get_computer(self, cid):
            if cid == 2:
                raise RuntimeError("backup boom")
            return super().get_computer(cid)

    swp = BackupFlaky()
    out = run_delete([{"hostname": "a", "swp_id": "1"},
                      {"hostname": "b", "swp_id": "2"},
                      {"hostname": "c", "swp_id": "3"}], swp, str(tmp_path), execute=True)
    assert swp.deleted == [1, 3]
    assert 2 not in swp.deleted
    backup_errors = [e for e in out["errors"] if e["stage"] == "backup"]
    assert len(backup_errors) == 1
    assert out["deleted"] == 2
    assert out["backed_up"] == 2


def test_malformed_swp_id_is_per_row_error(tmp_path):
    swp = StubSwp()
    out = run_delete([{"hostname": "bad", "swp_id": "12x"},
                      {"hostname": "host3", "swp_id": "3"}], swp, str(tmp_path), execute=True)
    assert swp.deleted == [3]
    parse_errors = [e for e in out["errors"] if e["stage"] == "parse"]
    assert len(parse_errors) == 1
    backups = glob.glob(str(tmp_path / "delete-backup-*.json"))
    assert len(backups) == 1
    records = json.load(open(backups[0]))
    assert len(records) == 1
    assert records[0]["hostName"] == "host3"
