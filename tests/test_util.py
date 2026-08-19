from __future__ import annotations
import json
import os
import time
from uet.util import save_snapshot, load_latest_snapshot, RunLog


def test_snapshot_roundtrip(tmp_path):
    wd = str(tmp_path)
    p = save_snapshot(wd, "swp-computers", [{"ID": 1}])
    assert os.path.exists(p)
    got = load_latest_snapshot(wd, "swp-computers", max_age_hours=1)
    assert got == [{"ID": 1}]


def test_snapshot_expiry(tmp_path):
    wd = str(tmp_path)
    p = save_snapshot(wd, "x", {"a": 1})
    old = time.time() - 3 * 3600
    os.utime(p, (old, old))
    assert load_latest_snapshot(wd, "x", max_age_hours=2) is None


def test_snapshot_missing(tmp_path):
    assert load_latest_snapshot(str(tmp_path), "nope", max_age_hours=1) is None


def test_runlog_appends_jsonl(tmp_path):
    log = RunLog(str(tmp_path))
    log.event("triage_start", total=5)
    log.event("api_error", url="http://x", status=429)
    lines = [json.loads(l) for l in open(log.path, encoding="utf-8")]
    assert lines[0]["kind"] == "triage_start" and lines[0]["total"] == 5
    assert lines[1]["status"] == 429
    assert "ts" in lines[0]


def test_snapshot_name_prefix_not_confused(tmp_path):
    wd = str(tmp_path)
    # "swp-computers" is saved first, then a distinct "swp" snapshot.
    save_snapshot(wd, "swp-computers", [{"ID": "computer-only"}])
    save_snapshot(wd, "swp", {"kind": "swp-only"})
    got = load_latest_snapshot(wd, "swp", max_age_hours=1)
    assert got == {"kind": "swp-only"}


def test_snapshot_name_prefix_no_match_returns_none(tmp_path):
    wd = str(tmp_path)
    # Only a "swp-computers" snapshot exists; "swp" itself was never saved.
    save_snapshot(wd, "swp-computers", [{"ID": "computer-only"}])
    assert load_latest_snapshot(wd, "swp", max_age_hours=1) is None


def test_runlog_paths_are_unique(tmp_path):
    wd = str(tmp_path)
    paths = [RunLog(wd).path for _ in range(5)]
    assert len(set(paths)) == len(paths)


def test_save_snapshot_paths_are_unique(tmp_path):
    wd = str(tmp_path)
    paths = [save_snapshot(wd, "dup", {"i": i}) for i in range(5)]
    assert len(set(paths)) == len(paths)
