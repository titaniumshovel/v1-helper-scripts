from __future__ import annotations
import csv
import json
from uet.worklist import WorklistItem, write_worklist, read_worklist


def item(**kw):
    base = dict(hostname="h1", swp_id=1, agent_guid="g", ips=["10.0.0.1"], os="linux",
                bucket="NEEDS_REPAIR", evidence=["e1", "e2"], recommended_mode="safe",
                match_tier="agent_guid")
    base.update(kw)
    return WorklistItem(**base)


def test_write_and_read_roundtrip(tmp_path):
    jpath, cpath = write_worklist([item()], str(tmp_path))
    data = json.load(open(jpath, encoding="utf-8"))
    assert data["schema"] == "uet-worklist/1"
    got = read_worklist(jpath)
    assert got[0].hostname == "h1" and got[0].evidence == ["e1", "e2"]
    rows = list(csv.DictReader(open(cpath, encoding="utf-8")))
    assert rows[0]["bucket"] == "NEEDS_REPAIR"
    assert rows[0]["evidence"] == "e1;e2"
