from __future__ import annotations
from uet.classify import classify_computer

NOW = 1_800_000_000_000  # epoch ms
DAY = 86_400_000


def comp(fp=None, last=None, status="inactive"):
    c = {"ID": 1, "hostName": "h", "computerStatus": {"agentStatus": status}}
    if fp:
        c["agentFingerPrint"] = fp
    if last:
        c["lastAgentCommunication"] = last
    return c


def test_managed_returns_none():
    assert classify_computer(comp(fp="AA", last=NOW - DAY, status="active"),
                             liveness=True, now_ms=NOW, stale_days=90) is None


def test_never_activated_and_cloud_gone_is_stale():
    r = classify_computer(comp(), liveness=False, now_ms=NOW, stale_days=90)
    assert r.bucket == "STALE"
    assert len(r.evidence) >= 2  # two independent signals recorded


def test_never_activated_but_live_needs_install():
    r = classify_computer(comp(), liveness=True, now_ms=NOW, stale_days=90)
    assert r.bucket == "NEEDS_INSTALL" and r.recommended_mode == "install"


def test_never_activated_unknown_investigate():
    r = classify_computer(comp(), liveness=None, now_ms=NOW, stale_days=90)
    assert r.bucket == "INVESTIGATE"


def test_old_offline_and_gone_is_stale():
    r = classify_computer(comp(fp="AA", last=NOW - 120 * DAY),
                          liveness=False, now_ms=NOW, stale_days=90)
    assert r.bucket == "STALE"


def test_old_offline_but_live_needs_repair():
    r = classify_computer(comp(fp="AA", last=NOW - 120 * DAY),
                          liveness=True, now_ms=NOW, stale_days=90)
    assert r.bucket == "NEEDS_REPAIR" and r.recommended_mode == "safe"


def test_recent_offline_unknown_liveness_needs_repair():
    r = classify_computer(comp(fp="AA", last=NOW - 5 * DAY),
                          liveness=None, now_ms=NOW, stale_days=90)
    assert r.bucket == "NEEDS_REPAIR"


def test_old_offline_unknown_liveness_investigate():
    r = classify_computer(comp(fp="AA", last=NOW - 120 * DAY),
                          liveness=None, now_ms=NOW, stale_days=90)
    assert r.bucket == "INVESTIGATE"


def test_zero_last_communication_treated_as_never():
    c = comp(fp="AA")
    c["lastAgentCommunication"] = 0  # SWP uses 0 as null/never-communicated
    r = classify_computer(c, liveness=None, now_ms=NOW, stale_days=90)
    assert r.bucket == "INVESTIGATE"
    assert "swp:never_communicated" in r.evidence


def test_agent_present_never_communicated_and_gone_is_stale():
    r = classify_computer(comp(fp="AA"), liveness=False, now_ms=NOW, stale_days=90)
    assert r.bucket == "STALE"
    assert len(r.evidence) >= 2
