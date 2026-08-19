from __future__ import annotations
import json
import socket
import threading
import time
from collections import Counter
import pytest
from uet import triage as tri


def _resolves(name):
    return "1.2.3.4"


def _unresolvable(name):
    raise socket.gaierror("nodename nor servname provided")


class StubV1:
    def list_endpoints(self):
        return [{"agentGuid": "g-1", "endpointName": "web01", "lastUsedIp": "10.1.1.1",
                 "eppAgent": {}}]


class StubSwp:
    def list_computers(self):
        return [
            # managed & healthy -> dropped
            {"ID": 1, "hostName": "ok01", "agentFingerPrint": "AA",
             "lastAgentCommunication": tri.now_ms() - 1000,
             "computerStatus": {"agentStatus": "active"}},
            # agent guid matches a live V1 endpoint, agent inactive -> NEEDS_REPAIR
            # (live SWP API casing: agentGUID, not agentGuid)
            {"ID": 2, "hostName": "web01", "agentGUID": "g-1", "agentFingerPrint": "BB",
             "lastAgentCommunication": tri.now_ms() - 3 * 86_400_000,
             "computerStatus": {"agentStatus": "inactive"}},
            # never activated, in axonius (live) -> NEEDS_INSTALL
            {"ID": 3, "hostName": "new01", "computerStatus": {"agentStatus": "unknown"}},
        ]

    def generate_deployment_script(self, platform):
        return "#!/bin/bash\nACTIVATIONURL='dsm://mgr:443/'"


def test_triage_buckets(tmp_path, monkeypatch):
    axonius = tmp_path / "ax.csv"
    axonius.write_text("hostname\nnew01\n")
    # inject a resolver that always "resolves" so previously-live hosts
    # (e.g. ok01, which has no axonius/V1 signal) never hit real DNS in tests
    items = tri.run_triage(StubV1(), StubSwp(), stale_days=90,
                           axonius_csv=str(axonius), workdir=str(tmp_path),
                           resolve=_resolves)
    by_host = {i.hostname: i for i in items}
    assert set(by_host) == {"web01", "new01"}
    assert by_host["web01"].bucket == "NEEDS_REPAIR"
    assert by_host["web01"].match_tier == "agent_guid"
    assert by_host["web01"].agent_guid == "g-1"
    assert by_host["new01"].bucket == "NEEDS_INSTALL"
    wl = json.load(open(tmp_path / "worklist.json", encoding="utf-8"))
    assert wl["schema"] == "uet-worklist/1"


def test_compute_liveness_axonius_hit_is_true():
    comp = {"hostName": "new01.corp"}
    assert tri.compute_liveness(comp, None, {"new01"}, resolve=_unresolvable) is True


def test_compute_liveness_axonius_hit_on_display_name_is_true():
    # SWP carries an IP in hostName for a large share of records and the real
    # machine name only in displayName; matching hostName alone would leave
    # those hosts with no Axonius evidence at all.
    comp = {"hostName": "172.19.245.54", "displayName": "AEULAUMBVA01P"}
    assert tri.compute_liveness(comp, None, {"aeulaumbva01p"},
                                resolve=_unresolvable) is True


def test_compute_liveness_display_name_miss_does_not_invent_liveness():
    comp = {"hostName": "172.19.245.54", "displayName": "AEULAUMBVA01P"}
    # unrelated host in the list -> no Axonius hit; falls through to DNS, and
    # an IP-shaped hostName that does not resolve still reads as gone
    assert tri.compute_liveness(comp, None, {"somethingelse"},
                                resolve=_unresolvable) is False


def test_axonius_keys_skips_empty_fields():
    assert tri.axonius_keys({"hostName": "web01.corp"}) == ["web01"]
    assert tri.axonius_keys({"displayName": "WEB01"}) == ["web01"]
    assert tri.axonius_keys({}) == []


def test_axonius_keys_drops_non_identifying_names():
    # '10.1.2.3'.split('.')[0] == '10' would otherwise match every host on the
    # /8; SWP stores an IP in hostName for a large share of records.
    assert tri.axonius_keys({"hostName": "10.1.2.3",
                             "displayName": "WEB01"}) == ["web01"]
    assert tri.axonius_keys({"hostName": "localhost"}) == []
    assert tri.axonius_keys({"hostName": "172.19.194.116"}) == []


def test_ip_named_host_is_not_live_via_octet_collision(tmp_path):
    ax = tmp_path / "ax.csv"
    ax.write_text("hostname\n10.9.9.9\nlocalhost\nweb01\n")
    hosts = tri.load_axonius_hosts(str(ax))
    assert hosts == {"web01"}
    comp = {"hostName": "10.1.2.3", "displayName": "10.1.2.3"}
    assert tri.compute_liveness(comp, None, hosts, resolve=_unresolvable) is False


def test_compute_liveness_v1_match_with_connection_evidence_is_true():
    comp = {"hostName": "web01"}
    match = {"agentGuid": "g-1",
             "eppAgent": {"lastConnectedDateTime": "2026-07-08T19:55:33"}}
    assert tri.compute_liveness(comp, match, set(), resolve=_unresolvable) is True


def test_compute_liveness_v1_match_via_edr_sensor_is_true():
    comp = {"hostName": "web01"}
    match = {"agentGuid": "g-1",
             "eppAgent": {"lastConnectedDateTime": ""},
             "edrSensor": {"lastConnectedDateTime": "2026-07-05T00:03:47"}}
    assert tri.compute_liveness(comp, match, set(), resolve=_unresolvable) is True


def test_compute_liveness_ghost_mirror_match_is_not_live():
    # Creating a bare "New Computer" record in SWP syncs a ghost mirror into
    # V1 Endpoint Inventory with a *synthesized* agentGuid but no connection
    # history (live-verified against TrendAI-East 2026-07-08). A ghost match
    # must NOT prove liveness — fall through to DNS (unresolvable -> gone).
    comp = {"hostName": "uet-fake-stale01"}
    match = {"agentGuid": "2b5e66da-c021-567b-f8fa-4570311a3560",
             "eppAgent": {"lastConnectedDateTime": "", "status": "unknown"},
             "edrSensor": {"lastConnectedDateTime": None}}
    assert tri.compute_liveness(comp, match, set(), resolve=_unresolvable) is False


def test_compute_liveness_dns_resolves_is_unknown():
    comp = {"hostName": "maybe01.corp"}
    assert tri.compute_liveness(comp, None, set(), resolve=_resolves) is None


def test_compute_liveness_dns_unresolved_is_false():
    comp = {"hostName": "gone01.corp"}
    assert tri.compute_liveness(comp, None, set(), resolve=_unresolvable) is False


def test_compute_liveness_falls_back_to_shortname():
    seen = []

    def resolve(name):
        seen.append(name)
        if "." in name:  # FQDN fails
            raise socket.gaierror("no fqdn")
        return "1.2.3.4"  # short name resolves

    comp = {"hostName": "host01.corp.example"}
    assert tri.compute_liveness(comp, None, set(), resolve=resolve) is None
    assert seen == ["host01.corp.example", "host01"]


class EnrichV1:
    def list_endpoints(self):
        return [{"agentGuid": "g-2", "endpointName": "enrich01", "osPlatform": "Windows"}]


class EnrichSwp:
    def list_computers(self):
        return [
            # SWP platform is empty/"unknown"; matched V1 record supplies osPlatform
            {"ID": 5, "hostName": "enrich01", "agentGUID": "g-2", "platform": "Unknown",
             "agentFingerPrint": "CC",
             "lastAgentCommunication": tri.now_ms() - 3 * 86_400_000,
             "computerStatus": {"agentStatus": "inactive"}},
        ]

    def generate_deployment_script(self, platform):
        return "#!/bin/bash\nACTIVATIONURL='dsm://mgr:443/'"


def test_run_triage_enriches_os_from_v1_when_swp_unknown(tmp_path):
    items = tri.run_triage(EnrichV1(), EnrichSwp(), stale_days=90,
                           axonius_csv=None, workdir=str(tmp_path),
                           resolve=_resolves)
    by_host = {i.hostname: i for i in items}
    assert by_host["enrich01"].os == "Windows"


class StaleV1:
    def list_endpoints(self):
        return []


class StaleSwp:
    def list_computers(self):
        return [
            # never activated (no fingerprint), no axonius, no V1 match,
            # and DNS won't resolve -> must land in STALE
            {"ID": 9, "hostName": "gone99.corp",
             "computerStatus": {"agentStatus": "unknown"}},
        ]

    def generate_deployment_script(self, platform):
        return "#!/bin/bash\nACTIVATIONURL='dsm://mgr:443/'"


def test_run_triage_never_activated_unresolvable_is_stale(tmp_path):
    # END-TO-END: a never-activated host whose hostname does not resolve in DNS
    # must be classified STALE with dns evidence (regression: STALE was
    # unreachable because compute_liveness never returned False).
    items = tri.run_triage(StaleV1(), StaleSwp(), stale_days=90,
                           axonius_csv=None, workdir=str(tmp_path),
                           resolve=_unresolvable)
    by_host = {i.hostname: i for i in items}
    assert by_host["gone99.corp"].bucket == "STALE"
    assert "liveness:dns_unresolved" in by_host["gone99.corp"].evidence


class _NeverActivatedSwp:
    """Several never-activated hosts, each with a distinct hostname, so the
    DNS gone-signal is the only thing that can move them off INVESTIGATE."""

    def __init__(self, hostnames):
        self._hostnames = list(hostnames)

    def list_computers(self):
        return [{"ID": i, "hostName": h, "computerStatus": {"agentStatus": "unknown"}}
                for i, h in enumerate(self._hostnames, start=1)]

    def generate_deployment_script(self, platform):
        return "#!/bin/bash\nACTIVATIONURL='dsm://mgr:443/'"


class _EmptyV1:
    def list_endpoints(self):
        return []


def test_run_triage_slow_dns_times_out_to_none_and_stays_fast(tmp_path):
    # A resolver that hangs (sleeps >> dns_timeout) for several hosts must not
    # serialize the timeout waits: with bounded concurrency + a per-lookup
    # timeout the whole run finishes in well under the serial-blocking time,
    # and each slow host resolves to None/inconclusive (INVESTIGATE), never
    # False/STALE.
    slow = ["slow1.corp", "slow2.corp", "slow3.corp", "slow4.corp"]

    def resolver(name):
        # every candidate name for the slow hosts hangs
        time.sleep(2.0)
        return "1.2.3.4"

    start = time.monotonic()
    items = tri.run_triage(_EmptyV1(), _NeverActivatedSwp(slow), stale_days=90,
                           axonius_csv=None, workdir=str(tmp_path),
                           resolve=resolver, dns_timeout=0.1, dns_workers=32)
    elapsed = time.monotonic() - start
    # serial blocking would be >= len(slow) * 2.0s = 8s; parallel + timeout is
    # dominated by a single ~0.1s timeout window.
    assert elapsed < 2.0, f"triage took {elapsed:.2f}s — DNS not parallel/bounded"
    by_host = {i.hostname: i for i in items}
    for h in slow:
        assert by_host[h].bucket == "INVESTIGATE"
        assert "liveness:unknown" in by_host[h].evidence
        assert "liveness:dns_unresolved" not in by_host[h].evidence


def test_run_triage_no_dns_never_activated_is_investigate(tmp_path):
    # --no-dns: the resolver must never be consulted, and a never-activated,
    # otherwise-unresolvable host must NOT be marked STALE (the DNS gone-signal
    # is off) — it lands in INVESTIGATE.
    def resolver(name):
        raise AssertionError("resolver must not be called in --no-dns mode")

    items = tri.run_triage(_EmptyV1(), _NeverActivatedSwp(["gone-nodns.corp"]),
                           stale_days=90, axonius_csv=None, workdir=str(tmp_path),
                           resolve=resolver, no_dns=True)
    by_host = {i.hostname: i for i in items}
    assert by_host["gone-nodns.corp"].bucket == "INVESTIGATE"
    assert "liveness:dns_unresolved" not in by_host["gone-nodns.corp"].evidence


def test_run_triage_memoizes_resolution_per_hostname(tmp_path):
    # Two computers sharing a hostname must trigger the underlying resolver at
    # most once for that name (per-run memoization/dedupe).
    counts = Counter()
    lock = threading.Lock()

    def resolver(name):
        with lock:
            counts[name] += 1
        return "1.2.3.4"

    class DupSwp:
        def list_computers(self):
            return [
                {"ID": 1, "hostName": "dup01.corp", "computerStatus": {"agentStatus": "unknown"}},
                {"ID": 2, "hostName": "dup01.corp", "computerStatus": {"agentStatus": "unknown"}},
            ]

        def generate_deployment_script(self, platform):
            return "#!/bin/bash\nACTIVATIONURL='dsm://mgr:443/'"

    tri.run_triage(_EmptyV1(), DupSwp(), stale_days=90, axonius_csv=None,
                   workdir=str(tmp_path), resolve=resolver, dns_timeout=5.0)
    assert counts["dup01.corp"] == 1
