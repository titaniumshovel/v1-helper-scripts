from __future__ import annotations
from uet.matching import build_index, match_computer, swp_agent_guid, swp_cloud_id

EPS = [
    {"agentGuid": "g-1", "endpointName": "web01.corp.example.com", "lastUsedIp": "10.0.0.1",
     "eppAgent": {"virtualMachineDetails": {"cloudInstanceId": "i-abc"}}},
    {"agentGuid": "g-2", "endpointName": "DB02", "lastUsedIp": "10.0.0.2", "eppAgent": {}},
]


def test_match_by_agent_guid():
    idx = build_index(EPS)
    m, tier = match_computer({"agentGuid": "g-1", "hostName": "nomatch"}, idx)
    assert tier == "agent_guid" and m["endpointName"].startswith("web01")


def test_match_by_agent_guid_capital_swp_variant():
    idx = build_index(EPS)
    m, tier = match_computer({"agentGUID": "g-1", "hostName": "nomatch"}, idx)
    assert tier == "agent_guid" and m["endpointName"].startswith("web01")


def test_swp_agent_guid_variants():
    assert swp_agent_guid({"agentGUID": "g-1"}) == "g-1"
    assert swp_agent_guid({"agentGuid": "g-2"}) == "g-2"
    assert swp_agent_guid({"agentGUID": "g-1", "agentGuid": "g-2"}) == "g-1"
    assert swp_agent_guid({}) is None


def test_match_by_cloud_id():
    idx = build_index(EPS)
    comp = {"hostName": "different", "ec2VirtualMachineSummary": {"instanceID": "i-abc"}}
    m, tier = match_computer(comp, idx)
    assert tier == "cloud_id" and m["agentGuid"] == "g-1"


def test_match_by_hostname_shortname_case_insensitive():
    idx = build_index(EPS)
    m, tier = match_computer({"hostName": "WEB01"}, idx)
    assert tier == "hostname" and m["agentGuid"] == "g-1"


def test_match_by_ip_last_resort():
    idx = build_index(EPS)
    m, tier = match_computer({"hostName": "zzz", "lastIPUsed": "10.0.0.2"}, idx)
    assert tier == "ip" and m["agentGuid"] == "g-2"


def test_no_match():
    idx = build_index(EPS)
    m, tier = match_computer({"hostName": "zzz"}, idx)
    assert m is None and tier == "none"


def test_swp_cloud_id_variants():
    assert swp_cloud_id({"ec2VirtualMachineSummary": {"instanceID": "i-1"}}) == "i-1"
    assert swp_cloud_id({"azureVMId": "vm-9"}) == "vm-9"
    assert swp_cloud_id({}) is None


COLLIDING_SHORTNAME_EPS = [
    {"agentGuid": "g-a", "endpointName": "web01.a.com", "lastUsedIp": "10.1.0.1"},
    {"agentGuid": "g-b", "endpointName": "web01.b.com", "lastUsedIp": "10.1.0.2"},
]

COLLIDING_FULLNAME_EPS = [
    {"agentGuid": "g-c", "endpointName": "web01.corp.example.com", "lastUsedIp": "10.2.0.1"},
    {"agentGuid": "g-d", "endpointName": "WEB01.corp.example.com", "lastUsedIp": "10.2.0.2"},
]


def test_ambiguous_shortname_collision_does_not_match_hostname_tier():
    idx = build_index(COLLIDING_SHORTNAME_EPS)
    m, tier = match_computer({"hostName": "WEB01"}, idx)
    assert tier != "hostname"


def test_ambiguous_shortname_collision_falls_through_to_ip():
    idx = build_index(COLLIDING_SHORTNAME_EPS)
    comp = {"hostName": "WEB01", "lastIPUsed": "10.1.0.2"}
    m, tier = match_computer(comp, idx)
    assert tier == "ip" and m["agentGuid"] == "g-b"


def test_ambiguous_full_hostname_collision_does_not_match_hostname_tier():
    idx = build_index(COLLIDING_FULLNAME_EPS)
    m, tier = match_computer({"hostName": "web01.corp.example.com"}, idx)
    assert tier != "hostname"


def test_single_endpoint_fqdn_shortname_is_not_a_false_collision():
    idx = build_index([
        {"agentGuid": "g-1", "endpointName": "web01.corp.example.com", "lastUsedIp": "10.0.0.1"},
    ])
    m, tier = match_computer({"hostName": "WEB01"}, idx)
    assert tier == "hostname" and m["agentGuid"] == "g-1"


def test_match_by_hostname_uses_displayname_fallback():
    idx = build_index(EPS)
    comp = {"hostName": "not-a-real-host-xyz", "displayName": "web01"}
    m, tier = match_computer(comp, idx)
    assert tier == "hostname" and m["agentGuid"] == "g-1"
