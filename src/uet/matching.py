from __future__ import annotations

# Sentinel marking a hostname/shortname key claimed by more than one distinct
# endpoint. Such keys must never resolve to a hostname-tier match.
_AMBIGUOUS = object()


def _shortname(name: str) -> str:
    return name.split(".")[0].lower()


def swp_agent_guid(comp: dict) -> str | None:
    # Live SWP /api/computers/search returns "agentGUID" (capital GUID).
    # Fall back to "agentGuid" for older/alternate payload shapes.
    return comp.get("agentGUID") or comp.get("agentGuid")


def swp_cloud_id(comp: dict) -> str | None:
    ec2 = comp.get("ec2VirtualMachineSummary") or {}
    if ec2.get("instanceID"):
        return ec2["instanceID"]
    if comp.get("azureVMId"):
        return comp["azureVMId"]
    return None


def _ep_cloud_id(ep: dict) -> str | None:
    return ((ep.get("eppAgent") or {}).get("virtualMachineDetails") or {}).get(
        "cloudInstanceId"
    )


def _claim_hostname_key(by_hostname: dict, key: str, ep: dict) -> None:
    """Insert `key -> ep`, marking the key _AMBIGUOUS if it is already
    claimed by a *different* endpoint. Once ambiguous, a key stays
    ambiguous regardless of further insertions.
    """
    existing = by_hostname.get(key)
    if existing is _AMBIGUOUS:
        return
    if existing is not None and existing is not ep:
        by_hostname[key] = _AMBIGUOUS
    else:
        by_hostname[key] = ep


def build_index(endpoints: list[dict]) -> dict:
    idx: dict = {"by_guid": {}, "by_cloud_id": {}, "by_hostname": {}, "by_ip": {}}
    for ep in endpoints:
        if ep.get("agentGuid"):
            idx["by_guid"][ep["agentGuid"]] = ep
        cid = _ep_cloud_id(ep)
        if cid:
            idx["by_cloud_id"][cid] = ep
        name = (ep.get("endpointName") or "").lower()
        if name:
            _claim_hostname_key(idx["by_hostname"], name, ep)
            _claim_hostname_key(idx["by_hostname"], _shortname(name), ep)
        ip = ep.get("lastUsedIp")
        if ip:
            idx["by_ip"][ip] = ep
    return idx


def match_computer(comp: dict, index: dict) -> tuple[dict | None, str]:
    guid = swp_agent_guid(comp)
    if guid and guid in index["by_guid"]:
        return index["by_guid"][guid], "agent_guid"
    cid = swp_cloud_id(comp)
    if cid and cid in index["by_cloud_id"]:
        return index["by_cloud_id"][cid], "cloud_id"
    for key in ("hostName", "displayName"):
        name = (comp.get(key) or "").lower()
        if name:
            hit = index["by_hostname"].get(name)
            if hit is None or hit is _AMBIGUOUS:
                hit = index["by_hostname"].get(_shortname(name))
            if hit is not None and hit is not _AMBIGUOUS:
                return hit, "hostname"
    ip = comp.get("lastIPUsed")
    if ip and ip in index["by_ip"]:
        return index["by_ip"][ip], "ip"
    return None, "none"
