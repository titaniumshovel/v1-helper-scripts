from __future__ import annotations

from dataclasses import dataclass, field

DAY_MS = 86_400_000


@dataclass
class Classification:
    bucket: str
    evidence: list[str] = field(default_factory=list)
    recommended_mode: str = "none"


def classify_computer(
    comp: dict, liveness: bool | None, now_ms: int, stale_days: int
) -> Classification | None:
    status = (comp.get("computerStatus") or {}).get("agentStatus", "unknown")
    fp = comp.get("agentFingerPrint")
    last = comp.get("lastAgentCommunication")
    # 0 or absent both mean "never communicated" (API null convention)
    offline_days = (now_ms - last) / DAY_MS if last else None

    if fp and status == "active":
        return None  # managed and healthy; not our problem

    ev: list[str] = [f"swp:agentStatus={status}"]
    if offline_days is not None:
        ev.append(f"swp:offline_days={offline_days:.0f}")
    else:
        ev.append("swp:never_communicated")
    if liveness is True:
        ev.append("liveness:host_appears_live")
    elif liveness is False:
        ev.append("liveness:host_appears_gone")
    else:
        ev.append("liveness:unknown")

    if not fp:  # never activated
        ev.append("swp:never_activated")
        if liveness is False:
            return Classification("STALE", ev)
        if liveness is True:
            return Classification("NEEDS_INSTALL", ev, "install")
        return Classification("INVESTIGATE", ev)

    # agent exists but not healthy
    if liveness is True:
        return Classification("NEEDS_REPAIR", ev, "safe")
    stale_by_age = offline_days is not None and offline_days > stale_days
    if stale_by_age and liveness is False:
        return Classification("STALE", ev)
    if not stale_by_age and offline_days is not None:
        return Classification("NEEDS_REPAIR", ev, "safe")
    if offline_days is None and liveness is False:
        # never communicated + host appears gone: two independent signals
        return Classification("STALE", ev)
    return Classification("INVESTIGATE", ev)
