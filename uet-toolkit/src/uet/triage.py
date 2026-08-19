from __future__ import annotations

import concurrent.futures
import csv
import socket
import threading
import time

from uet.classify import classify_computer
from uet.config import get_secret, load_config
from uet.matching import build_index, match_computer, swp_agent_guid
from uet.util import RunLog, save_snapshot
from uet.worklist import WorklistItem, write_worklist


def now_ms() -> int:
    return int(time.time() * 1000)


# Names that identify no single host, and so must never be used as a match key.
# Both sides of the comparison are reduced to a short name by splitting on '.',
# which turns an IP address into a bare octet: '10.1.2.3' -> '10'. SWP stores an
# IP address in hostName for a meaningful share of records in some large
# production tenants, so a single '10' key would vouch for hundreds of hosts at
# once. 'localhost' is in the Axonius export for the same reason - it names
# whoever is asking.
_NON_IDENTIFYING = {"localhost"}


def _identifying(short: str) -> bool:
    return bool(short) and not short.isdigit() and short not in _NON_IDENTIFYING


def load_axonius_hosts(path: str | None) -> set[str]:
    if not path:
        return set()
    with open(path, encoding="utf-8") as f:
        return {short for short in
                (row["hostname"].split(".")[0].lower()
                 for row in csv.DictReader(f) if row.get("hostname"))
                if _identifying(short)}


def _v1_has_connected(ep: dict) -> bool:
    """True if the V1 endpoint record shows any real agent/sensor check-in."""
    for key in ("eppAgent", "edrSensor"):
        if ((ep.get(key) or {}).get("lastConnectedDateTime") or "").strip():
            return True
    return False


def axonius_keys(comp: dict) -> list[str]:
    """Short names for an SWP computer to test against the Axonius host list.

    SWP's `hostName` is an IP address for a large share of records in some
    large production tenants, with the real machine name carried only in
    `displayName`. Testing `hostName` alone means those hosts can never pick up
    Axonius liveness evidence no matter how recently Axonius saw them, which
    parks them in INVESTIGATE. Both names are SWP's own labels for the same
    computer, so both are equally valid match keys.
    """
    keys = []
    for field in ("hostName", "displayName"):
        s = (comp.get(field) or "").split(".")[0].lower()
        if _identifying(s):
            keys.append(s)
    return keys


def compute_liveness(comp: dict, match: dict | None, axonius_hosts: set[str],
                     resolve=socket.gethostbyname) -> bool | None:
    if any(k in axonius_hosts for k in axonius_keys(comp)):
        return True
    if match and match.get("agentGuid") and _v1_has_connected(match):
        # a V1 record matched this computer AND its agent/sensor has actually
        # phoned home at least once -> something on that host has reported.
        # (Bare "New Computer" SWP records sync ghost mirrors into V1 with a
        # synthesized agentGuid but no connection history; those prove nothing.)
        return True
    # DNS gone-signal: if the hostname (or its short form) no longer resolves,
    # the host is very likely gone. Resolves -> unknown (None); every attempt
    # raises -> gone (False). socket.gaierror is a subclass of OSError.
    hostname = (comp.get("hostName") or "").strip()
    if not hostname:
        return None
    names = [hostname]
    if "." in hostname:
        names.append(hostname.split(".")[0])
    for name in names:
        try:
            resolve(name)
            return None
        except OSError:
            continue
    return False


_DNS_INCONCLUSIVE = ""  # sentinel resolve() return -> compute_liveness yields None


class _BatchResolver:
    """Resolves hostnames for a whole run_triage batch with bounded
    concurrency, a per-lookup timeout, and per-name memoization.

    It is passed to ``compute_liveness`` as its ``resolve=`` callable, so
    ``compute_liveness`` itself stays pure/synchronous and unchanged: it still
    just calls ``resolve(name)`` and treats a return as "resolved" (unknown)
    and an ``OSError`` as "this name is gone".

    Behavior of the wrapped callable:
      * The real (blocking) resolver runs on a ThreadPoolExecutor, so slow/hung
        lookups across many hosts overlap instead of serializing.
      * A lookup that exceeds ``dns_timeout`` resolves to *inconclusive*: the
        callable returns the sentinel (never raises), so that host's
        DNS-derived liveness becomes ``None`` — never ``False``. A timeout must
        not push a candidate to STALE.
      * Each unique name invokes the underlying resolver at most once per run.
      * With ``no_dns=True`` no executor is created and every lookup is
        inconclusive (returns the sentinel), so no host can be marked
        DNS-gone; STALE is then driven only by non-DNS signals.
    """

    def __init__(self, resolve, dns_timeout: float, dns_workers: int, no_dns: bool):
        self._resolve = resolve
        self._timeout = dns_timeout
        self._no_dns = no_dns
        self._lock = threading.Lock()
        self._futures: dict[str, concurrent.futures.Future] = {}
        self._submitted_at: dict[str, float] = {}
        self._outcomes: dict[str, tuple[str, object]] = {}
        self._executor = (
            None if no_dns
            else concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, dns_workers), thread_name_prefix="uet-dns")
        )

    def submit(self, name: str) -> None:
        """Prewarm: kick off the underlying lookup now so that when the main
        loop later blocks on it the work is already in flight (overlapping the
        per-lookup timeout windows across hosts)."""
        if self._no_dns or not name:
            return
        self._ensure(name)

    def _ensure(self, name: str):
        with self._lock:
            fut = self._futures.get(name)
            if fut is None:
                fut = self._executor.submit(self._resolve, name)
                self._futures[name] = fut
                self._submitted_at[name] = time.monotonic()
            return fut, self._submitted_at[name]

    def resolve(self, name: str):
        if self._no_dns:
            return _DNS_INCONCLUSIVE
        with self._lock:
            memo = self._outcomes.get(name)
        if memo is None:
            fut, submitted_at = self._ensure(name)
            # Deadline is measured from submission, not from this call, so a
            # batch of prewarmed lookups shares one ~dns_timeout window rather
            # than each re-arming the full timeout serially.
            remaining = self._timeout - (time.monotonic() - submitted_at)
            if remaining < 0:
                remaining = 0
            try:
                memo = ("return", fut.result(timeout=remaining))
            except concurrent.futures.TimeoutError:
                memo = ("return", _DNS_INCONCLUSIVE)
            except OSError as exc:
                memo = ("raise", exc)
            with self._lock:
                memo = self._outcomes.setdefault(name, memo)
        kind, val = memo
        if kind == "raise":
            raise val
        return val

    def shutdown(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)


def run_triage(v1, swp, stale_days: int, axonius_csv: str | None,
               workdir: str, log: RunLog | None = None,
               resolve=socket.gethostbyname,
               dns_timeout: float = 5.0, dns_workers: int = 32,
               no_dns: bool = False) -> list[WorklistItem]:
    log = log or RunLog(workdir)
    endpoints = v1.list_endpoints()
    computers = swp.list_computers()
    save_snapshot(workdir, "v1-endpoints", endpoints)
    save_snapshot(workdir, "swp-computers", computers)
    log.event("triage_inventory", v1_count=len(endpoints), swp_count=len(computers))

    axonius_hosts = load_axonius_hosts(axonius_csv)
    index = build_index(endpoints)
    dns = _BatchResolver(resolve, dns_timeout, dns_workers, no_dns)

    # First pass: resolve V1 matches and prewarm DNS lookups. We only prewarm
    # hosts that will actually reach compute_liveness's DNS branch — i.e. those
    # with neither an Axonius hit nor a matched V1 agent (both short-circuit to
    # live before any DNS is attempted).
    prepared: list[tuple[dict, dict | None, str]] = []
    for comp in computers:
        match, tier = match_computer(comp, index)
        prepared.append((comp, match, tier))
        if any(k in axonius_hosts for k in axonius_keys(comp)):
            continue
        if match and match.get("agentGuid"):
            continue
        dns.submit((comp.get("hostName") or "").strip())

    items: list[WorklistItem] = []
    now = now_ms()
    try:
        for comp, match, tier in prepared:
            liveness = compute_liveness(comp, match, axonius_hosts, resolve=dns.resolve)
            cls = classify_computer(comp, liveness, now, stale_days)
            if cls is None:
                continue
            evidence = cls.evidence + [f"match:{tier}"]
            if liveness is False:
                # surface *why* the host reads as gone, so the delete reviewer sees it
                evidence.append("liveness:dns_unresolved")
            os_name = comp.get("platform") or ""
            # SWP platform is commonly empty/"Unknown" for the NEEDS_INSTALL
            # population; fall back to the matched V1 record's osPlatform.
            if (not os_name or "unknown" in os_name.lower()) and match and match.get("osPlatform"):
                os_name = match["osPlatform"]
            items.append(WorklistItem(
                hostname=comp.get("hostName") or comp.get("displayName") or f"swp-{comp['ID']}",
                swp_id=comp["ID"],
                agent_guid=swp_agent_guid(comp) or (match or {}).get("agentGuid", ""),
                ips=[ip for ip in [comp.get("lastIPUsed")] if ip],
                os=os_name,
                bucket=cls.bucket,
                evidence=evidence,
                recommended_mode=cls.recommended_mode,
                match_tier=tier,
            ))
    finally:
        dns.shutdown()
    jpath, cpath = write_worklist(items, workdir)
    counts: dict[str, int] = {}
    for i in items:
        counts[i.bucket] = counts.get(i.bucket, 0) + 1
    log.event("triage_done", counts=counts, worklist=jpath)
    print(f"worklist written: {jpath} / {cpath}")
    for bucket in ("STALE", "NEEDS_INSTALL", "NEEDS_REPAIR", "INVESTIGATE"):
        print(f"  {bucket:14s} {counts.get(bucket, 0)}")

    try:  # payload generation added in a later task; keep triage usable without it
        from uet.payload_gen import generate_payloads
        generate_payloads(swp, workdir)
    except ModuleNotFoundError:
        # tolerate absence in partial installs; real import errors inside payload_gen must surface
        pass
    return items


def cmd_triage(args) -> int:
    from uet.swp_client import SwpClient
    from uet.v1_client import V1Client

    cfg = load_config(args.config)
    if not cfg.swp_base_url:
        raise SystemExit("error: [swp] base_url missing in uet.toml (see docs/api-notes.md)")
    v1 = V1Client(cfg.v1_base_url, get_secret("V1_API_KEY", args.key_file))
    swp = SwpClient(cfg.swp_base_url, get_secret("SWP_API_SECRET", args.swp_key_file))
    run_triage(v1, swp, cfg.stale_days, args.axonius_csv, cfg.workdir,
               dns_timeout=getattr(args, "dns_timeout", 5.0),
               dns_workers=getattr(args, "dns_workers", 32),
               no_dns=getattr(args, "no_dns", False))
    return 0
