from __future__ import annotations

import ipaddress
import socket

from uet.worklist import WorklistItem

# Transports that open a network connection to the host themselves, and so can
# be pointed at the wrong machine by a bad hostname. `ssm` is deliberately
# absent: it resolves a target through the EC2/SSM APIs (instance ID), never by
# dialling the worklist hostname, so a public-resolving hostname can't misroute
# it onto the internet.
DIRECT_CONNECT_TRANSPORTS = frozenset({"ssh", "winrm"})


def _parse_networks(cidrs) -> list:
    nets = []
    for raw in cidrs or ():
        text = (raw or "").strip()
        if not text:
            continue
        try:
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            raise SystemExit(
                f"error: [run] allowed_cidrs contains an invalid CIDR: {text!r}"
            )
    return nets


def is_allowed_ip(ip: str, allowed_cidrs=()) -> bool:
    """True if `ip` is somewhere we're willing to send a payload.

    Private (RFC1918/loopback/link-local) always qualifies. Anything else has
    to be named explicitly in `[run] allowed_cidrs` — for tenants that run
    public-registered space internally.
    """
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    if addr.is_unspecified or addr.is_multicast or addr.is_reserved:
        return False
    if addr.is_private:
        return True
    return any(addr in net for net in _parse_networks(allowed_cidrs))


def check_target(item: WorklistItem, allowed_cidrs=(),
                 resolve=socket.gethostbyname) -> tuple[str | None, str | None]:
    """Pick a safe connect target for a direct-connect transport.

    Returns `(target, None)` or `(None, error)` — exactly one is set.

    A worklist IP wins over the hostname. SWP's `lastIPUsed` is an address the
    agent actually reported from, whereas `hostName` is whatever the host
    believed its own name was at registration time — which, if it was resolving
    itself through public DNS, can be an ISP reverse-DNS name pointing at a
    completely unrelated address (see docs/api-notes.md, "ISP-named hosts").
    """
    _parse_networks(allowed_cidrs)  # fail fast on malformed config
    for ip in item.ips:
        if is_allowed_ip(ip, allowed_cidrs):
            return ip, None

    host = (item.hostname or "").strip()
    known = ", ".join(item.ips) if item.ips else "none"
    if not host:
        return None, (f"no connect target: worklist has no hostname and no "
                      f"private IP (ips={known})")
    if is_allowed_ip(host, allowed_cidrs):
        return host, None  # hostname field is already a usable literal IP

    try:
        resolved = resolve(host)
    except OSError as e:
        return None, (f"refusing {host}: hostname does not resolve "
                      f"({type(e).__name__}) and worklist has no private IP "
                      f"(ips={known})")
    if not is_allowed_ip(resolved, allowed_cidrs):
        return None, (
            f"refusing {host}: resolves to {resolved}, outside "
            f"RFC1918/allowed ranges — connecting would reach a third party on "
            f"the public internet, not this host (worklist ips={known}). This "
            f"is what an ISP-generated reverse-DNS hostname looks like. If that "
            f"range really is yours, add it to [run] allowed_cidrs in uet.toml; "
            f"to override the check entirely, re-run with --allow-public-target."
        )
    return host, None
