from __future__ import annotations

import subprocess

from uet.config import Config
from uet.worklist import WorklistItem


def build_ssh_cmd(host: str, user: str, mode: str, dry_run: bool) -> list[str]:
    """Orchestrated (key-auth) transport: the payload arrives on stdin.

    `sudo -n` is required, not optional. The payload occupies stdin, so sudo has
    nowhere to read a password from; without -n a host whose sudoers demands one
    hangs until the 1200s timeout instead of failing. BatchMode=yes already makes
    the same guarantee for ssh itself. Hosts with interactive ssh/sudo cannot use
    this path at all — use payloads/run-linux-hosts.sh, which stages the payload
    over a multiplexed connection and runs it under a TTY.
    """
    remote = f"sudo -n bash -s -- --mode {mode}" + (" --dry-run" if dry_run else "")
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new", f"{user}@{host}", remote]


def run_host(item: WorklistItem, payload_path: str, mode: str,
             dry_run: bool, cfg: Config, target: str | None = None):
    from uet.transports import HostResult

    # `target` is the address vetted by uet.target.check_target (a private IP
    # where one is known). Falling back to item.hostname keeps direct callers
    # working, but run_hosts always supplies it.
    cmd = build_ssh_cmd(target or item.hostname, cfg.ssh_user, mode, dry_run)
    try:
        with open(payload_path, "rb") as f:
            proc = subprocess.run(cmd, stdin=f, capture_output=True,
                                  text=True, timeout=1200)
        return HostResult(item.hostname, proc.returncode in (0, 2, 3),
                          proc.stdout, proc.stderr, proc.returncode)
    except subprocess.TimeoutExpired:
        return HostResult(item.hostname, False, "", "ssh timeout after 1200s", 124)
    except OSError as e:
        return HostResult(item.hostname, False, "", f"ssh exec failed: {e}", 127)
