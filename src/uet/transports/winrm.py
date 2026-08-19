from __future__ import annotations

import base64
import os
import uuid

from uet.config import Config
from uet.worklist import WorklistItem

# Windows caps a process command line at ~8191 chars, and pywinrm's
# run_ps/run_cmd deliver the whole script as one `powershell -encodedcommand`
# command line — any real payload (ours embeds a base64 deployment script)
# blows that limit with WSManFaultError "The filename or extension is too
# long" (live-verified 2026-07-08). So: transfer the payload to the host as
# base64 chunks appended to a temp file with small `echo` commands, then run a
# tiny bootstrap that decodes and executes it.
_CHUNK = 4000


def run_host(item: WorklistItem, payload_path: str, mode: str,
             dry_run: bool, cfg: Config, target: str | None = None):
    from uet.transports import HostResult

    try:
        import winrm  # type: ignore
    except ImportError:
        raise SystemExit("winrm transport requires: pip install 'uet[winrm]'")
    user = os.environ.get("UET_WINRM_USER", "")
    password = os.environ.get("UET_WINRM_PASSWORD", "")
    if not user or not password:
        raise SystemExit("set UET_WINRM_USER and UET_WINRM_PASSWORD env vars")
    with open(payload_path, encoding="utf-8") as f:
        script = f.read()

    # Connect to the address vetted by uet.target.check_target (a private IP
    # where one is known), not to a hostname that may be an ISP PTR name.
    session = winrm.Session(f"https://{target or item.hostname}:5986/wsman",
                            auth=(user, password), transport="ntlm",
                            server_cert_validation="ignore")
    b64 = base64.b64encode(script.encode("utf-8")).decode()
    tag = uuid.uuid4().hex[:8]
    remote_b64 = f"C:\\Windows\\Temp\\uet-{tag}.b64"
    remote_ps1 = f"C:\\Windows\\Temp\\uet-{tag}.ps1"

    try:
        for i in range(0, len(b64), _CHUNK):
            # Parenthesized echo so a chunk ending in a digit can't turn the
            # redirect into a numbered-stream redirect (`echo x1>>f` pitfall).
            op = ">" if i == 0 else ">>"
            r = session.run_cmd(f'(echo {b64[i:i + _CHUNK]}){op}"{remote_b64}"')
            if r.status_code != 0:
                return HostResult(item.hostname, False,
                                  r.std_out.decode(errors="replace"),
                                  "payload transfer failed: "
                                  + r.std_err.decode(errors="replace"),
                                  r.status_code)
        prefix = f"$env:UET_MODE='{mode}'; " + ("$env:UET_DRY_RUN='1'; " if dry_run else "")
        boot = (
            prefix
            + f"$b64 = (Get-Content '{remote_b64}' -Raw) -replace '\\s',''; "
            + f"[IO.File]::WriteAllBytes('{remote_ps1}', [Convert]::FromBase64String($b64)); "
            + f"& powershell -NoProfile -ExecutionPolicy Bypass -File '{remote_ps1}'; "
            + "$rc = $LASTEXITCODE; "
            + f"Remove-Item '{remote_b64}','{remote_ps1}' -Force -ErrorAction SilentlyContinue; "
            + "exit $rc"
        )
        r = session.run_ps(boot)
        return HostResult(item.hostname, r.status_code in (0, 2, 3),
                          r.std_out.decode(errors="replace"),
                          r.std_err.decode(errors="replace"), r.status_code)
    except Exception as e:  # noqa: BLE001 — one bad host must not abort the sweep
        return HostResult(item.hostname, False, "",
                          f"winrm failed: {type(e).__name__}: {e}", 125)
