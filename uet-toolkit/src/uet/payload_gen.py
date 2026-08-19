# src/uet/payload_gen.py
from __future__ import annotations

import base64
import os
import re

_REPO_PAYLOADS = os.path.join(os.path.dirname(__file__), "..", "..", "payloads")

_SENTINELS = {
    "sh": {
        "dsm": ('UET_DSM_URL=""  # __UET_DSM_URL__', 'UET_DSM_URL="{v}"'),
        "deploy": ('UET_DEPLOY_B64=""  # __UET_DEPLOY_B64__', 'UET_DEPLOY_B64="{v}"'),
        "activation": ('UET_ACTIVATION_ARGS=""  # __UET_ACTIVATION_ARGS__',
                       'UET_ACTIVATION_ARGS="{v}"'),
    },
    "ps1": {
        "dsm": ('$UetDsmUrl = ""  # __UET_DSM_URL__', '$UetDsmUrl = "{v}"'),
        "deploy": ('$UetDeployB64 = ""  # __UET_DEPLOY_B64__', '$UetDeployB64 = "{v}"'),
        "activation": ('$UetActivationArgs = ""  # __UET_ACTIVATION_ARGS__',
                       '$UetActivationArgs = "{v}"'),
    },
}


def extract_dsm_url(script_body: str) -> str:
    m = re.search(r"dsm://[^\s'\"]+", script_body)
    return m.group(0) if m else ""


def extract_activation_args(script_body: str) -> str:
    """Pull the quoted activation credentials ("tenantID:..." "token:..."),
    from the deployment script's `dsa_control -a` line, as a space-separated
    string. Bare `-a <url>` without credentials cannot activate against
    multi-tenant SWP (live-verified), so safe-mode reactivation needs these.
    """
    for line in script_body.splitlines():
        m = re.search(r'dsa_control["\']?\s+-a\s+\S+((?:\s+"[^"]+")+)', line)
        if m:
            return " ".join(re.findall(r'"([^"]+)"', m.group(1)))
    return ""


def embed_payload(template_text: str, dsm_url: str, deploy_b64: str, style: str,
                  activation_args: str = "") -> str:
    s = _SENTINELS[style]
    for key, name in (("dsm", "__UET_DSM_URL__"), ("deploy", "__UET_DEPLOY_B64__"),
                      ("activation", "__UET_ACTIVATION_ARGS__")):
        if s[key][0] not in template_text:
            raise ValueError(f"sentinel {name} missing from {style} template")
    out = template_text.replace(s["dsm"][0], s["dsm"][1].format(v=dsm_url))
    out = out.replace(s["deploy"][0], s["deploy"][1].format(v=deploy_b64))
    out = out.replace(s["activation"][0], s["activation"][1].format(v=activation_args))
    return out


def _template_path(name: str) -> str:
    # installed layout: payloads/ sits next to the repo; fall back to CWD
    for base in (_REPO_PAYLOADS, "payloads"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(f"payload template {name} not found")


def generate_payloads(swp, workdir: str) -> list[str]:
    outdir = os.path.join(workdir, "payloads")
    os.makedirs(outdir, exist_ok=True)
    written: list[str] = []
    for platform, tpl_name, style, out_name in (
        ("linux", "check-fix-agent.sh", "sh", "check-fix-agent-linux.sh"),
        ("windows", "check-fix-agent.ps1", "ps1", "check-fix-agent-windows.ps1"),
    ):
        script = swp.generate_deployment_script(platform)
        dsm = extract_dsm_url(script)
        activation = extract_activation_args(script)
        b64 = base64.b64encode(script.encode()).decode()
        with open(_template_path(tpl_name), encoding="utf-8") as f:
            text = f.read()
        out_path = os.path.join(outdir, out_name)
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        # O_CREAT mode is ignored when the file already exists; enforce 0600
        # unconditionally so overwriting a pre-existing file can't leak the token.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(embed_payload(text, dsm, b64, style, activation_args=activation))
        written.append(out_path)
    return written
