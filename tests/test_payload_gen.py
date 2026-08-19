# tests/test_payload_gen.py
from __future__ import annotations
import base64
import os
import stat

import pytest

from uet.payload_gen import (extract_activation_args, extract_dsm_url,
                             embed_payload, generate_payloads)

SCRIPT = ("#!/bin/bash\nACTIVATIONURL='dsm://agents.mgr.example:443/'\ncurl ...\n"
          '/opt/ds_agent/dsa_control -a dsm://agents.mgr.example:443/ '
          '"tenantID:T-1" "token:K-1"\n')

SH_TPL = ('UET_DSM_URL=""  # __UET_DSM_URL__\n'
          'UET_DEPLOY_B64=""  # __UET_DEPLOY_B64__\n'
          'UET_ACTIVATION_ARGS=""  # __UET_ACTIVATION_ARGS__\n')
PS1_TPL = ('$UetDsmUrl = ""  # __UET_DSM_URL__\n'
           '$UetDeployB64 = ""  # __UET_DEPLOY_B64__\n'
           '$UetActivationArgs = ""  # __UET_ACTIVATION_ARGS__\n')


def test_extract_dsm_url():
    assert extract_dsm_url(SCRIPT) == "dsm://agents.mgr.example:443/"
    assert extract_dsm_url("no url here") == ""


def test_extract_activation_args_linux_style():
    assert extract_activation_args(SCRIPT) == "tenantID:T-1 token:K-1"


def test_extract_activation_args_windows_style():
    # Windows deployment scripts invoke via a quoted path and a variable URL:
    #   & "...\dsa_control" -a $ACTIVATIONURL "tenantID:X" "token:Y"
    script = ('& $Env:ProgramFiles"\\Trend Micro\\Deep Security Agent\\dsa_control" '
              '-a $ACTIVATIONURL "tenantID:T-2" "token:K-2"\n')
    assert extract_activation_args(script) == "tenantID:T-2 token:K-2"


def test_extract_activation_args_absent():
    assert extract_activation_args("no activation line") == ""
    assert extract_activation_args("dsa_control -a dsm://h:443/") == ""


def test_embed_sh():
    out = embed_payload(SH_TPL, "dsm://h:443/", "QUJD", style="sh",
                        activation_args="tenantID:T-1 token:K-1")
    assert 'UET_DSM_URL="dsm://h:443/"' in out
    assert 'UET_DEPLOY_B64="QUJD"' in out
    assert 'UET_ACTIVATION_ARGS="tenantID:T-1 token:K-1"' in out
    assert "__UET_DSM_URL__" not in out
    assert "__UET_ACTIVATION_ARGS__" not in out


def test_embed_ps1():
    out = embed_payload(PS1_TPL, "dsm://h:443/", "QUJD", style="ps1",
                        activation_args="tenantID:T-1 token:K-1")
    assert '$UetDsmUrl = "dsm://h:443/"' in out
    assert '$UetDeployB64 = "QUJD"' in out
    assert '$UetActivationArgs = "tenantID:T-1 token:K-1"' in out


def test_embed_payload_raises_on_missing_dsm_sentinel():
    tpl = SH_TPL.replace('UET_DSM_URL=""  # __UET_DSM_URL__\n', "")
    with pytest.raises(ValueError, match="__UET_DSM_URL__"):
        embed_payload(tpl, "dsm://h:443/", "QUJD", style="sh")


def test_embed_payload_raises_on_missing_deploy_sentinel():
    tpl = SH_TPL.replace('UET_DEPLOY_B64=""  # __UET_DEPLOY_B64__\n', "")
    with pytest.raises(ValueError, match="__UET_DEPLOY_B64__"):
        embed_payload(tpl, "dsm://h:443/", "QUJD", style="sh")


def test_embed_payload_raises_on_missing_activation_sentinel():
    tpl = SH_TPL.replace('UET_ACTIVATION_ARGS=""  # __UET_ACTIVATION_ARGS__\n', "")
    with pytest.raises(ValueError, match="__UET_ACTIVATION_ARGS__"):
        embed_payload(tpl, "dsm://h:443/", "QUJD", style="sh")


WINDOWS_SCRIPT = ("# ps deploy\nACTIVATIONURL='dsm://agents.mgr.example:443/'\n"
                  '& "...\\dsa_control" -a $ACTIVATIONURL "tenantID:T-1" "token:K-1"')


class StubSwp:
    def generate_deployment_script(self, platform):
        return SCRIPT if platform == "linux" else WINDOWS_SCRIPT


def test_generate_payloads_fixes_perms_on_preexisting_file(tmp_path):
    # overwriting a pre-existing file must still result in 0600 (O_CREAT mode
    # is ignored for existing files, so an explicit fchmod is required)
    outdir = tmp_path / "payloads"
    outdir.mkdir()
    pre = outdir / "check-fix-agent-linux.sh"
    pre.write_text("stale contents")
    os.chmod(pre, 0o644)
    generate_payloads(StubSwp(), str(tmp_path))
    assert stat.S_IMODE(os.stat(pre).st_mode) == 0o600


def test_generate_payloads(tmp_path):
    paths = generate_payloads(StubSwp(), str(tmp_path))
    assert len(paths) == 2
    sh = [p for p in paths if p.endswith(".sh")][0]
    text = open(sh, encoding="utf-8").read()
    assert 'UET_DSM_URL="dsm://agents.mgr.example:443/"' in text
    b64 = base64.b64encode(SCRIPT.encode()).decode()
    assert b64 in text
    mode = stat.S_IMODE(os.stat(sh).st_mode)
    assert mode == 0o600  # embedded activation token is a secret

    ps1 = [p for p in paths if p.endswith(".ps1")][0]
    ps1_text = open(ps1, encoding="utf-8").read()
    assert '$UetDsmUrl = "dsm://agents.mgr.example:443/"' in ps1_text
    ps1_b64 = base64.b64encode(WINDOWS_SCRIPT.encode()).decode()
    assert ps1_b64 in ps1_text
    ps1_mode = stat.S_IMODE(os.stat(ps1).st_mode)
    assert ps1_mode == 0o600


def test_generate_payloads_embeds_activation_args(tmp_path):
    paths = generate_payloads(StubSwp(), str(tmp_path))
    sh_text = open([p for p in paths if p.endswith(".sh")][0], encoding="utf-8").read()
    assert 'UET_ACTIVATION_ARGS="tenantID:T-1 token:K-1"' in sh_text
    ps1_text = open([p for p in paths if p.endswith(".ps1")][0], encoding="utf-8").read()
    assert '$UetActivationArgs = "tenantID:T-1 token:K-1"' in ps1_text
