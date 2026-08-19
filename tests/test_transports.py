from __future__ import annotations
import json
import os
import types
import pytest
from uet.config import Config
from uet.transports import run_hosts, TRANSPORTS, payload_for
from uet.transports.ssh import build_ssh_cmd
from uet.worklist import WorklistItem


def wi(host="h1", os_="linux"):
    return WorklistItem(hostname=host, swp_id=1, agent_guid="", os=os_,
                        bucket="NEEDS_REPAIR", recommended_mode="safe")


def _make_payload(tmp_path, name="check-fix-agent-linux.sh"):
    d = tmp_path / "payloads"
    d.mkdir(exist_ok=True)
    (d / name).write_text("#!/bin/bash\n")


def test_payload_for_winrm_always_ps1_even_with_empty_os():
    # transport implies OS: winrm hosts are Windows regardless of item.os
    p = payload_for(wi(os_=""), "winrm", "/wd")
    assert p.endswith("check-fix-agent-windows.ps1")


def test_payload_for_ssh_uses_os():
    assert payload_for(wi(os_="Linux"), "ssh", "/wd").endswith("check-fix-agent-linux.sh")
    assert payload_for(wi(os_="Windows"), "ssh", "/wd").endswith("check-fix-agent-windows.ps1")


def test_run_hosts_winrm_picks_ps1_for_unknown_os(tmp_path, monkeypatch):
    from uet import transports

    seen = {}

    def fake_run_host(item, payload_path, mode, dry_run, cfg):
        seen["payload"] = payload_path
        return transports.HostResult(item.hostname, True,
                                     '{"schema":"uet-result/1","host":"a","outcome":"FIXED"}',
                                     "", 0)

    monkeypatch.setitem(TRANSPORTS, "winrm", type("M", (), {"run_host": staticmethod(fake_run_host)}))
    _make_payload(tmp_path, name="check-fix-agent-windows.ps1")
    run_hosts([wi("a", os_="")], str(tmp_path), "winrm", "safe", False, Config())
    assert seen["payload"].endswith("check-fix-agent-windows.ps1")


def test_build_ssh_cmd():
    cmd = build_ssh_cmd("h1", "admin", "safe", dry_run=True)
    assert cmd[:3] == ["ssh", "-o", "BatchMode=yes"]
    assert "admin@h1" in cmd
    joined = " ".join(cmd)
    assert "--mode safe" in joined and "--dry-run" in joined
    # Non-interactive sudo is mandatory here: the payload is on stdin, so a
    # password prompt would hang to the 1200s timeout rather than erroring.
    assert "sudo -n" in joined


def test_run_hosts_writes_results_and_respects_canary(tmp_path, monkeypatch):
    from uet import transports

    calls = []

    def fake_run_host(item, payload_path, mode, dry_run, cfg):
        calls.append(item.hostname)
        return transports.HostResult(item.hostname, True,
                                     '{"schema":"uet-result/1","host":"%s","outcome":"FIXED"}' % item.hostname,
                                     "", 0)

    monkeypatch.setitem(TRANSPORTS, "fake", type("M", (), {"run_host": staticmethod(fake_run_host)}))
    items = [wi("a"), wi("b"), wi("c")]
    _make_payload(tmp_path)
    out = run_hosts(items, str(tmp_path), "fake", "safe", False, Config(), canary=2)
    assert len(out) == 2 and calls == ["a", "b"]
    assert json.load(open(tmp_path / "results" / "a.json"))["outcome"] == "FIXED"


def test_run_hosts_skips_existing_results(tmp_path, monkeypatch):
    from uet import transports
    os.makedirs(tmp_path / "results", exist_ok=True)
    (tmp_path / "results" / "a.json").write_text('{"outcome":"FIXED"}')
    calls = []

    def fake_run_host(item, payload_path, mode, dry_run, cfg):
        calls.append(item.hostname)
        return transports.HostResult(item.hostname, True, "{}", "", 0)

    monkeypatch.setitem(TRANSPORTS, "fake", type("M", (), {"run_host": staticmethod(fake_run_host)}))
    _make_payload(tmp_path)
    run_hosts([wi("a"), wi("b")], str(tmp_path), "fake", "safe", False, Config())
    assert calls == ["b"]


def test_unparseable_stdout_saved_as_error(tmp_path, monkeypatch):
    from uet import transports

    def fake_run_host(item, payload_path, mode, dry_run, cfg):
        return transports.HostResult(item.hostname, False, "ssh: connection refused", "", 255)

    monkeypatch.setitem(TRANSPORTS, "fake", type("M", (), {"run_host": staticmethod(fake_run_host)}))
    _make_payload(tmp_path)
    run_hosts([wi("a")], str(tmp_path), "fake", "safe", False, Config())
    assert os.path.exists(tmp_path / "results" / "a.error.txt")


def test_run_hosts_missing_payload_raises_clear_error(tmp_path, monkeypatch):
    from uet import transports

    def fake_run_host(item, payload_path, mode, dry_run, cfg):
        raise AssertionError("transport should not be dispatched when payload is missing")

    monkeypatch.setitem(TRANSPORTS, "fake", type("M", (), {"run_host": staticmethod(fake_run_host)}))
    with pytest.raises(SystemExit) as exc_info:
        run_hosts([wi("a")], str(tmp_path), "fake", "safe", False, Config())
    assert "uet triage" in str(exc_info.value)
    assert not os.path.exists(tmp_path / "results")


def test_run_hosts_dedupes_duplicate_hostnames(tmp_path, monkeypatch):
    from uet import transports

    calls = []

    def fake_run_host(item, payload_path, mode, dry_run, cfg):
        calls.append(item.hostname)
        return transports.HostResult(item.hostname, True,
                                     '{"schema":"uet-result/1","host":"%s","outcome":"FIXED"}' % item.hostname,
                                     "", 0)

    monkeypatch.setitem(TRANSPORTS, "fake", type("M", (), {"run_host": staticmethod(fake_run_host)}))
    _make_payload(tmp_path)
    out = run_hosts([wi("a"), wi("a")], str(tmp_path), "fake", "safe", False, Config())
    assert calls.count("a") == 1
    assert len(out) == 1


# ---- winrm transport internals (live-verified failure 2026-07-08: pywinrm's
# run_ps(-encodedcommand) hits the ~8K Windows command-line limit for any real
# payload -> WSManFaultError "The filename or extension is too long") ----

class _FakeWinrmResult:
    def __init__(self, status_code=0, std_out=b"", std_err=b""):
        self.status_code = status_code
        self.std_out = std_out
        self.std_err = std_err


class _FakeWinrmSession:
    instances: list = []

    def __init__(self, endpoint, auth, transport, server_cert_validation):
        self.endpoint = endpoint
        self.cmd_calls: list[str] = []
        self.ps_calls: list[str] = []
        _FakeWinrmSession.instances.append(self)

    def run_cmd(self, cmd):
        self.cmd_calls.append(cmd)
        return _FakeWinrmResult(0)

    def run_ps(self, script):
        self.ps_calls.append(script)
        return _FakeWinrmResult(
            0, b'{"schema":"uet-result/1","host":"w1","outcome":"FIXED"}', b"")


@pytest.fixture
def fake_winrm(monkeypatch):
    import sys, types
    _FakeWinrmSession.instances = []
    mod = types.SimpleNamespace(Session=_FakeWinrmSession)
    monkeypatch.setitem(sys.modules, "winrm", mod)
    monkeypatch.setenv("UET_WINRM_USER", "admin")
    monkeypatch.setenv("UET_WINRM_PASSWORD", "pw")
    return mod


def _big_payload(tmp_path, size=30000):
    p = tmp_path / "check-fix-agent-windows.ps1"
    p.write_text("# payload\n" + ("$x = 1\n" * (size // 8)))
    return str(p)


def test_winrm_never_exceeds_command_length_limit(tmp_path, fake_winrm):
    from uet.transports import winrm as winrm_mod
    payload = _big_payload(tmp_path)
    res = winrm_mod.run_host(wi("w1", os_="windows"), payload, "safe", False, Config())
    s = _FakeWinrmSession.instances[-1]
    too_long = [c for c in s.cmd_calls + s.ps_calls if len(c) > 8000]
    assert too_long == [], f"{len(too_long)} remote commands exceed 8K"
    assert res.ok


def test_winrm_chunked_transfer_reassembles_payload(tmp_path, fake_winrm):
    import base64, re
    from uet.transports import winrm as winrm_mod
    payload = _big_payload(tmp_path)
    winrm_mod.run_host(wi("w1", os_="windows"), payload, "safe", False, Config())
    s = _FakeWinrmSession.instances[-1]
    # every transfer command carries a b64 fragment; reassembled they must
    # decode to exactly the payload text
    frags = []
    for c in s.cmd_calls:
        m = re.search(r"echo ([A-Za-z0-9+/=]+)\)?>", c)
        if m:
            frags.append(m.group(1))
    assert frags, f"no b64 transfer commands seen: {s.cmd_calls[:2]}"
    assert base64.b64decode("".join(frags)).decode() == open(payload).read()


def test_winrm_executes_with_mode_env_and_parses_result(tmp_path, fake_winrm):
    from uet.transports import winrm as winrm_mod
    payload = _big_payload(tmp_path)
    res = winrm_mod.run_host(wi("w1", os_="windows"), payload, "safe", True, Config())
    s = _FakeWinrmSession.instances[-1]
    assert s.ps_calls, "no bootstrap run_ps call"
    boot = s.ps_calls[-1]
    assert "UET_MODE" in boot and "'safe'" in boot
    assert "UET_DRY_RUN" in boot
    assert '"outcome":"FIXED"' in res.stdout


def test_winrm_exception_becomes_failed_result_not_crash(tmp_path, fake_winrm):
    # One bad host must not abort the whole run_hosts sweep: exceptions from
    # pywinrm must come back as a failed HostResult (mirroring the ssh
    # transport's OSError handling), not propagate.
    from uet.transports import winrm as winrm_mod

    def boom(self, cmd):
        raise RuntimeError("WSManFaultError: filename or extension is too long")
    _FakeWinrmSession.run_cmd = boom
    try:
        payload = _big_payload(tmp_path)
        res = winrm_mod.run_host(wi("w1", os_="windows"), payload, "safe", False, Config())
        assert res.ok is False
        assert "WSManFaultError" in res.stderr or "too long" in res.stderr
    finally:
        _FakeWinrmSession.run_cmd = lambda self, cmd: (
            self.cmd_calls.append(cmd) or _FakeWinrmResult(0))


# ---- ssm transport internals (hardening: explicit hostname -> instance-id
# resolution, since Targets=tag:Name silently matches zero instances when the
# EC2 Name tag isn't the hostname SWP records) ----

class _FakeEc2:
    def __init__(self):
        self.tiers: dict[str, list[str]] = {}
        self.calls: list[list[dict]] = []

    def describe_instances(self, Filters):
        self.calls.append(Filters)
        tier = next(f["Name"] for f in Filters if f["Name"] != "instance-state-name")
        ids = self.tiers.get(tier, [])
        return {"Reservations": [{"Instances": [{"InstanceId": i} for i in ids]}]}


class _InvocationDoesNotExist(Exception):
    pass


class _FakeSsm:
    def __init__(self):
        self.send_command_calls: list[dict] = []
        self.invocation_calls: list[dict] = []
        self.send_command_error: Exception | None = None
        self.invocation_responses: list = []
        self.exceptions = types.SimpleNamespace(InvocationDoesNotExist=_InvocationDoesNotExist)

    def send_command(self, **kwargs):
        self.send_command_calls.append(kwargs)
        if self.send_command_error:
            raise self.send_command_error
        return {"Command": {"CommandId": "cmd-1"}}

    def get_command_invocation(self, **kwargs):
        self.invocation_calls.append(kwargs)
        item = self.invocation_responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _FakeClientError(Exception):
    def __init__(self, error_response, operation_name):
        self.response = error_response
        super().__init__(str(error_response))


@pytest.fixture
def fake_boto3(monkeypatch):
    import sys, types
    ec2 = _FakeEc2()
    ssm = _FakeSsm()
    calls: list[tuple[str, str | None]] = []

    def client(name, region_name=None):
        calls.append((name, region_name))
        return {"ec2": ec2, "ssm": ssm}[name]

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=client))
    exc_mod = types.SimpleNamespace(ClientError=_FakeClientError)
    monkeypatch.setitem(sys.modules, "botocore", types.SimpleNamespace(exceptions=exc_mod))
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exc_mod)
    return types.SimpleNamespace(ec2=ec2, ssm=ssm, calls=calls)


def _ssm_payload(tmp_path, name="check-fix-agent-linux.sh"):
    p = tmp_path / name
    p.write_text("#!/bin/bash\necho hi\n")
    return str(p)


def _success_invocation(stdout="ok", rc=0):
    return {"Status": "Success", "StandardOutputContent": stdout,
            "StandardErrorContent": "", "ResponseCode": rc}


def test_ssm_resolves_via_name_tag(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["tag:Name"] = ["i-abc"]
    fake_boto3.ssm.invocation_responses = [_success_invocation()]
    res = ssm_mod.run_host(wi("h1"), _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok
    assert fake_boto3.ssm.send_command_calls[0]["InstanceIds"] == ["i-abc"]
    assert fake_boto3.ec2.calls[0][0]["Name"] == "tag:Name"


def test_ssm_falls_back_to_private_dns_name(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["private-dns-name"] = ["i-def"]
    fake_boto3.ssm.invocation_responses = [_success_invocation()]
    res = ssm_mod.run_host(wi("h2"), _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok
    assert fake_boto3.ssm.send_command_calls[0]["InstanceIds"] == ["i-def"]
    tried = [next(f["Name"] for f in c if f["Name"] != "instance-state-name")
              for c in fake_boto3.ec2.calls]
    assert tried == ["tag:Name", "private-dns-name"]


def test_ssm_falls_back_to_private_ip(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["private-ip-address"] = ["i-ghi"]
    fake_boto3.ssm.invocation_responses = [_success_invocation()]
    item = wi("h3")
    item.ips = ["10.0.0.5"]
    res = ssm_mod.run_host(item, _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok
    assert fake_boto3.ssm.send_command_calls[0]["InstanceIds"] == ["i-ghi"]
    ip_filter = next(f for f in fake_boto3.ec2.calls[-1] if f["Name"] == "private-ip-address")
    assert ip_filter["Values"] == ["10.0.0.5"]


def test_ssm_zero_matches_fails_fast(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    item = wi("ghost")
    item.ips = ["10.0.0.9"]
    res = ssm_mod.run_host(item, _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok is False
    assert res.rc == 1
    assert "ghost" in res.stderr
    assert fake_boto3.ssm.send_command_calls == []


def test_ssm_ambiguous_match_fails(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["tag:Name"] = ["i-1", "i-2"]
    res = ssm_mod.run_host(wi("dup"), _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok is False
    assert "i-1" in res.stderr and "i-2" in res.stderr
    assert fake_boto3.ssm.send_command_calls == []


def test_ssm_happy_path_carries_stdout_and_rc(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["tag:Name"] = ["i-abc"]
    fake_boto3.ssm.invocation_responses = [
        _success_invocation(stdout='{"schema":"uet-result/1","outcome":"FIXED"}', rc=0)]
    res = ssm_mod.run_host(wi("h1"), _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok is True
    assert "FIXED" in res.stdout
    assert res.rc == 0


def test_ssm_invalid_instance_id_gives_clear_message(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["tag:Name"] = ["i-abc"]
    fake_boto3.ssm.send_command_error = _FakeClientError(
        {"Error": {"Code": "InvalidInstanceId", "Message": "boom"}}, "SendCommand")
    res = ssm_mod.run_host(wi("h1"), _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok is False
    assert "not registered with SSM" in res.stderr
    assert "i-abc" in res.stderr


def test_ssm_region_passed_to_both_clients(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["tag:Name"] = ["i-abc"]
    fake_boto3.ssm.invocation_responses = [_success_invocation()]
    cfg = Config()
    cfg.ssm_region = "us-east-1"
    ssm_mod.run_host(wi("h1"), _ssm_payload(tmp_path), "safe", False, cfg)
    assert ("ec2", "us-east-1") in fake_boto3.calls
    assert ("ssm", "us-east-1") in fake_boto3.calls


def test_ssm_region_empty_string_means_none(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["tag:Name"] = ["i-abc"]
    fake_boto3.ssm.invocation_responses = [_success_invocation()]
    ssm_mod.run_host(wi("h1"), _ssm_payload(tmp_path), "safe", False, Config())
    assert ("ec2", None) in fake_boto3.calls
    assert ("ssm", None) in fake_boto3.calls


def test_ssm_poll_tolerates_invocation_not_yet_existing(tmp_path, fake_boto3, monkeypatch):
    from uet.transports import ssm as ssm_mod
    monkeypatch.setattr(ssm_mod.time, "sleep", lambda s: None)
    fake_boto3.ec2.tiers["tag:Name"] = ["i-abc"]
    fake_boto3.ssm.invocation_responses = [
        fake_boto3.ssm.exceptions.InvocationDoesNotExist("not yet"),
        _success_invocation(),
    ]
    res = ssm_mod.run_host(wi("h1"), _ssm_payload(tmp_path), "safe", False, Config())
    assert res.ok is True
