from __future__ import annotations

import socket

import pytest

from uet.config import Config
from uet.target import DIRECT_CONNECT_TRANSPORTS, check_target, is_allowed_ip
from uet.transports import resolve_targets
from uet.util import RunLog
from uet.worklist import WorklistItem


def wi(host="h1", ips=None):
    return WorklistItem(hostname=host, swp_id=1, agent_guid="", ips=list(ips or []),
                        os="windows", bucket="NEEDS_REPAIR", recommended_mode="safe")


def never(name):
    raise AssertionError(f"should not have resolved {name}")


class TestIsAllowedIp:
    @pytest.mark.parametrize("ip", ["198.51.100.137", "172.16.0.1", "192.168.1.5",
                                    "127.0.0.1", "169.254.1.1"])
    def test_private_allowed(self, ip):
        assert is_allowed_ip(ip)

    @pytest.mark.parametrize("ip", ["9.9.9.9", "8.8.8.8", "1.1.1.1"])
    def test_public_refused(self, ip):
        assert not is_allowed_ip(ip)

    @pytest.mark.parametrize("ip", ["", "not-an-ip", "0.0.0.0", "224.0.0.1", None])
    def test_junk_and_unusable_refused(self, ip):
        assert not is_allowed_ip(ip)

    def test_public_allowed_when_cidr_configured(self):
        assert is_allowed_ip("9.9.9.9", ["9.9.9.0/24"])
        assert not is_allowed_ip("8.8.8.8", ["9.9.9.0/24"])

    def test_invalid_configured_cidr_fails_fast(self):
        with pytest.raises(SystemExit):
            is_allowed_ip("8.8.8.8", ["not-a-cidr"])


class TestCheckTarget:
    def test_private_worklist_ip_wins_without_dns(self):
        # The real-world case this guards: an ISP hostname, but SWP gave us the
        # internal lastIPUsed. Prefer the IP and never touch DNS.
        item = wi("syn-203-000-113-043.biz.example-isp.com", ["198.51.100.137"])
        target, err = check_target(item, resolve=never)
        assert (target, err) == ("198.51.100.137", None)

    def test_isp_hostname_with_no_private_ip_is_refused(self):
        item = wi("syn-203-000-113-043.biz.example-isp.com", [])
        target, err = check_target(item, resolve=lambda n: "9.9.9.9")
        assert target is None
        assert "9.9.9.9" in err
        assert "public internet" in err

    def test_hostname_resolving_privately_is_allowed(self):
        item = wi("realhost.internal.example.com", [])
        target, err = check_target(item, resolve=lambda n: "10.1.2.3")
        assert (target, err) == ("realhost.internal.example.com", None)

    def test_public_worklist_ip_alone_is_not_enough(self):
        item = wi("syn-203-000-113-043.biz.example-isp.com", ["9.9.9.9"])
        target, err = check_target(item, resolve=lambda n: "9.9.9.9")
        assert target is None and "9.9.9.9" in err

    def test_unresolvable_hostname_with_no_private_ip_is_refused(self):
        def boom(name):
            raise socket.gaierror("nope")

        target, err = check_target(wi("gone.example.com", []), resolve=boom)
        assert target is None and "does not resolve" in err

    def test_empty_hostname_and_no_ip_is_refused(self):
        target, err = check_target(wi("", []), resolve=never)
        assert target is None and "no connect target" in err

    def test_hostname_that_is_already_a_private_ip_literal(self):
        target, err = check_target(wi("10.9.8.7", []), resolve=never)
        assert (target, err) == ("10.9.8.7", None)

    def test_configured_cidr_permits_the_isp_range(self):
        item = wi("syn-203-000-113-043.biz.example-isp.com", [])
        target, err = check_target(item, ["9.9.9.0/24"],
                                   resolve=lambda n: "9.9.9.9")
        assert err is None and target == "syn-203-000-113-043.biz.example-isp.com"

    def test_first_private_ip_is_picked_over_a_public_one(self):
        item = wi("h", ["9.9.9.9", "10.0.0.9"])
        target, err = check_target(item, resolve=never)
        assert (target, err) == ("10.0.0.9", None)


class TestResolveTargets:
    def _run(self, tmp_path, items, transport="winrm", allow=False, cfg=None):
        results_dir = str(tmp_path / "results")
        kept, targets = resolve_targets(items, transport, results_dir,
                                        cfg or Config(), RunLog(str(tmp_path)),
                                        allow_public_target=allow)
        return kept, targets, results_dir

    def test_refused_host_is_dropped_and_gets_an_error_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("socket.gethostbyname", lambda n: "9.9.9.9")
        bad = wi("syn-203-000-113-043.biz.example-isp.com", [])
        kept, targets, results_dir = self._run(tmp_path, [bad])
        assert kept == [] and targets == {}
        err_file = tmp_path / "results" / "syn-203-000-113-043.biz.example-isp.com.error.txt"
        assert "target refused" in err_file.read_text()

    def test_good_host_survives_with_private_target(self, tmp_path):
        good = wi("syn-203-000-113-043.biz.example-isp.com", ["198.51.100.137"])
        kept, targets, _ = self._run(tmp_path, [good])
        assert kept == [good]
        assert targets[good.hostname] == "198.51.100.137"

    def test_override_lets_a_public_host_through_as_hostname(self, tmp_path, monkeypatch):
        monkeypatch.setattr("socket.gethostbyname", lambda n: "9.9.9.9")
        bad = wi("syn-203-000-113-043.biz.example-isp.com", [])
        kept, targets, _ = self._run(tmp_path, [bad], allow=True)
        assert kept == [bad]
        assert targets[bad.hostname] == bad.hostname

    def test_configured_cidr_is_honoured(self, tmp_path, monkeypatch):
        monkeypatch.setattr("socket.gethostbyname", lambda n: "9.9.9.9")
        cfg = Config()
        cfg.allowed_cidrs = ["9.9.9.0/24"]
        bad = wi("syn-203-000-113-043.biz.example-isp.com", [])
        kept, _, _ = self._run(tmp_path, [bad], cfg=cfg)
        assert kept == [bad]

    def test_ssm_is_never_gated(self, tmp_path, monkeypatch):
        monkeypatch.setattr("socket.gethostbyname", lambda n: "9.9.9.9")
        # ssm resolves via the EC2 API, not DNS, so a public-resolving hostname
        # cannot misroute it — it must not be filtered.
        bad = wi("syn-203-000-113-043.biz.example-isp.com", [])
        kept, targets, _ = self._run(tmp_path, [bad], transport="ssm")
        assert kept == [bad] and targets == {}
        assert "ssm" not in DIRECT_CONNECT_TRANSPORTS


class TestTransportsUseTarget:
    def test_ssh_dials_the_target_not_the_hostname(self, tmp_path, monkeypatch):
        from uet.transports import ssh as ssh_mod

        seen = {}

        class Proc:
            returncode = 0
            stdout = '{"schema":"uet-result/1"}'
            stderr = ""

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            return Proc()

        monkeypatch.setattr(ssh_mod.subprocess, "run", fake_run)
        payload = tmp_path / "p.sh"
        payload.write_text("#!/bin/bash\n")
        item = wi("syn-203-000-113-043.biz.example-isp.com", ["198.51.100.137"])
        ssh_mod.run_host(item, str(payload), "safe", False, Config(),
                         target="198.51.100.137")
        assert "root@198.51.100.137" in seen["cmd"]
        assert not any("example-isp" in part for part in seen["cmd"])

    def test_run_hosts_passes_target_through_to_the_transport(self, tmp_path, monkeypatch):
        from uet import transports
        from uet.transports import TRANSPORTS, run_hosts

        seen = {}

        def fake_run_host(item, payload_path, mode, dry_run, cfg, target=None):
            seen["target"] = target
            return transports.HostResult(item.hostname, True,
                                         '{"schema":"uet-result/1"}', "", 0)

        monkeypatch.setitem(TRANSPORTS, "winrm",
                            type("M", (), {"run_host": staticmethod(fake_run_host)}))
        (tmp_path / "payloads").mkdir()
        (tmp_path / "payloads" / "check-fix-agent-windows.ps1").write_text("x")
        item = wi("syn-203-000-113-043.biz.example-isp.com", ["198.51.100.137"])
        run_hosts([item], str(tmp_path), "winrm", "safe", False, Config())
        assert seen["target"] == "198.51.100.137"
