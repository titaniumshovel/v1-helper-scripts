from __future__ import annotations

from uet import triage as tri
from uet.cli import main
from uet.config import Config


def test_swp_key_file_arg_is_accepted_and_global(monkeypatch):
    # global flag goes before the subcommand and is parsed onto args
    captured = {}

    def fake_cmd_triage(args):
        captured["key_file"] = args.key_file
        captured["swp_key_file"] = args.swp_key_file
        return 0

    monkeypatch.setattr("uet.triage.cmd_triage", fake_cmd_triage)
    rc = main(["--key-file", "v1.key", "--swp-key-file", "swp.key", "triage"])
    assert rc == 0
    assert captured == {"key_file": "v1.key", "swp_key_file": "swp.key"}


def test_triage_dns_flags_parsed_and_defaulted(monkeypatch):
    captured = {}

    def fake_cmd_triage(args):
        captured["dns_timeout"] = args.dns_timeout
        captured["dns_workers"] = args.dns_workers
        captured["no_dns"] = args.no_dns
        return 0

    monkeypatch.setattr("uet.triage.cmd_triage", fake_cmd_triage)
    # defaults
    assert main(["triage"]) == 0
    assert captured == {"dns_timeout": 5.0, "dns_workers": 32, "no_dns": False}
    # overrides
    assert main(["triage", "--dns-timeout", "0.5", "--dns-workers", "8", "--no-dns"]) == 0
    assert captured == {"dns_timeout": 0.5, "dns_workers": 8, "no_dns": True}


def test_cmd_triage_routes_two_distinct_secrets(monkeypatch):
    # the V1 key and SWP key must come from their own respective files, else
    # SWP would be handed the V1 key and 401.
    calls = []

    def fake_get_secret(env_name, key_file=None):
        calls.append((env_name, key_file))
        return f"secret-for-{env_name}"

    monkeypatch.setattr(tri, "get_secret", fake_get_secret)
    monkeypatch.setattr(tri, "load_config", lambda path: Config(swp_base_url="https://swp"))
    monkeypatch.setattr("uet.v1_client.V1Client", lambda base, key: ("v1", base, key))
    monkeypatch.setattr("uet.swp_client.SwpClient", lambda base, key: ("swp", base, key))
    monkeypatch.setattr(tri, "run_triage", lambda *a, **k: [])

    class Args:
        config = "uet.toml"
        key_file = "v1.key"
        swp_key_file = "swp.key"
        axonius_csv = None

    assert tri.cmd_triage(Args()) == 0
    assert ("V1_API_KEY", "v1.key") in calls
    assert ("SWP_API_SECRET", "swp.key") in calls
