from __future__ import annotations
import pytest
from uet.config import Config, load_config, get_secret


def test_load_config_defaults_when_missing(tmp_path):
    cfg = load_config(str(tmp_path / "nope.toml"))
    assert cfg.v1_base_url == "https://api.xdr.trendmicro.com"
    assert cfg.stale_days == 90
    assert cfg.workdir == "uet-data"


def test_load_config_overrides(tmp_path):
    p = tmp_path / "uet.toml"
    p.write_text('[triage]\nstale_days = 30\n[swp]\nbase_url = "https://x"\n')
    cfg = load_config(str(p))
    assert cfg.stale_days == 30
    assert cfg.swp_base_url == "https://x"


def test_load_config_ssm_region(tmp_path):
    p = tmp_path / "uet.toml"
    p.write_text('[run]\nssm_region = "us-east-1"\n')
    cfg = load_config(str(p))
    assert cfg.ssm_region == "us-east-1"


def test_load_config_ssm_region_defaults_empty(tmp_path):
    cfg = load_config(str(tmp_path / "nope.toml"))
    assert cfg.ssm_region == ""


def test_get_secret_env(monkeypatch):
    monkeypatch.setenv("V1_API_KEY", "sek")
    assert get_secret("V1_API_KEY") == "sek"


def test_get_secret_key_file(tmp_path, monkeypatch):
    monkeypatch.delenv("V1_API_KEY", raising=False)
    f = tmp_path / "k"
    f.write_text("filesek\n")
    assert get_secret("V1_API_KEY", key_file=str(f)) == "filesek"


def test_get_secret_missing_exits(monkeypatch):
    monkeypatch.delenv("V1_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        get_secret("V1_API_KEY")


def test_get_secret_nonexistent_key_file_clean_exit(tmp_path, monkeypatch):
    monkeypatch.delenv("V1_API_KEY", raising=False)
    missing = tmp_path / "nope.key"
    with pytest.raises(SystemExit) as exc_info:
        get_secret("V1_API_KEY", key_file=str(missing))
    assert str(missing) in str(exc_info.value)
