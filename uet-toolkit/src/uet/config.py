from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class Config:
    v1_base_url: str = "https://api.xdr.trendmicro.com"
    swp_base_url: str = ""
    stale_days: int = 90
    snapshot_max_age_hours: int = 12
    concurrency: int = 10
    workdir: str = "uet-data"
    ssh_user: str = "root"
    ssm_region: str = ""
    # Non-private ranges that are nonetheless ours, for tenants running
    # public-registered space internally. Private ranges are always allowed.
    allowed_cidrs: list[str] = field(default_factory=list)


def load_config(path: str = "uet.toml") -> Config:
    cfg = Config()
    if not os.path.exists(path):
        return cfg
    with open(path, "rb") as f:
        data = tomllib.load(f)
    cfg.v1_base_url = data.get("v1", {}).get("base_url", cfg.v1_base_url)
    cfg.swp_base_url = data.get("swp", {}).get("base_url", cfg.swp_base_url)
    tri = data.get("triage", {})
    cfg.stale_days = tri.get("stale_days", cfg.stale_days)
    cfg.snapshot_max_age_hours = tri.get("snapshot_max_age_hours", cfg.snapshot_max_age_hours)
    run = data.get("run", {})
    cfg.concurrency = run.get("concurrency", cfg.concurrency)
    cfg.ssh_user = run.get("ssh_user", cfg.ssh_user)
    cfg.ssm_region = run.get("ssm_region", cfg.ssm_region)
    cfg.allowed_cidrs = list(run.get("allowed_cidrs", cfg.allowed_cidrs))
    cfg.workdir = data.get("workdir", cfg.workdir)
    return cfg


def get_secret(env_name: str, key_file: str | None = None) -> str:
    val = os.environ.get(env_name, "")
    if not val and key_file:
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
        except OSError as e:
            sys.exit(f"error: could not read --key-file {key_file}: {e.strerror}")
    if not val:
        sys.exit(
            f"error: secret {env_name} not found. Set the {env_name} env var "
            f"or pass --key-file pointing at a file containing it."
        )
    return val
