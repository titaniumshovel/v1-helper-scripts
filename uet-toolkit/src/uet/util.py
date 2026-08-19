from __future__ import annotations

import glob
import json
import os
import re
import time
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")


def save_snapshot(workdir: str, name: str, data: object) -> str:
    d = os.path.join(workdir, "snapshots")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{name}-{_ts_slug()}.json")
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp_path, path)
    return path


def load_latest_snapshot(workdir: str, name: str, max_age_hours: int) -> object | None:
    pattern = os.path.join(workdir, "snapshots", f"{name}-*.json")
    name_re = re.compile(rf"^{re.escape(name)}-\d{{8}}-\d{{6}}(-\d{{6}})?\.json$")
    candidates = sorted(
        p for p in glob.glob(pattern) if name_re.match(os.path.basename(p))
    )
    if not candidates:
        return None
    latest = candidates[-1]
    age = time.time() - os.path.getmtime(latest)
    if age > max_age_hours * 3600:
        return None
    with open(latest, "r", encoding="utf-8") as f:
        return json.load(f)


class RunLog:
    def __init__(self, workdir: str):
        d = os.path.join(workdir, "logs")
        os.makedirs(d, exist_ok=True)
        self.path = os.path.join(d, f"run-{_ts_slug()}.jsonl")

    def event(self, kind: str, **fields) -> None:
        rec = {"ts": utc_now_iso(), "kind": kind}
        rec.update(fields)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
