from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict, dataclass, field

from uet.util import utc_now_iso

SCHEMA = "uet-worklist/1"
FIELDS = ["hostname", "swp_id", "agent_guid", "ips", "os", "bucket",
          "evidence", "recommended_mode", "match_tier"]


@dataclass
class WorklistItem:
    hostname: str
    swp_id: int
    agent_guid: str
    ips: list[str] = field(default_factory=list)
    os: str = ""
    bucket: str = "INVESTIGATE"
    evidence: list[str] = field(default_factory=list)
    recommended_mode: str = "none"
    match_tier: str = "none"


def write_worklist(items: list[WorklistItem], outdir: str) -> tuple[str, str]:
    os.makedirs(outdir, exist_ok=True)
    jpath = os.path.join(outdir, "worklist.json")
    cpath = os.path.join(outdir, "worklist.csv")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump({"schema": SCHEMA, "generated": utc_now_iso(),
                   "items": [asdict(i) for i in items]}, f, indent=2)
    with open(cpath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for i in items:
            row = asdict(i)
            row["ips"] = ";".join(row["ips"])
            row["evidence"] = ";".join(row["evidence"])
            w.writerow(row)
    return jpath, cpath


def read_worklist(path: str) -> list[WorklistItem]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if data.get("schema") != SCHEMA:
        raise ValueError(f"unexpected worklist schema: {data.get('schema')}")
    return [WorklistItem(**it) for it in data["items"]]
