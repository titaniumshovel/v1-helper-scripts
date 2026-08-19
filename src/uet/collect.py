from __future__ import annotations

import csv
import json
import os
import re
import time

from uet.worklist import WorklistItem, read_worklist

VERIFIED_OUTCOMES = {"FIXED", "INSTALLED", "NO_ACTION_NEEDED"}


def _safe_name(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host)


def merge_results(items: list[WorklistItem], results_dir: str) -> list[dict]:
    rows = []
    for it in items:
        safe = _safe_name(it.hostname)
        row = {"hostname": it.hostname, "swp_id": it.swp_id, "bucket": it.bucket,
               "evidence": ";".join(it.evidence), "outcome": "NOT_RUN",
               "actions": [], "blockers": []}
        jpath = os.path.join(results_dir, f"{safe}.json")
        epath = os.path.join(results_dir, f"{safe}.error.txt")
        if os.path.exists(jpath):
            try:
                with open(jpath, encoding="utf-8") as f:
                    res = json.load(f)
            except (json.JSONDecodeError, OSError):
                row["outcome"] = "CORRUPT_RESULT"
            else:
                row["outcome"] = res.get("outcome", "ERROR")
                row["actions"] = res.get("actions", [])
                row["blockers"] = res.get("blockers", [])
        elif os.path.exists(epath):
            row["outcome"] = "TRANSPORT_ERROR"
        rows.append(row)
    return rows


def verify_console(rows: list[dict], swp) -> list[dict]:
    status_by_id = {c["ID"]: (c.get("computerStatus") or {}).get("agentStatus", "unknown")
                    for c in swp.list_computers()}
    for row in rows:
        row["console_status"] = status_by_id.get(row["swp_id"], "gone")
        row["verified"] = (row["outcome"] in VERIFIED_OUTCOMES
                           and row["console_status"] == "active")
    return rows


def settle_and_verify(rows: list[dict], swp, attempts: int, delay: int,
                       sleep=time.sleep) -> list[dict]:
    """Poll the console up to `attempts` times, waiting `delay` seconds between
    attempts, until previously-verified-outcome rows show as active (settled).
    Returns as soon as nothing is pending, or after the final attempt."""
    for attempt in range(1, attempts + 1):
        rows = verify_console(rows, swp)
        pending = [r for r in rows if r["outcome"] in VERIFIED_OUTCOMES
                   and r["console_status"] != "active"]
        if not pending or attempt == attempts:
            break
        print(f"waiting {delay}s for {len(pending)} hosts to settle in console...")
        sleep(delay)
    return rows


def write_final_report(rows: list[dict], workdir: str) -> str:
    path = os.path.join(workdir, "final-report.csv")
    cols = ["hostname", "bucket", "outcome", "console_status", "verified",
            "actions", "blockers", "evidence"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            out = dict(row)
            out["actions"] = ";".join(row["actions"])
            out["blockers"] = ";".join(row["blockers"])
            w.writerow(out)
    counts: dict[str, int] = {}
    blockers: dict[str, int] = {}
    for row in rows:
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
        for b in row["blockers"]:
            blockers[b] = blockers.get(b, 0) + 1
    print(f"final report: {path}")
    for k in sorted(counts):
        print(f"  {k:16s} {counts[k]}")
    if blockers:
        print("top blockers:")
        for b, n in sorted(blockers.items(), key=lambda kv: -kv[1])[:5]:
            print(f"  {b}: {n}")
    return path


def cmd_collect(args) -> int:
    from uet.config import get_secret, load_config
    from uet.swp_client import SwpClient

    cfg = load_config(args.config)
    worklist_path = os.path.join(cfg.workdir, "worklist.json")
    try:
        items = read_worklist(worklist_path)
    except FileNotFoundError:
        raise SystemExit(f"error: {worklist_path} not found — run 'uet triage' first")
    rows = merge_results(items, os.path.join(cfg.workdir, "results"))
    swp = SwpClient(cfg.swp_base_url, get_secret("SWP_API_SECRET", args.swp_key_file))
    rows = settle_and_verify(rows, swp, args.settle_attempts, args.settle_delay)
    write_final_report(rows, cfg.workdir)
    return 0
