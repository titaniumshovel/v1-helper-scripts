from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime, timezone

from uet.util import RunLog


STALE_BUCKET = "STALE"


def require_stale(rows: list[dict], fieldnames: list[str]) -> None:
    """Refuse to delete anything triage didn't put in the STALE bucket.

    `approved=yes` alone is one human keystroke away from deleting a repair
    candidate — a NEEDS_REPAIR host still has an agent that can be fixed, and
    deleting its record throws away the activation history instead. The bucket
    is the toolkit's own verdict, so make it binding by default.
    """
    if not rows:
        return
    if "bucket" not in fieldnames:
        sys.exit("error: CSV has no 'bucket' column, so the STALE check cannot run. "
                 "Derive the approved CSV from worklist.csv (it carries bucket), or "
                 "pass --allow-non-stale to delete without the check.")
    bad = [r for r in rows
           if (r.get("bucket") or "").strip().upper() != STALE_BUCKET]
    if not bad:
        return
    shown = "\n".join(
        f"  swp_id={r.get('swp_id') or '?'} hostname={r.get('hostname') or '?'} "
        f"bucket={(r.get('bucket') or '').strip() or '(empty)'}"
        for r in bad[:10]
    )
    if len(bad) > 10:
        shown += f"\n  ... and {len(bad) - 10} more"
    sys.exit(f"error: {len(bad)} of {len(rows)} approved row(s) are not in the "
             f"{STALE_BUCKET} bucket:\n{shown}\n"
             f"Only {STALE_BUCKET} hosts are delete candidates — the rest still have "
             f"an agent to repair. Fix the CSV, or pass --allow-non-stale if you "
             f"really mean to delete these.")


def load_approved(csv_path: str, allow_non_stale: bool = False) -> list[dict]:
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        if "approved" not in fieldnames:
            sys.exit("error: CSV must contain an 'approved' column — review the STALE "
                     "list and mark approved=yes per row before deleting.")
        rows = [row for row in reader
                if (row.get("approved") or "").strip().lower() == "yes"]
    if not allow_non_stale:
        require_stale(rows, fieldnames)
    return rows


def run_delete(rows: list[dict], swp, workdir: str, execute: bool,
               log: RunLog | None = None) -> dict:
    log = log or RunLog(workdir)
    os.makedirs(workdir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = os.path.join(workdir, f"delete-backup-{ts}.json")

    errors = []
    parsed = []
    for row in rows:
        raw = row["swp_id"]
        try:
            parsed.append((row, int(raw)))
        except ValueError as e:
            errors.append({"swp_id": raw, "stage": "parse", "error": str(e)})

    records = []
    backed_up = []
    for row, cid in parsed:
        try:
            record = swp.get_computer(cid)
        except Exception as e:  # noqa: BLE001 — record and continue
            errors.append({"swp_id": cid, "stage": "backup", "error": str(e)})
            continue
        records.append(record)
        backed_up.append((row, cid, record))
    with open(backup_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    log.event("delete_backup", path=backup_path, count=len(records))

    deleted = 0
    if not execute:
        print(f"DRY RUN: would delete {len(backed_up)} computers "
              f"(backup written to {backup_path}). Re-run with --execute to proceed.")
        for row, cid, _record in backed_up:
            print(f"  would delete swp_id={row['swp_id']} hostname={row['hostname']}")
    else:
        for row, cid, _record in backed_up:
            try:
                swp.delete_computer(cid)
                deleted += 1
                log.event("deleted", swp_id=cid, hostname=row["hostname"])
            except Exception as e:  # noqa: BLE001
                errors.append({"swp_id": cid, "stage": "delete", "error": str(e)})
                log.event("delete_error", swp_id=cid, error=str(e))
        print(f"deleted {deleted}/{len(backed_up)} computers; backup: {backup_path}")
    if errors:
        print(f"{len(errors)} errors — see run log")
    return {"backed_up": len(records), "deleted": deleted, "errors": errors}


def cmd_delete(args) -> int:
    from uet.config import get_secret, load_config
    from uet.swp_client import SwpClient

    cfg = load_config(args.config)
    rows = load_approved(args.approved_csv,
                         allow_non_stale=getattr(args, "allow_non_stale", False))
    if not rows:
        print("nothing approved; no action taken")
        return 0
    swp = SwpClient(cfg.swp_base_url, get_secret("SWP_API_SECRET", args.swp_key_file))
    out = run_delete(rows, swp, cfg.workdir, execute=args.execute)
    return 1 if out["errors"] else 0
