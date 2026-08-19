from __future__ import annotations

import inspect
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from uet.config import Config
from uet.target import DIRECT_CONNECT_TRANSPORTS, check_target
from uet.util import RunLog
from uet.worklist import WorklistItem


@dataclass
class HostResult:
    host: str
    ok: bool
    stdout: str
    stderr: str
    rc: int


from uet.transports import ssh as _ssh  # noqa: E402
from uet.transports import ssm as _ssm  # noqa: E402
from uet.transports import winrm as _winrm  # noqa: E402

TRANSPORTS = {"ssh": _ssh, "winrm": _winrm, "ssm": _ssm}


def _safe_name(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host)


def payload_for(item: WorklistItem, transport_name: str, workdir: str) -> str:
    # transport implies OS: winrm is always Windows (ps1), regardless of the
    # possibly-empty/"unknown" item.os. ssh/ssm route on item.os.
    if transport_name == "winrm" or "windows" in item.os.lower():
        name = "check-fix-agent-windows.ps1"
    else:
        name = "check-fix-agent-linux.sh"
    return os.path.join(workdir, "payloads", name)


def _extract_json_line(stdout: str) -> str | None:
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                json.loads(line)
                return line
            except json.JSONDecodeError:
                continue
    return None


def _dispatch(mod, item: WorklistItem, payload_path: str, mode: str,
              dry_run: bool, cfg: Config, target: str | None):
    # `target` is opt-in per transport: ssm has no use for it, and test doubles
    # predate it. Inspect rather than try/except TypeError, which would swallow
    # a genuine TypeError raised inside the transport.
    kwargs = {}
    if "target" in inspect.signature(mod.run_host).parameters:
        kwargs["target"] = target
    return mod.run_host(item, payload_path, mode, dry_run, cfg, **kwargs)


def resolve_targets(todo: list[WorklistItem], transport_name: str, results_dir: str,
                    cfg: Config, log: RunLog, allow_public_target: bool = False,
                    ) -> tuple[list[WorklistItem], dict[str, str]]:
    """Pick a connect target per host, dropping any we refuse to dial.

    Refused hosts get a `.error.txt` so `uet collect` reports them as
    TRANSPORT_ERROR rather than silently omitting them. Resume is unaffected:
    it keys off `.json`, so a refused host is retried on the next run.
    """
    if transport_name not in DIRECT_CONNECT_TRANSPORTS:
        return todo, {}

    kept: list[WorklistItem] = []
    targets: dict[str, str] = {}
    for item in todo:
        target, err = check_target(item, cfg.allowed_cidrs)
        if err and not allow_public_target:
            os.makedirs(results_dir, exist_ok=True)
            safe = _safe_name(item.hostname)
            with open(os.path.join(results_dir, f"{safe}.error.txt"), "w",
                      encoding="utf-8") as f:
                f.write(f"rc=126\nstdout:\n\nstderr:\ntarget refused: {err}\n")
            log.event("target_refused", host=item.hostname, error=err)
            print(f"REFUSED {item.hostname}: {err}")
            continue
        targets[item.hostname] = target or item.hostname
        kept.append(item)
    return kept, targets


def run_hosts(items: list[WorklistItem], workdir: str, transport_name: str,
              mode: str, dry_run: bool, cfg: Config, canary: int | None = None,
              log: RunLog | None = None,
              allow_public_target: bool = False) -> list[HostResult]:
    log = log or RunLog(workdir)
    results_dir = os.path.join(workdir, "results")

    seen_hosts: set[str] = set()
    todo = []
    for item in items:
        if os.path.exists(os.path.join(results_dir, f"{_safe_name(item.hostname)}.json")):
            log.event("skip_existing_result", host=item.hostname)
            continue
        safe = _safe_name(item.hostname)
        if safe in seen_hosts:
            log.event("skip_duplicate_hostname", host=item.hostname)
            continue
        seen_hosts.add(safe)
        todo.append(item)
    # NOTE: canary is applied AFTER filtering out already-done hosts, so a
    # `--canary N` re-run resumes and only fires against the next N
    # not-yet-completed hosts, rather than re-counting hosts already done.
    if canary is not None:
        todo = todo[:canary]

    # Target safety runs before the payload check so a refused host can't make
    # us demand a payload we never needed.
    todo, targets = resolve_targets(todo, transport_name, results_dir, cfg, log,
                                    allow_public_target=allow_public_target)

    missing_payloads = sorted({payload_for(item, transport_name, workdir) for item in todo
                               if not os.path.exists(payload_for(item, transport_name, workdir))})
    if missing_payloads:
        raise SystemExit(
            f"error: payload {missing_payloads[0]} not found — "
            f"run 'uet triage' first to generate payloads"
        )

    os.makedirs(results_dir, exist_ok=True)
    mod = TRANSPORTS[transport_name]

    def one(item: WorklistItem) -> HostResult:
        res = _dispatch(mod, item, payload_for(item, transport_name, workdir),
                        mode, dry_run, cfg, targets.get(item.hostname))
        safe = _safe_name(item.hostname)
        line = _extract_json_line(res.stdout)
        if line:
            with open(os.path.join(results_dir, f"{safe}.json"), "w", encoding="utf-8") as f:
                f.write(line + "\n")
        else:
            with open(os.path.join(results_dir, f"{safe}.error.txt"), "w", encoding="utf-8") as f:
                f.write(f"rc={res.rc}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}\n")
        log.event("host_done", host=item.hostname, rc=res.rc, ok=res.ok)
        return res

    with ThreadPoolExecutor(max_workers=cfg.concurrency) as ex:
        out = list(ex.map(one, todo))
    print(f"ran {len(out)} hosts; results in {results_dir}")
    return out


def cmd_run(args) -> int:
    from uet.config import load_config
    from uet.worklist import read_worklist

    cfg = load_config(args.config)
    worklist_path = os.path.join(cfg.workdir, "worklist.json")
    try:
        items = read_worklist(worklist_path)
    except FileNotFoundError:
        raise SystemExit(f"error: {worklist_path} not found — run 'uet triage' first")
    if args.bucket:
        items = [i for i in items if i.bucket == args.bucket]
    run_hosts(items, cfg.workdir, args.transport, args.mode, args.dry_run,
              cfg, canary=args.canary,
              allow_public_target=getattr(args, "allow_public_target", False))
    return 0
