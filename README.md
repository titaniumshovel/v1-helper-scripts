# uet — Unmanaged Endpoints Toolkit

`uet` is a CLI toolkit for triaging and remediating unmanaged endpoints in
Trend Vision One / Server & Workload Protection (SWP). Point it at a tenant
where SWP shows a pile of computers as **Unmanaged**, and it classifies every
one of them into an action bucket using SWP + Vision One (V1) inventory data,
drives self-contained bash/PowerShell payloads on the servers themselves to
diagnose and fix agents (since SWP's API cannot activate an agent — only the
agent can activate itself), and produces an audit trail of what was fixed,
installed, or safe to delete from the console.

| Bucket | Meaning | Recommended action |
|---|---|---|
| `STALE` | Delete candidate — no agent fingerprint or long-offline, **and** a second independent signal (Axonius/liveness says gone) confirms the host itself is gone | Review, then `uet delete` |
| `NEEDS_INSTALL` | Host appears live but has no agent at all | `uet run --mode install` |
| `NEEDS_REPAIR` | Agent exists but is deactivated / offline / errored | `uet run --mode safe` (escalate to `reinstall`/`install` if that's not enough) |
| `INVESTIGATE` | Conflicting or insufficient evidence (e.g. only one of the two STALE signals) | Human review |

## Install

Requires Python >= 3.9.

```bash
pip install .

# optional transports:
pip install '.[ssm]'     # AWS Systems Manager Run Command (needs boto3)
pip install '.[winrm]'   # WinRM for Windows hosts (needs pywinrm)
```

This installs the `uet` console script (`uet.cli:main`).

## Configure

All configuration lives in `uet.toml` in the working directory (override the
path with `--config`). A fully-commented example ships as
[`uet.toml.example`](uet.toml.example) — copy it to `uet.toml` and fill in
`[swp] base_url`. Every key below is optional — these are the defaults `uet`
falls back to if the file or key is missing:

```toml
# top-level
workdir = "uet-data"          # all snapshots, worklist, results, reports go here

[v1]
base_url = "https://api.xdr.trendmicro.com"

[swp]
base_url = ""                  # REQUIRED

[triage]
stale_days = 90                 # offline-age threshold for the STALE bucket
snapshot_max_age_hours = 12     # how fresh a cached API snapshot must be to reuse it

[run]
concurrency = 10                 # parallel hosts for `uet run`
ssh_user = "root"                # remote user for the ssh transport
allowed_cidrs = []               # extra non-private ranges treated as yours
                                 # (private ranges are always allowed)
```

`allowed_cidrs` only matters for the connect-target safety check described
under Caveats — leave it empty unless you genuinely run public-registered
space internally.

`uet triage` and `uet delete` refuse to run without `[swp] base_url` set.

### Secrets

Never put API keys in `uet.toml`, the repo, or logs. `uet` reads two *distinct*
secrets, each via its own environment variable or its own `--key-file` /
`--swp-key-file` flag. Both flags are global — they go *before* the
subcommand, e.g. `uet --key-file .secrets/v1.key --swp-key-file .secrets/swp.key triage`:

| Secret | Env var | Key-file flag | Used by |
|---|---|---|---|
| Vision One API key | `V1_API_KEY` | `--key-file` | `uet triage` (V1 endpoint inventory) |
| SWP API key | `SWP_API_SECRET` | `--swp-key-file` | `uet triage`, `uet collect`, `uet delete` |

The two secrets take **separate** flags on purpose: the V1 and SWP keys are
different credentials, so a single `--key-file` cannot serve both (SWP would
be handed the V1 key and reject it with a `401`).

**The Vision One API key does *not* work for the SWP API.** SWP requires its
own, separately issued API key: SWP console → **Administration → API Keys** →
create a key with the role you need (read-only for triage/collect; a
delete-capable role only for the key used with `uet delete`). Requests are
authenticated via the headers `api-secret-key: <key>` and `api-version: v1`
(both required — omitting `api-version` gets a `400`).

WinRM transport credentials are separate: `UET_WINRM_USER` / `UET_WINRM_PASSWORD`
env vars (see Caveats below).

> **Generated payloads are secrets too.** `uet triage` calls the SWP
> Deployment Scripts API and bakes the resulting activation token into
> `uet-data/payloads/check-fix-agent-linux.sh` and
> `check-fix-agent-windows.ps1` (written `0600`). Anyone holding one of these
> files can activate an agent against your manager. Treat them like API keys:
> never commit them, never post them, and don't widen their permissions.

## Recommended rollout order

Start read-only, prove a small canary, then widen. `uet run` and `uet collect`
both resume: re-running skips hosts that already have a result file, so it's
safe to re-issue these commands.

```bash
uet triage                                  # read-only, writes worklist
# review uet-data/worklist.csv
uet run --transport ssh --mode safe --dry-run --canary 10
uet collect                                 # confirm the 10 look sane
uet run --transport ssh --mode safe --canary 10
uet collect
# widen: drop --canary; escalate --mode per bucket
uet run --transport ssh --mode install --bucket NEEDS_INSTALL
uet collect
# stale cleanup: add 'approved' column to STALE rows of worklist.csv
uet delete --approved-csv approved-stale.csv            # dry-run
uet delete --approved-csv approved-stale.csv --execute
```

Note on `uet collect`: agent activation is not instant — it can take minutes
for the SWP console to reflect a freshly reactivated/installed agent as
`active`. `uet collect` re-polls SWP up to `--settle-attempts` times (default
`3`), waiting `--settle-delay` seconds between attempts (default `60`),
before writing `uet-data/final-report.csv`. Increase these if hosts still show
as unverified right after a wave.

## Bring your own transport

`uet run` (ssh/winrm/ssm) is optional. If you'd rather use Ansible, SCCM,
Tanium, or anything else to reach the servers, that's fully supported:

1. Run `uet triage` once to generate the payloads
   (`uet-data/payloads/check-fix-agent-linux.sh` and
   `check-fix-agent-windows.ps1`).
2. Execute the appropriate payload on each host with whatever tooling you
   like, passing `--mode <safe|reinstall|install>` and `--dry-run` as needed
   (or the `UET_MODE` / `UET_DRY_RUN` env vars — see the payload header
   comments).
3. Save each host's stdout — exactly one JSON result line — to
   `uet-data/results/<hostname>.json` (hostname must match the `hostname`
   field from `worklist.json`/`worklist.csv`, with any character outside
   `[A-Za-z0-9_.-]` replaced by `_`).
4. Run `uet collect` to merge everything and re-verify against the console.

## Exit codes / outcome glossary

Each payload run exits with one of three codes and always prints exactly one
JSON line to stdout (schema `uet-result/3`) with an `outcome` field:

| Exit code | Meaning |
|---|---|
| `0` | Payload ran to completion (fix ladder attempted if applicable) |
| `2` | `BLOCKED` — payload refused to act; see `blockers[]` |
| `3` | `--dry-run` — diagnose-only, no changes made |

| Outcome | Meaning |
|---|---|
| `FIXED` | Agent existed but was unhealthy; the safe/reinstall fix ladder repaired it |
| `INSTALLED` | No agent was present; the embedded deployment script installed one |
| `NO_ACTION_NEEDED` | Diagnose found the agent already installed, running, and activated against our manager |
| `STILL_BROKEN` | Fix ladder ran (or `--dry-run` diagnosed) but the agent remains unhealthy — check `blockers[]` |
| `BLOCKED` | Payload refused to act: bad `--mode`, a foreign manager owns the agent, or the payload isn't running as root/admin |
| `ERROR` | The payload's error trap fired (unexpected failure) before a real outcome could be determined — should not appear in normal operation |
| `TRANSPORT_ERROR` | (`uet collect` only) `uet run`'s transport never got a JSON line back from the host — see `uet-data/results/<host>.error.txt` |
| `CORRUPT_RESULT` | (`uet collect` only) a `uet-data/results/<host>.json` file exists but isn't valid JSON (e.g. a truncated copy). `uet collect` never aborts on this — it records the row and moves on. `uet run`'s resume logic only checks that the file *exists*, not that it parses, so delete the bad file before re-running that host or it will be skipped again |
| `NOT_RUN` | (`uet collect` only) no result file (`.json` or `.error.txt`) exists yet for this worklist host |

## Caveats

- **`uet run` refuses to dial a hostname that resolves off-network.** SWP's
  `hostName` is whatever the host called itself at registration; a host that
  was resolving itself via public DNS gets recorded under its **ISP
  reverse-DNS name** (e.g. `syn-203-000-113-043.biz.example-isp.com` resolving
  to `9.9.9.9`). Dialling that name would hand the payload — and the
  tenant activation token it carries — to an unrelated host on the public
  internet. So for `ssh`/`winrm`:
  1. A private worklist IP (`lastIPUsed`) is preferred over the hostname, and
     used as the connect target when present.
  2. Failing that, the hostname is resolved; if it lands outside RFC1918 /
     `[run] allowed_cidrs`, the host is **refused** — a `.error.txt` is written
     so `uet collect` reports it as `TRANSPORT_ERROR` instead of silently
     skipping it, and the next run retries it.
  3. `--allow-public-target` disables the check. `ssm` is never gated: it
     resolves via the EC2/SSM APIs, not DNS.
- **`uet delete` only deletes `STALE` rows.** `approved=yes` is one keystroke,
  and a `NEEDS_REPAIR` host still has a fixable agent — deleting its record
  discards the activation history instead of repairing it. So the approved CSV
  must carry a `bucket` column (worklist.csv already does) and every approved
  row must be `STALE`; otherwise `uet delete` exits before making any API call
  and names the offending rows. `--allow-non-stale` overrides, including the
  requirement for the column. **This is a guardrail, not a verdict** — triage
  can under-call STALE (an unresolvable ISP hostname is one known gap), so a
  human deciding otherwise on API evidence is a legitimate use of the flag.
- **SSM command size.** AWS Systems Manager Run Command caps command payloads
  at roughly 100KB. Embedded deployment scripts fit comfortably today, but an
  unusually large deployment script could blow this budget — if it does,
  switch to an S3-based SSM document instead of inline commands.
- **SSM resolves hostnames to a single EC2 instance ID before sending.** The
  `ssm` transport tries, in order, an EC2 `describe_instances` match on the
  `Name` tag, then `private-dns-name`, then `private-ip-address` (against the
  worklist item's known IPs) — each ANDed with `instance-state-name=running`,
  stopping at the first tier that returns any instances. Zero matches across
  all tiers, or more than one match at the winning tier, fails that host
  immediately (no `send_command`, no 20-minute silent poll) with a message
  naming the hostname and what was tried. Set `[run] ssm_region` in
  `uet.toml` if the target instances aren't in boto3's default region.
- **WinRM needs NTLM credentials via env vars**, not `uet.toml`:
  `UET_WINRM_USER` / `UET_WINRM_PASSWORD`. The winrm transport also connects
  with `server_cert_validation="ignore"` — a pragmatic default for internal or
  self-signed WinRM endpoints, but worth flagging to your security team before
  a wider rollout.
- **Payload `--mode` values are lowercase only:** `safe`, `reinstall`,
  `install`. The bash payload matches the mode string exactly and returns a
  `bad_mode` blocker on anything else (including different casing). The
  PowerShell payload is more forgiving and normalizes any casing
  (`-Mode SAFE` works) before dispatch.
- **Foreign-manager agents are never touched**, in any mode, dry-run or not.
  If a host's agent is activated against a manager other than ours, the
  payload reports `BLOCKED` with a `foreign_manager` blocker and takes no
  action.
- **`uet triage --refresh` is currently a no-op.** `triage` always pulls live
  V1/SWP inventory and writes a fresh timestamped snapshot under
  `uet-data/snapshots/`; it does not yet read back a prior snapshot, so
  there's nothing for `--refresh` to bypass. Snapshots are written for
  audit/resume purposes today, not (yet) consumed to skip a live pull.
- **CAM cloud-asset enrichment is a future enhancement.** Triage's liveness
  signal today comes from three sources, in priority order:
  1. A V1 inventory match (a matched V1 record means something on that host has
     reported) → host appears **live**.
  2. An optional Axonius CSV (`--axonius-csv path.csv`, one `hostname` column):
     a hostname present in the export → host appears **live**.
  3. **DNS resolution** as the gone-signal: if a host has neither of the above
     and its hostname (and its short form) *fail to resolve*, the host is very
     likely gone → this is the second independent signal that can push a
     never-activated / long-offline candidate to **STALE**. A hostname that
     *does* resolve is treated as inconclusive (unknown), not proof of life.

  Until CAM cross-referencing lands, provide an "online but no Trend
  telemetry" export from your asset inventory tool as an additional liveness
  source for the STALE bucket.

  DNS lookups are run with bounded concurrency and a per-lookup timeout so a
  few dead/hung hosts can't stall a large run:

  | Flag | Default | Effect |
  |---|---|---|
  | `--dns-timeout SECONDS` | `5.0` | Per-hostname lookup timeout. A lookup that exceeds it is recorded as **inconclusive** (`None`), never as "gone" — a slow/hung resolver cannot mark a host STALE. |
  | `--dns-workers N` | `32` | Max concurrent DNS lookups (thread-pool size). Lookups across hosts overlap instead of serializing. |
  | `--no-dns` | off | Skip DNS entirely; every lookup is treated as inconclusive, so **no** host can be marked DNS-gone. With `--no-dns` the STALE bucket is driven only by the other signals (e.g. Axonius), since the DNS gone-signal is off. |

### Evidence-column tokens

Each worklist row carries an `evidence` list explaining *why* it landed in its
bucket. Tokens use these prefixes:

- `swp:*` — facts read from the SWP computer record:
  `swp:agentStatus=<status>`, `swp:offline_days=<n>`, `swp:never_communicated`,
  `swp:never_activated`.
- `liveness:*` — the derived liveness verdict:
  `liveness:host_appears_live`, `liveness:host_appears_gone`,
  `liveness:unknown`, and `liveness:dns_unresolved` (added when the STALE
  verdict rests on the DNS gone-signal — the hostname did not resolve).
- `match:*` — which key matched this computer to a V1 endpoint:
  `match:agent_guid`, `match:cloud_id`, `match:hostname`, `match:ip`, or
  `match:none` when no V1 record matched.

## Transports available

| Transport | Use case | Extra dependency |
|---|---|---|
| `ssh` | Linux hosts reachable over SSH | none (uses system `ssh`) |
| `winrm` | Windows hosts reachable over WinRM | `pywinrm` (`pip install '.[winrm]'`) |
| `ssm` | Any host manageable via AWS Systems Manager Run Command | `boto3` (`pip install '.[ssm]'`) |

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
