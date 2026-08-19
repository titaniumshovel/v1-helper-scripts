#!/usr/bin/env bash
# uet driver — runs check-fix-agent-linux.sh across a host list from a jump box.
# THIS RUNS ON THE JUMP SERVER, not on the targets.
#
# Why this exists: the obvious one-liner
#
#     ssh "$h" 'sudo bash -s -- --dry-run' < check-fix-agent-linux.sh
#
# cannot work where SSH and sudo authenticate interactively. The payload
# occupies stdin, so neither ssh nor sudo can read a password from it, and a
# `requiretty` sudoers policy rejects the piped form outright. The symptom is no
# JSON line at all, which reads like an agent problem but is a transport
# problem.
#
# Instead: open ONE multiplexed SSH connection per host (so the SSH password is
# entered once, not once per operation), stage the payload over it into a
# private mode-700 directory, then run it under `ssh -t` so sudo has a TTY to
# prompt on.
#
# Expect two prompts per host: SSH, then sudo. That is inherent to password auth
# with a named account. Given a key plus NOPASSWD sudo, add --batch to run
# unattended.
#
# Intentionally no `set -e`: one unreachable host must not abandon the rest of
# the list.
set -uo pipefail

PAYLOAD=""
HOSTS_FILE=""
USER_NAME="${UET_SSH_USER:-$(id -un)}"
MODE="safe"
DRY_RUN=1
OUTDIR="results"
CRED_FILE=""
COLLECT_DIAG=0
BATCH=0

usage() {
  cat >&2 <<'EOF'
usage: run-linux-hosts.sh --payload <script> --hosts <file> [options]

  --payload <path>    check-fix-agent-linux.sh
  --hosts <path>      one host per line, or a CSV whose first column is the
                      host; blank lines and #comments ignored, header skipped
  --user <name>       SSH user (default: $UET_SSH_USER or current user)
  --mode <m>          safe | refresh | reinstall | install   (default: safe)
  --dry-run           diagnose only, change nothing  (DEFAULT)
  --run               actually apply fixes; disables --dry-run
  --cred-file <path>  local file holding "tenantID:<id> token:<tok>".
                      Staged to the target as 0600 and passed by PATH, so the
                      token never appears in the remote argv / ps output.
  --collect-diag      also collect a diagnostics bundle per host
  --out <dir>         results directory (default: results)
  --batch             non-interactive; requires key auth + NOPASSWD sudo
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --payload) PAYLOAD="${2:-}"; shift 2 ;;
    --hosts) HOSTS_FILE="${2:-}"; shift 2 ;;
    --user) USER_NAME="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --run) DRY_RUN=0; shift ;;
    --cred-file) CRED_FILE="${2:-}"; shift 2 ;;
    --collect-diag) COLLECT_DIAG=1; shift ;;
    --out) OUTDIR="${2:-}"; shift 2 ;;
    --batch) BATCH=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done

[ -n "$PAYLOAD" ] && [ -r "$PAYLOAD" ] || { echo "error: --payload missing or unreadable" >&2; usage; }
[ -n "$HOSTS_FILE" ] && [ -r "$HOSTS_FILE" ] || { echo "error: --hosts missing or unreadable" >&2; usage; }
[ -z "$CRED_FILE" ] || [ -r "$CRED_FILE" ] || { echo "error: --cred-file unreadable" >&2; exit 2; }
case "$MODE" in safe|refresh|reinstall|install) ;; *) echo "error: bad --mode $MODE" >&2; exit 2 ;; esac

if [ "$DRY_RUN" = 0 ] && [ "$MODE" != refresh ] && [ -z "$CRED_FILE" ]; then
  echo "warning: --run in '$MODE' without --cred-file; reactivation will be skipped" >&2
fi

mkdir -p "$OUTDIR" || exit 1

# Private control-socket dir. %C is a hash of user/host/port, which keeps the
# socket path short — a long ControlPath silently breaks the 104-byte sun_path
# limit, and the failure mode looks like a connection error.
CM_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uet-cm.XXXXXX")" || exit 1
chmod 700 "$CM_DIR"
CP="$CM_DIR/%C"
OPENED=""

cleanup() {
  # Exit each master explicitly rather than waiting for ControlPersist. Same
  # -o ControlPath and same target, so %C hashes to the same socket.
  local t
  for t in $OPENED; do
    ssh -o ControlPath="$CP" -O exit "$t" 2>/dev/null
  done
  rm -rf "$CM_DIR"
}
trap cleanup EXIT INT TERM

SSH_COMMON="-o ControlMaster=auto -o ControlPersist=120 -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR"
[ "$BATCH" = 1 ] && SSH_COMMON="$SSH_COMMON -o BatchMode=yes"

# Host list: strip #comments and trailing space, take the first CSV field, drop a
# header row that names a column rather than a host. `while read` rather than
# mapfile so this still runs under the bash 3.2 on a macOS staging box.
HOSTS=""
while IFS= read -r line; do
  [ -n "$line" ] && HOSTS="$HOSTS $line"
done < <(
  sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$HOSTS_FILE" \
    | awk -F, 'NF && $1 != "" {print $1}' \
    | grep -viE '^(hostname|swp_display_name|host)$'
)

# shellcheck disable=SC2086
set -- $HOSTS
[ "$#" -gt 0 ] || { echo "error: no hosts parsed from $HOSTS_FILE" >&2; exit 2; }

printf 'uet: %d host(s), mode=%s dry_run=%s user=%s\n' "$#" "$MODE" "$DRY_RUN" "$USER_NAME" >&2
[ "$BATCH" = 1 ] || printf 'uet: expect two prompts per host (ssh, then sudo)\n' >&2

SUMMARY_FILE="$(mktemp "${TMPDIR:-/tmp}/uet-sum.XXXXXX")"
ok=0; degraded=0; broken=0; blocked=0; failed=0

record() {  # host outcome notes
  printf '%s|%s|%s\n' "$1" "$2" "${3:--}" >> "$SUMMARY_FILE"
}

for h in "$@"; do
  printf '\nuet: ===== %s =====\n' "$h" >&2
  target="$USER_NAME@$h"
  jf="$OUTDIR/$h.json"
  ef="$OUTDIR/$h.err"
  rawf="$OUTDIR/$h.raw"
  : > "$ef"

  # Master connection first, so the SSH password is entered once and the staging
  # copy plus the run both reuse it.
  # shellcheck disable=SC2086
  if ! ssh $SSH_COMMON -o ControlPath="$CP" "$target" true 2>>"$ef"; then
    echo "uet: $h UNREACHABLE / auth failed (see $ef)" >&2
    record "$h" "TRANSPORT_ERROR"; failed=$((failed+1)); continue
  fi
  OPENED="$OPENED $target"

  # Stage into a fresh mode-700 dir rather than a predictable /var/tmp name: the
  # payload is executed by root, and a pre-created symlink at a guessable path
  # would turn that into a local privilege-escalation primitive.
  # shellcheck disable=SC2086
  rdir="$(ssh $SSH_COMMON -o ControlPath="$CP" "$target" \
    'd=$(mktemp -d /var/tmp/uet.XXXXXX) && chmod 700 "$d" && printf %s "$d"' 2>>"$ef")"
  case "$rdir" in
    /var/tmp/uet.*) ;;
    *) echo "uet: $h could not create staging dir (see $ef)" >&2
       record "$h" "STAGE_ERROR"; failed=$((failed+1)); continue ;;
  esac

  # shellcheck disable=SC2086
  if ! scp $SSH_COMMON -o ControlPath="$CP" -q "$PAYLOAD" "$target:$rdir/payload.sh" 2>>"$ef"; then
    echo "uet: $h failed to stage payload (see $ef)" >&2
    ssh $SSH_COMMON -o ControlPath="$CP" "$target" "rm -rf $rdir" 2>>"$ef"
    record "$h" "STAGE_ERROR"; failed=$((failed+1)); continue
  fi

  remote_env=""
  if [ -n "$CRED_FILE" ]; then
    # shellcheck disable=SC2086
    if ! scp $SSH_COMMON -o ControlPath="$CP" -q "$CRED_FILE" "$target:$rdir/cred" 2>>"$ef"; then
      echo "uet: $h failed to stage credential (see $ef)" >&2
      ssh $SSH_COMMON -o ControlPath="$CP" "$target" "rm -rf $rdir" 2>>"$ef"
      record "$h" "STAGE_ERROR"; failed=$((failed+1)); continue
    fi
    # shellcheck disable=SC2086
    ssh $SSH_COMMON -o ControlPath="$CP" "$target" "chmod 600 $rdir/cred" 2>>"$ef"
    remote_env="UET_ACTIVATION_ARGS_FILE=$rdir/cred"
  fi

  args="--mode $MODE"
  [ "$DRY_RUN" = 1 ] && args="$args --dry-run"
  [ "$COLLECT_DIAG" = 1 ] && args="$args --collect-diag"

  # The staging dir is removed whatever the payload's exit status. sudo -p makes
  # it obvious which password is being asked for.
  remote_cmd="sudo -p 'uet: sudo password for %u@%h: ' $remote_env bash $rdir/payload.sh $args; rc=\$?; rm -rf $rdir; exit \$rc"

  # shellcheck disable=SC2086
  ssh $SSH_COMMON -o ControlPath="$CP" -t "$target" "$remote_cmd" >"$rawf" 2>>"$ef"
  rc=$?

  # A TTY session mixes login banner / MOTD text into stdout, so take the LAST
  # line that looks like a JSON object instead of assuming the payload owns the
  # stream. -t leaves CRLF endings, hence the \r strip.
  tr -d '\r' < "$rawf" | awk '/^\{/{last=$0} END{if (last) print last}' > "$jf"

  if [ ! -s "$jf" ]; then
    echo "uet: $h produced NO result line (rc=$rc) — transport or staging, not the agent" >&2
    echo "uet:   raw output kept at $rawf" >&2
    rm -f "$jf"
    record "$h" "NO_RESULT(rc=$rc)"; failed=$((failed+1)); continue
  fi
  rm -f "$rawf"

  outcome="$(sed -n 's/.*"outcome":"\([A-Z_]*\)".*/\1/p' "$jf")"
  notes="$(sed -n 's/.*"notes":\[\([^]]*\)\].*/\1/p' "$jf" | tr -d '"')"
  printf 'uet: %s -> %s (rc=%s)%s\n' "$h" "${outcome:-UNPARSEABLE}" "$rc" \
    "${notes:+  notes: $notes}" >&2
  record "$h" "${outcome:-UNPARSEABLE}" "$notes"
  case "$outcome" in
    NO_ACTION_NEEDED|FIXED|INSTALLED) ok=$((ok+1)) ;;
    DEGRADED) degraded=$((degraded+1)) ;;
    STILL_BROKEN) broken=$((broken+1)) ;;
    BLOCKED) blocked=$((blocked+1)) ;;
    *) failed=$((failed+1)) ;;
  esac
done

printf '\nuet: ================ summary ================\n' >&2
printf '%-34s %-18s %s\n' "HOST" "OUTCOME" "NOTES" >&2
while IFS='|' read -r a b c; do
  printf '%-34s %-18s %s\n' "$a" "$b" "$c" >&2
done < "$SUMMARY_FILE"
rm -f "$SUMMARY_FILE"
printf '\nok=%d degraded=%d still_broken=%d blocked=%d failed=%d\n' \
  "$ok" "$degraded" "$broken" "$blocked" "$failed" >&2
printf 'uet: results in %s/\n' "$OUTDIR" >&2

# DEGRADED means the agent core is healthy but a module fault was detected;
# STILL_BROKEN and BLOCKED need attention. None of those are driver failures, so
# they do not fail the run — only transport and parse failures do.
[ "$failed" -eq 0 ]
