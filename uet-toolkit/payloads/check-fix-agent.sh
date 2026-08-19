#!/usr/bin/env bash
# uet check-fix-agent payload (Linux) — schema uet-result/3
# Diagnoses the Trend SWP agent (ds_agent) and, per --mode, applies tiered fixes.
# stdout: exactly one JSON result line. stderr: progress chatter.
#
# SCOPE, read this before trusting an outcome: this payload sees the AGENT, not
# the manager's view of the agent's MODULES. A host can be installed, running
# and activated (so healthy() is true) while the console still flags
# "Anti-Malware Engine with Basic Functions", "MQTT Connection Offline" or
# "Smart Protection Server Disconnected" — those are module-level and largely
# manager-side. NO_ACTION_NEEDED therefore means "the agent core is healthy",
# NOT "the console will show green". Read notes[] for what was left unverified.
set -u

# macOS dev boxes may lack GNU coreutils `timeout`; degrade to a no-op wrapper
# that just runs the command without a duration bound. Target hosts are Linux
# and always have real `timeout`, so behavior there is unchanged. The wrapper
# must swallow a leading `-k <grace>` too — every real call site passes it,
# because dsa_control ignores SIGTERM and GNU timeout without -k then waits
# forever (live-verified: a "timeout 300" activation still running 20+ min in).
if ! command -v timeout >/dev/null 2>&1; then
  timeout() { if [ "$1" = "-k" ]; then shift 2; fi; shift; "$@"; }
fi

SCHEMA="uet-result/3"
MODE="${UET_MODE:-safe}"
DRY_RUN="${UET_DRY_RUN:-0}"
AGENT_DIR="${UET_AGENT_DIR:-/opt/ds_agent}"
DIAG_DIR="${UET_DIAG_DIR:-/var/opt/ds_agent/diag}"
COLLECT_DIAG="${UET_COLLECT_DIAG:-0}"

# Operator-set env values are captured BEFORE the embedded slots below, because
# `uet` rewrites those slot lines at generation time and would otherwise clobber
# them. This lets one file serve both flows: orchestrated runs get the values
# baked in, customer self-service runs pass them as env vars. Keeping it to one
# file matters — the shipped copy previously drifted from the tested template.
_ENV_DSM_URL="${UET_DSM_URL:-}"
_ENV_DEPLOY_B64="${UET_DEPLOY_B64:-}"
_ENV_ACTIVATION_ARGS="${UET_ACTIVATION_ARGS:-}"

UET_DSM_URL=""  # __UET_DSM_URL__
UET_DEPLOY_B64=""  # __UET_DEPLOY_B64__
UET_ACTIVATION_ARGS=""  # __UET_ACTIVATION_ARGS__

# `:=` fires when the slot is unset OR empty, so an unfilled slot falls through
# to the env value. No hardcoded manager URL default on purpose: an empty
# UET_DSM_URL skips the reachability probe entirely, which keeps the test suite
# off the network and keeps air-gapped runs from reporting a misleading
# manager_unreachable. The shipped bundle gets the URL baked into the slot by
# `payload_gen` — that is what keeps the customer copy identical to the tested
# template instead of hand-edited and drifting.
: "${UET_DSM_URL:=$_ENV_DSM_URL}"
: "${UET_DEPLOY_B64:=$_ENV_DEPLOY_B64}"
: "${UET_ACTIVATION_ARGS:=$_ENV_ACTIVATION_ARGS}"

# Credentials may instead arrive as a path to a 0600 file. Preferred over the
# env var for orchestrated runs: `sudo VAR=<token> ...` puts the token in the
# remote process argv, where any local user can read it out of `ps`. A path is
# not a secret.
if [ -z "$UET_ACTIVATION_ARGS" ] && [ -n "${UET_ACTIVATION_ARGS_FILE:-}" ]; then
  if [ -r "$UET_ACTIVATION_ARGS_FILE" ]; then
    UET_ACTIVATION_ARGS="$(tr -d '\r\n' < "$UET_ACTIVATION_ARGS_FILE")"
  fi
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      if [ $# -ge 2 ]; then shift 2; else shift; fi
      ;;
    --dry-run) DRY_RUN=1; shift ;;
    --collect-diag) COLLECT_DIAG=1; shift ;;
    *) shift ;;
  esac
done

HOST="$(hostname -f 2>/dev/null || hostname)"
ACTIONS=""
PLANNED=""
BLOCKERS=""
NOTES=""
OUTCOME="ERROR"
INSTALLED=false SERVICE_RUNNING=false ACTIVATED=false FOREIGN=false MANAGER_REACHABLE=null
DISK_FREE_MB=0 AGENT_STATUS_RAW="" AGENT_STATUS_FULL="" COMPONENT_INFO_RAW=""
COMPONENT_INFO_FULL=""
KERNEL="" AGENT_VERSION="" AGENT_VERSION_SOURCE="" AGENT_STATE=""
DRIVER_HOOKED="" DRIVER_CHECKED=""
AU_STATUS="" HEARTBEAT_AGE_SEC=null HEARTBEAT_RESULT="" HEARTBEAT_ERROR=""
SECURE_BOOT=null TREND_KMODS=""
AM_MODE="unknown" AM_EVIDENCE="" AM_ENGINE_ATSE="" AM_PATTERNS="" DIAG_FILE=""
STATUS_RAW_CAP="${UET_STATUS_RAW_CAP:-2000}"
COMPONENT_RAW_CAP=1200

log() { echo "uet: $*" >&2; }
add_action() { ACTIONS="${ACTIONS:+$ACTIONS,}\"$1\""; }
add_planned() {
  case ",$PLANNED," in
    *",\"$1\","*) return ;;
  esac
  PLANNED="${PLANNED:+$PLANNED,}\"$1\""
}
add_blocker() {
  case ",$BLOCKERS," in
    *",\"$1\","*) return ;;
  esac
  BLOCKERS="${BLOCKERS:+$BLOCKERS,}\"$1\""
}
add_note() {
  case ",$NOTES," in
    *",\"$1\","*) return ;;
  esac
  NOTES="${NOTES:+$NOTES,}\"$1\""
}
# Newlines become literal \n rather than being deleted. The raw dsa_query dump
# is now a diagnostic we actually read, and collapsing 28 field lines into one
# run-on string made it useless. Order matters: backslash, then quote, then
# newline->\n, then strip any remaining control bytes (awk has already consumed
# the real newlines, so the final tr cannot undo the escaping).
json_escape() {
  printf '%s' "$1" \
    | sed 's/\\/\\\\/g; s/"/\\"/g' \
    | awk '{ l[NR]=$0 } END { for (i=1;i<=NR;i++) printf "%s%s", (i>1 ? "\\n" : ""), l[i] }' \
    | tr -d '\000-\037\177'
}

emit() {
  printf '{"schema":"%s","host":"%s","mode":"%s","dry_run":%s,"checks":{"installed":%s,"service_running":%s,"activated":%s,"manager_reachable":%s,"disk_free_mb":%s,"kernel":"%s","agent_version":"%s","agent_version_source":"%s","agent_state":"%s","driver_hooked":"%s","driver_checked":"%s","au_status":"%s","heartbeat_age_sec":%s,"heartbeat_result":"%s","heartbeat_error":"%s","secure_boot":%s,"trend_kmods":"%s","am_mode":"%s","am_evidence":"%s","am_engine_atse":"%s","am_patterns":"%s","agent_status_raw":"%s","component_info_raw":"%s"},"actions":[%s],"planned":[%s],"blockers":[%s],"notes":[%s],"diag_file":"%s","outcome":"%s"}\n' \
    "$SCHEMA" "$(json_escape "$HOST")" "$MODE" \
    "$([ "$DRY_RUN" = 1 ] && echo true || echo false)" \
    "$INSTALLED" "$SERVICE_RUNNING" "$ACTIVATED" "$MANAGER_REACHABLE" \
    "$DISK_FREE_MB" \
    "$(json_escape "$KERNEL")" "$(json_escape "$AGENT_VERSION")" \
    "$(json_escape "$AGENT_VERSION_SOURCE")" \
    "$(json_escape "$AGENT_STATE")" "$(json_escape "$DRIVER_HOOKED")" \
    "$(json_escape "$DRIVER_CHECKED")" "$(json_escape "$AU_STATUS")" \
    "$HEARTBEAT_AGE_SEC" "$HEARTBEAT_RESULT" "$(json_escape "$HEARTBEAT_ERROR")" \
    "$SECURE_BOOT" "$(json_escape "$TREND_KMODS")" \
    "$AM_MODE" "$(json_escape "$AM_EVIDENCE")" \
    "$(json_escape "$AM_ENGINE_ATSE")" "$(json_escape "$AM_PATTERNS")" \
    "$(json_escape "$AGENT_STATUS_RAW")" "$(json_escape "$COMPONENT_INFO_RAW")" \
    "$ACTIONS" "$PLANNED" "$BLOCKERS" "$NOTES" "$(json_escape "$DIAG_FILE")" "$OUTCOME"
  UET_EMITTED=1
}

# Guarantee exactly one JSON result line even on an unexpected early exit: if
# the script dies before any normal emit ran, fire once with OUTCOME=ERROR.
trap 'rc=$?; if [ -z "${UET_EMITTED:-}" ]; then OUTCOME="ERROR"; emit; fi' EXIT

# Test hook: force an uncaught early exit before any normal flow, to prove the
# EXIT trap still emits an ERROR result line.
if [ -n "${UET_TEST_FORCE_CRASH:-}" ]; then false; exit 1; fi

finish() { emit; exit "$1"; }

service_running() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active ds_agent >/dev/null 2>&1
  else
    service ds_agent status >/dev/null 2>&1
  fi
}

_url_host() {
  local hp="${1#*://}"
  hp="${hp%%/*}"; hp="${hp%%:*}"
  printf '%s' "$hp" | tr '[:upper:]' '[:lower:]'
}

_domain_suffix() {
  printf '%s' "$1" | awk -F. '{ if (NF >= 2) print $(NF-1) "." $NF; else print $0 }'
}

# Pull one VALUE line out of dsa_query -c GetAgentStatus. Real output opens with
# an index of field NAMES ("AgentStatus.13: agentState") and puts values further
# down ("AgentStatus.agentState: green"); anchoring on the field name after the
# dot matches only the value line, never the index.
_status_field() {
  printf '%s' "$AGENT_STATUS_FULL" \
    | grep -oE "AgentStatus\.$1:[[:space:]]*[^[:space:]]+" \
    | head -n 1 | sed -E "s/^AgentStatus\.$1:[[:space:]]*//"
}

# Best-effort agent build number from `dsa_query -c GetPluginVersion`, a
# documented command ("version information of the agent and protection
# modules"). Its OUTPUT SCHEMA is not published, so the parse is deliberately
# narrow: only a version-shaped string on a line that names the agent is
# accepted, which keeps a protection module's version from being reported as
# the agent's. A miss yields nothing rather than a guess.
_plugin_agent_version() {
  timeout -k 10 30 "$AGENT_DIR/dsa_query" -c GetPluginVersion 2>/dev/null \
    | grep -i 'agent' \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+([.-][0-9]+)?' \
    | head -n 1
}

# Agent version WITH provenance, because a build number with no stated source is
# exactly the kind of claim this engagement cannot afford. rpm/dpkg are
# authoritative and tried first; note that rpm's %{VERSION} alone is "20.0.1",
# which is not the build the console shows ("20.0.1.7380") and not enough to
# reason about KSP generation thresholds, so a purely numeric %{RELEASE} is
# appended to match the console's format.
_set_agent_version() {
  AGENT_VERSION=""; AGENT_VERSION_SOURCE=""
  local v r
  if command -v rpm >/dev/null 2>&1; then
    v="$(rpm -q --qf '%{VERSION}' ds_agent 2>/dev/null || true)"
    case "$v" in *"not installed"*|*"is not"*) v="" ;; esac
    if [ -n "$v" ]; then
      r="$(rpm -q --qf '%{RELEASE}' ds_agent 2>/dev/null || true)"
      case "$r" in ''|*[!0-9]*) ;; *) v="$v.$r" ;; esac
      AGENT_VERSION="$v"; AGENT_VERSION_SOURCE="rpm"; return
    fi
  fi
  if command -v dpkg-query >/dev/null 2>&1; then
    v="$(dpkg-query -W -f='${Version}' ds-agent 2>/dev/null || true)"
    case "$v" in *"not installed"*|*"is not"*) v="" ;; esac
    if [ -n "$v" ]; then
      AGENT_VERSION="$v"; AGENT_VERSION_SOURCE="dpkg"; return
    fi
  fi
  if [ "$INSTALLED" = true ] && [ "$SERVICE_RUNNING" = true ]; then
    v="$(_plugin_agent_version)"
    if [ -n "$v" ]; then
      AGENT_VERSION="$v"; AGENT_VERSION_SOURCE="GetPluginVersion"
    fi
  fi
}

# Promote the Anti-Malware engine and pattern levels out of the raw dump and
# into named fields. rev4 captured them only inside component_info_raw, which is
# capped and truncated mid-field on a real host, so comparing two hosts' pattern
# levels meant hand-parsing a cut-off blob. Pairs are keyed by pattern NAME, not
# by the agent's index: the index is not stable across hosts (Spyware/Grayware
# was pattern.10 on one production host and pattern.11 on another). Version
# strings are compared as strings by the reader — that is arithmetic, not an
# interpretation of an undocumented field.
_set_component_versions() {
  AM_ENGINE_ATSE=""; AM_PATTERNS=""
  AM_ENGINE_ATSE="$(printf '%s' "$COMPONENT_INFO_FULL" \
    | grep -oE 'Component\.AM\.version\.engine\.ATSE:[[:space:]]*[^[:space:]]+' \
    | head -n 1 | sed -E 's/^.*ATSE:[[:space:]]*//')"
  AM_PATTERNS="$(printf '%s' "$COMPONENT_INFO_FULL" | awk '
    /^Component\.AM\.version\.pattern\.[0-9]+\.name:/ {
      i = $0; sub(/^Component\.AM\.version\.pattern\./, "", i); sub(/\.name:.*$/, "", i)
      v = $0; sub(/^[^:]*:[ \t]*/, "", v); sub(/[ \t]+$/, "", v); n[i] = v; next
    }
    /^Component\.AM\.version\.pattern\.[0-9]+\.version:/ {
      i = $0; sub(/^Component\.AM\.version\.pattern\./, "", i); sub(/\.version:.*$/, "", i)
      v = $0; sub(/^[^:]*:[ \t]*/, "", v); sub(/[ \t]+$/, "", v); r[i] = v; next
    }
    END { for (i in n) if (i in r) print n[i] "=" r[i] }
  ' | LC_ALL=C sort | awk '{ printf "%s%s", (NR>1 ? ";" : ""), $0 }' \
    | head -c "$COMPONENT_RAW_CAP")"
}

# Anti-Malware mode. Reports "on" or "basic" only on the agent's own
# GetComponentInfo verdict (Component.AM.mode / Component.AM.driverOffline),
# which is authoritative; otherwise "unknown". The log grep is now strictly a
# fallback for hosts where GetComponentInfo returned nothing: the previous
# unanchored `2209` pattern matched those digits inside microsecond timestamps
# (e.g. "02:24:18.742209") and flagged four hosts whose AM was verified fine
# (live-confirmed 2026-08-07), so the fallback now only accepts 2209 as a
# standalone token, never embedded in a longer number.
_detect_am_mode() {
  AM_MODE="unknown"; AM_EVIDENCE=""
  local mode offline
  mode="$(printf '%s' "$COMPONENT_INFO_FULL" \
    | grep -oE 'Component\.AM\.mode:[[:space:]]*[^[:space:]]+' \
    | head -n 1 | sed -E 's/^Component\.AM\.mode:[[:space:]]*//')"
  offline="$(printf '%s' "$COMPONENT_INFO_FULL" \
    | grep -oE 'Component\.AM\.driverOffline:[[:space:]]*[^[:space:]]+' \
    | head -n 1 | sed -E 's/^Component\.AM\.driverOffline:[[:space:]]*//')"
  if [ -n "$mode" ]; then
    if [ "$mode" = "on" ] && [ "$offline" != "true" ]; then
      AM_MODE="on"
    else
      AM_MODE="basic"
    fi
    AM_EVIDENCE="componentinfo:Component.AM.mode=$mode"
    return
  fi
  if [ "$offline" = "true" ]; then
    AM_MODE="basic"
    AM_EVIDENCE="componentinfo:Component.AM.driverOffline=true"
    return
  fi
  local lf
  for lf in "$DIAG_DIR/ds_agent.log" "$DIAG_DIR/ds_agent-err.log" \
            /var/log/ds_agent.log /var/log/ds_agent-err.log; do
    [ -r "$lf" ] || continue
    if grep -qiE '(^|[^0-9A-Fa-f.x])2209([^0-9A-Fa-f]|$)|only basic function|basic functions available|basic function mode' "$lf" 2>/dev/null; then
      AM_MODE="basic"
      AM_EVIDENCE="log:$lf"
      return
    fi
  done
}

diagnose() {
  INSTALLED=false SERVICE_RUNNING=false ACTIVATED=false FOREIGN=false
  AGENT_STATUS_FULL="" COMPONENT_INFO_FULL=""
  DISK_FREE_MB="$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}')"
  DISK_FREE_MB="${DISK_FREE_MB:-0}"
  KERNEL="$(uname -r 2>/dev/null || true)"

  # Secure Boot without the Trend key enrolled is a documented cause of the AM
  # driver failing to load, so it is worth capturing even when everything else
  # looks fine. Non-UEFI hosts report neither enabled nor disabled -> null.
  SECURE_BOOT=null
  if command -v mokutil >/dev/null 2>&1; then
    local sb; sb="$(mokutil --sb-state 2>/dev/null || true)"
    case "$sb" in
      *[Ee]nabled*) SECURE_BOOT=true ;;
      *[Dd]isabled*) SECURE_BOOT=false ;;
    esac
  fi
  TREND_KMODS="$(lsmod 2>/dev/null | awk '{print $1}' \
    | grep -iE '^(ds_|dsa|tmhook|tmesk|tmevt|tm_|trend)' | tr '\n' ',' | sed 's/,$//')"

  [ -x "$AGENT_DIR/dsa_control" ] && INSTALLED=true
  if [ "$INSTALLED" = true ] && service_running; then
    SERVICE_RUNNING=true
    AGENT_STATUS_FULL="$(timeout -k 10 30 "$AGENT_DIR/dsa_query" -c GetAgentStatus 2>&1 || true)"
    AGENT_STATUS_RAW="$(printf '%s' "$AGENT_STATUS_FULL" | head -c "$STATUS_RAW_CAP")"
    # Captured in full and truncated only for the REPORTED field, matching
    # AGENT_STATUS_FULL/RAW. Parsing the truncated copy silently dropped every
    # pattern past the cap.
    COMPONENT_INFO_FULL="$(timeout -k 10 30 "$AGENT_DIR/dsa_query" -c GetComponentInfo 2>&1 || true)"
    COMPONENT_INFO_RAW="$(printf '%s' "$COMPONENT_INFO_FULL" | head -c "$COMPONENT_RAW_CAP")"

    AGENT_STATE="$(_status_field agentState)"
    DRIVER_HOOKED="$(_status_field driverHooked)"
    DRIVER_CHECKED="$(_status_field driverChecked)"
    AU_STATUS="$(_status_field auStatus)"

    # Heartbeat freshness proves manager comms independently of `activated`,
    # which stays true on a host that has silently stopped checking in.
    local now last
    now="$(_status_field currentTime)"
    last="$(_status_field lastAgentToManagerSession)"
    HEARTBEAT_AGE_SEC=null
    case "$now$last" in
      ''|*[!0-9]*) ;;
      *) HEARTBEAT_AGE_SEC=$((now - last)) ;;
    esac

    # Activation is proven only by a dsmUrl VALUE line ("dsmUrl: <scheme>://").
    # Real agents (live-captured) open with an index of field NAMES — which
    # mentions dsmUrl with no value — and the value line sits far past 400
    # chars, so judge on the FULL output; the truncation is only for the
    # reported agent_status_raw field. A looser "*dsmUrl*" or "*[Aa]ctivated*"
    # match false-positives on the index line / "not activated" text.
    if printf '%s' "$AGENT_STATUS_FULL" | grep -Eq 'dsmUrl:[[:space:]]*[A-Za-z][A-Za-z0-9+.-]*://'; then
      ACTIVATED=true
    fi
    # Activated, but is it activated against OUR manager? The agent records
    # the endpoint it actually talks to, which on SWP differs from the
    # activation URL in both scheme (https:// vs dsm://) and host (regional
    # agents-NNN.workload.<region>.cloudone.trendmicro.com vs the
    # agents.deepsecurity.trendmicro.com redirector) — live-verified, so
    # exact host:port equality is unsatisfiable. Compare the registrable
    # domain (last two labels) instead: "foreign" means a manager in a
    # different admin domain (e.g. a customer's on-prem DSM), which we must
    # never touch.
    if [ "$ACTIVATED" = true ] && [ -n "$UET_DSM_URL" ]; then
      local expected_host actual_url actual_host
      expected_host="$(_url_host "$UET_DSM_URL")"
      actual_url="$(printf '%s' "$AGENT_STATUS_FULL" \
        | grep -oE 'dsmUrl:[[:space:]]*[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]"]+' \
        | head -n 1 | sed -E 's/^dsmUrl:[[:space:]]*//')"
      actual_host="$(_url_host "$actual_url")"
      if [ -z "$actual_host" ] || [ "$(_domain_suffix "$actual_host")" != "$(_domain_suffix "$expected_host")" ]; then
        FOREIGN=true
      fi
    fi
  fi
  _detect_am_mode
  _set_component_versions
  # The build number cannot change mid-run, so the first source that answers
  # wins and later diagnose passes (the post-heartbeat confirm re-reads) skip
  # the lookup rather than re-querying the agent each time.
  if [ -z "$AGENT_VERSION" ]; then _set_agent_version; fi
  if [ -n "$UET_DSM_URL" ] && [ "${UET_SKIP_MANAGER_CHECK:-0}" != 1 ]; then
    local hp mh mp
    hp="${UET_DSM_URL#dsm://}"; hp="${hp%%/*}"
    mh="${hp%%:*}"; mp="${hp##*:}"; [ "$mp" = "$mh" ] && mp=4120
    if timeout -k 2 5 bash -c "exec 3<>/dev/tcp/$mh/$mp" 2>/dev/null; then
      MANAGER_REACHABLE=true
    else
      MANAGER_REACHABLE=false
      add_blocker "manager_unreachable"
    fi
  fi
}

# healthy() is deliberately AGENT-core only. See the SCOPE note at the top:
# module-level faults are invisible here, which is why the caller must also
# read am_mode / heartbeat_age_sec / notes[] before concluding a host is fine.
healthy() { [ "$INSTALLED" = true ] && [ "$SERVICE_RUNNING" = true ] && [ "$ACTIVATED" = true ]; }

# A core-healthy host that nonetheless has a real, script-unfixable fault. Both
# conditions produced a self-contradictory rev2 result — an agent reported as
# needing no action while carrying a blocker explaining why it was broken.
# `manager_reachable:false` in particular is the likely root cause behind an
# "Offline" console status: the agent is fine locally and simply cannot reach the
# manager, which no amount of restarting or reactivating fixes.
# A heartbeat that errored, or that never moved the agent's own
# lastAgentToManagerSession, counts too: the check-in is the one thing this
# payload does that proves manager comms, so discarding its result is how a host
# whose console status was Offline came back NO_ACTION_NEEDED.
# Only an explicit `false` counts for MANAGER_REACHABLE; null means the probe did
# not run.
degraded() {
  [ "$AM_MODE" = basic ] || [ "$MANAGER_REACHABLE" = false ] \
    || [ "$HEARTBEAT_RESULT" = failed ] || [ "$HEARTBEAT_RESULT" = unconfirmed ]
}

# Record what this run could and could not establish, so a human reading the
# raw JSON off a jump box (with no console cross-check in front of them) is not
# misled by a core-healthy verdict.
annotate() {
  if [ "$AM_MODE" = basic ]; then
    add_note "am_basic_functions_detected"
  elif [ "$AM_MODE" = unknown ] && [ "$SERVICE_RUNNING" = true ]; then
    add_note "modules_not_verified"
  fi
  case "$HEARTBEAT_AGE_SEC" in
    null) ;;
    *) [ "$HEARTBEAT_AGE_SEC" -gt "${UET_HEARTBEAT_STALE_SECS:-1800}" ] && add_note "heartbeat_stale" ;;
  esac
  [ "$SECURE_BOOT" = true ] && add_note "secure_boot_enabled_key_unverified"
  [ "$DISK_FREE_MB" -lt "${UET_MIN_DISK_MB:-500}" ] 2>/dev/null && add_note "low_disk"
  return 0
}

collect_diag() {
  local out
  out="${UET_DIAG_OUT:-/var/tmp/uet-diag-$(hostname -s 2>/dev/null || echo host)-$(date +%s).txt}"
  {
    echo "=== uet diag $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
    echo "--- uname -a ---";            uname -a 2>&1
    echo "--- agent version ---";       echo "$AGENT_VERSION (source: ${AGENT_VERSION_SOURCE:-none})"
    echo "--- dsa_query GetPluginVersion ---"
    timeout -k 10 30 "$AGENT_DIR/dsa_query" -c GetPluginVersion 2>&1 || true
    echo "--- mokutil --sb-state ---";  (command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>&1) || echo "mokutil absent"
    echo "--- lsmod (trend) ---";       lsmod 2>&1 | grep -iE '^(ds_|dsa|tmhook|tmesk|tmevt|tm_|trend)' || echo "none matched"
    echo "--- dsa_query GetAgentStatus ---"
    timeout -k 10 30 "$AGENT_DIR/dsa_query" -c GetAgentStatus 2>&1 || true
    echo "--- dsa_query GetComponentInfo ---"
    timeout -k 10 30 "$AGENT_DIR/dsa_query" -c GetComponentInfo 2>&1 || true
    echo "--- AM / kernel / driver lines from agent logs ---"
    for lf in "$DIAG_DIR/ds_agent.log" "$DIAG_DIR/ds_agent-err.log" \
              /var/log/ds_agent.log /var/log/ds_agent-err.log; do
      [ -r "$lf" ] || continue
      echo "  [$lf]"
      grep -iE '2209|basic function|user mode|kernel|driver|unsupported|KSP' "$lf" 2>/dev/null | tail -40
    done
  } > "$out" 2>&1
  chmod 600 "$out" 2>/dev/null || true
  DIAG_FILE="$out"
  add_action "collect_diag"
  log "diagnostics written to $out"
}

# ---- main ----
case "$MODE" in safe|reinstall|install|refresh) ;; *) add_blocker "bad_mode"; OUTCOME="BLOCKED"; finish 2 ;; esac

diagnose
log "diagnose: installed=$INSTALLED service=$SERVICE_RUNNING activated=$ACTIVATED state=${AGENT_STATE:-?} am_mode=$AM_MODE hb_age=$HEARTBEAT_AGE_SEC kernel=${KERNEL:-?}"

# Foreign-manager agents are never touched, in any mode, dry-run or not.
if [ "$FOREIGN" = true ]; then
  add_blocker "foreign_manager"
  annotate
  OUTCOME="BLOCKED"
  if [ "$DRY_RUN" = 1 ]; then finish 3; else finish 2; fi
fi

# Diagnostics collection is read-only, so it is allowed in --dry-run. It needs
# root to read the agent's logs; without it the bundle is mostly empty.
if [ "$COLLECT_DIAG" = 1 ] && [ "$(id -u)" = "0" ]; then collect_diag; fi

# Enumerate, for --dry-run, the actions a real run of this mode would attempt
# from the current diagnosis, plus any pre-flight blockers already visible.
# Mirrors the Windows payload's Invoke-PlanEnumeration so the result schema keeps
# one shape across platforms; earlier revs emitted empty actions/blockers
# unconditionally in dry run, so a dry run could not tell the operator what
# was about to happen or what was missing.
enumerate_plan() {
  if [ "$MODE" = refresh ]; then
    if [ "$INSTALLED" = true ]; then
      add_planned "service_restart"
      add_planned "heartbeat"
    else
      add_blocker "needs_install_mode"
    fi
    return 0
  fi
  if [ "$INSTALLED" = true ]; then
    if [ "$SERVICE_RUNNING" = false ]; then
      add_planned "service_start"
      if [ -z "$UET_DSM_URL" ] || [ -z "$UET_ACTIVATION_ARGS" ]; then
        # Activation state is unknowable while the service is down; if a
        # reactivation turns out to be needed, it would be blocked.
        add_note "reactivation_unavailable_no_credentials"
      fi
    elif [ "$ACTIVATED" = false ]; then
      add_planned "reactivate"
      if [ -z "$UET_DSM_URL" ] || [ -z "$UET_ACTIVATION_ARGS" ]; then
        add_blocker "no_activation_args"
      fi
    fi
    add_planned "heartbeat"
    if ! healthy && [ "$MODE" = reinstall ]; then
      add_planned "run_deployment_script"
    fi
  else
    case "$MODE" in
      safe) add_blocker "needs_install_mode" ;;
      install) add_planned "run_deployment_script" ;;
    esac
  fi
  case ",$PLANNED," in
    *',"run_deployment_script",'*)
      [ -z "$UET_DEPLOY_B64" ] && add_blocker "no_deployment_script_embedded" ;;
  esac
  return 0
}

if [ "$DRY_RUN" = 1 ]; then
  enumerate_plan
  annotate
  if ! healthy; then OUTCOME="STILL_BROKEN"
  elif degraded; then OUTCOME="DEGRADED"
  else OUTCOME="NO_ACTION_NEEDED"; fi
  finish 3
fi

if [ "$(id -u)" != "0" ]; then
  add_blocker "not_root"; annotate; OUTCOME="BLOCKED"; finish 2
fi

# A check-in, and then proof that it landed. rev4 piped the command's output to
# stderr, threw away its exit status, and recorded the action unconditionally —
# so a production host, whose `dsa_control -m` answered "HTTP Status: 403 - Forbidden
# - untrusted peer.", was reported as NO_ACTION_NEEDED with
# actions:["heartbeat"]. Two independent failure signals are checked, because
# neither alone is sufficient:
#   1. the command failed  — non-zero exit, or a non-2xx "HTTP Status:" line in
#      its own output (dsa_control's exit status is not dependable, and reading
#      an HTTP status code off observed output is arithmetic, not an
#      interpretation of an undocumented field);
#   2. the check-in did not land — the agent's own heartbeat age did not improve.
# Signal 2 only counts once the age is ALSO past the stale threshold: a static
# age on a host that checked in a minute ago is not evidence of failure, and the
# status field can lag a successful session by a few seconds. The confirm re-read
# therefore polls for improvement rather than judging on a single sample.
send_heartbeat() {
  local before out rc code tries
  before="$HEARTBEAT_AGE_SEC"
  HEARTBEAT_RESULT=""; HEARTBEAT_ERROR=""
  out="$(timeout -k 10 60 "$AGENT_DIR/dsa_control" -m 2>&1)"; rc=$?
  [ -n "$out" ] && printf '%s\n' "$out" >&2

  code="$(printf '%s' "$out" | grep -oE 'HTTP Status:[[:space:]]*[0-9]{3}' \
    | head -n 1 | grep -oE '[0-9]{3}$')"
  local failed=false
  [ "$rc" -ne 0 ] && failed=true
  if [ -n "$code" ]; then
    case "$code" in 2??) ;; *) failed=true ;; esac
  fi
  if [ "$failed" = true ]; then
    HEARTBEAT_RESULT="failed"
    HEARTBEAT_ERROR="$(printf '%s' "$out" | grep -v '^[[:space:]]*$' | head -n 1 | head -c 200)"
    [ -z "$HEARTBEAT_ERROR" ] && HEARTBEAT_ERROR="dsa_control -m exited $rc"
    add_note "heartbeat_failed"
    # "untrusted peer" maps to documented events 771 (Contact by Unrecognized
    # Client) / 716 (Reactivation Attempted by Unknown Agent) and its fix is
    # manager-side reactivation settings, not a restart — so it earns a note of
    # its own. Keyed on the observed error STRING, not on any status enum.
    printf '%s' "$out" | grep -qi 'untrusted peer' && add_note "manager_rejected_untrusted_peer"
    return 0
  fi

  add_action "heartbeat"
  HEARTBEAT_RESULT="ok"
  tries="${UET_HEARTBEAT_CONFIRM_TRIES:-3}"
  while [ "$tries" -gt 0 ]; do
    sleep "${UET_SLEEP_SECS:-5}"
    diagnose
    case "$before$HEARTBEAT_AGE_SEC" in
      *null*) break ;;
    esac
    [ "$HEARTBEAT_AGE_SEC" -lt "$before" ] && break
    tries=$((tries-1))
  done
  case "$before$HEARTBEAT_AGE_SEC" in
    *null*) return 0 ;;
  esac
  if [ "$HEARTBEAT_AGE_SEC" -ge "$before" ] \
     && [ "$HEARTBEAT_AGE_SEC" -gt "${UET_HEARTBEAT_STALE_SECS:-1800}" ]; then
    HEARTBEAT_RESULT="unconfirmed"
    add_note "heartbeat_not_confirmed"
  fi
  return 0
}

# A core-healthy host still gets a check-in. This path previously returned
# NO_ACTION_NEEDED before the fix ladder ran, which meant the one safe,
# idempotent action that clears the module-level faults this engagement is
# chasing (MQTT Connection Offline, Smart Protection Server Disconnected) never
# fired on precisely the hosts it would have helped. send_heartbeat re-reads
# status afterwards and refuses to call an unproven check-in a success, so this
# path can now legitimately end in DEGRADED.
#
# `refresh` is exempt: its entire purpose is to re-attempt a driver load on a
# host that IS core-healthy but has Anti-Malware in basic-functions mode, so
# returning early here would make the mode a no-op.
if [ "$MODE" != refresh ] && healthy; then
  send_heartbeat
  annotate
  if degraded; then OUTCOME="DEGRADED"; else OUTCOME="NO_ACTION_NEEDED"; fi
  finish 0
fi

# ---- fix ladder ----
safe_fixes() {
  if [ "$INSTALLED" = true ] && [ "$SERVICE_RUNNING" = false ]; then
    log "starting ds_agent service"
    if command -v systemctl >/dev/null 2>&1; then systemctl start ds_agent >&2 2>&1; else service ds_agent start >&2 2>&1; fi
    add_action "service_start"
    # dsa_query needs a few seconds after a service start before it reports
    # status; poll for readiness instead of misreading "not ready yet" as
    # "not activated" and escalating to an unnecessary reactivation
    # (live-verified failure mode).
    tries="${UET_READY_TRIES:-6}"
    while [ "$tries" -gt 0 ]; do
      sleep "${UET_SLEEP_SECS:-5}"
      diagnose
      [ "$ACTIVATED" = true ] && break
      tries=$((tries-1))
    done
  fi
  if [ "$INSTALLED" = true ] && [ "$SERVICE_RUNNING" = true ] && [ "$ACTIVATED" = false ]; then
    if [ -n "$UET_DSM_URL" ] && [ -n "$UET_ACTIVATION_ARGS" ]; then
      log "reactivating agent"
      # No `dsa_control -r` first: reset deactivates the agent (destructive
      # if the diagnosis was wrong), and a credentialed -a activates a
      # deactivated agent without it. $UET_ACTIVATION_ARGS is deliberately
      # unquoted: space-separated tenantID:/token: tokens (no inner spaces);
      # a bare -a without them cannot activate against multi-tenant SWP.
      # shellcheck disable=SC2086
      timeout -k 10 300 "$AGENT_DIR/dsa_control" -a "$UET_DSM_URL" $UET_ACTIVATION_ARGS >&2 || true
      add_action "reactivate"
      sleep "${UET_SLEEP_SECS:-10}"
      diagnose
    else
      add_blocker "no_activation_args"
    fi
  fi
  if [ "$INSTALLED" = true ] && [ "$SERVICE_RUNNING" = true ] && [ "$ACTIVATED" = true ]; then
    send_heartbeat
  fi
}

# `refresh` re-attempts the kernel driver load, for a host whose kernel support
# package has since arrived. It restarts ds_agent, which briefly drops
# protection — that is why it is an explicit mode and never part of the ladder.
# It cannot help a kernel Trend ships no AM driver for (a Δ-marked kernel in the
# supported-kernels list); those need a kernel change, not a restart.
refresh_driver() {
  if [ "$INSTALLED" = false ]; then add_blocker "needs_install_mode"; return 1; fi
  log "restarting ds_agent to re-attempt driver load"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart ds_agent >&2 2>&1 || true
  else
    service ds_agent restart >&2 2>&1 || true
  fi
  add_action "service_restart"
  tries="${UET_READY_TRIES:-6}"
  while [ "$tries" -gt 0 ]; do
    sleep "${UET_SLEEP_SECS:-5}"
    diagnose
    [ "$ACTIVATED" = true ] && break
    tries=$((tries-1))
  done
  [ "$ACTIVATED" = true ] && send_heartbeat
  return 0
}

run_deployment_script() {
  if [ -z "$UET_DEPLOY_B64" ]; then
    add_blocker "no_deployment_script_embedded"; return 1
  fi
  local tmp
  tmp="$(mktemp /tmp/uet-deploy.XXXXXX.sh)"
  printf '%s' "$UET_DEPLOY_B64" | base64 -d > "$tmp"
  chmod 700 "$tmp"
  log "running deployment script $tmp"
  timeout -k 10 900 bash "$tmp" >&2
  local rc=$?
  rm -f "$tmp"
  add_action "run_deployment_script"
  sleep "${UET_SLEEP_SECS:-10}"
  diagnose
  return $rc
}

WAS_INSTALLED="$INSTALLED"
# Only `refresh` can reach here already core-healthy, and it must not then claim
# to have FIXED a host that was never broken.
WAS_HEALTHY=false
healthy && WAS_HEALTHY=true

if [ "$MODE" = refresh ]; then
  refresh_driver || true
else
  safe_fixes
  if ! healthy; then
    case "$MODE" in
      install)
        if [ "$INSTALLED" = false ]; then run_deployment_script || true; fi ;;
      reinstall)
        if [ "$INSTALLED" = true ]; then run_deployment_script || true; fi ;;
      safe)
        [ "$INSTALLED" = false ] && add_blocker "needs_install_mode" ;;
    esac
  fi
fi

annotate

if healthy; then
  if degraded; then OUTCOME="DEGRADED"
  elif [ "$WAS_INSTALLED" = false ]; then OUTCOME="INSTALLED"
  elif [ "$WAS_HEALTHY" = true ]; then OUTCOME="NO_ACTION_NEEDED"
  else OUTCOME="FIXED"; fi
  finish 0
fi
OUTCOME="STILL_BROKEN"
finish 0
