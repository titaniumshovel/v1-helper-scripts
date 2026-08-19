from __future__ import annotations
import json
import os
import shutil
import stat
import subprocess
import pytest

PAYLOAD = os.path.join(os.path.dirname(__file__), "..", "..", "payloads", "check-fix-agent.sh")

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


def make_shim(dirpath, name, body):
    p = os.path.join(dirpath, name)
    with open(p, "w") as f:
        f.write("#!/usr/bin/env bash\n" + body)
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    return p


def run_payload(tmp_path, shims: dict, agent_installed: bool, args=None, env=None):
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    for name, body in shims.items():
        make_shim(str(shim_dir), name, body)
    agent_dir = tmp_path / "ds_agent"
    if agent_installed:
        agent_dir.mkdir(exist_ok=True)
        make_shim(
            str(agent_dir),
            "dsa_control",
            'if [ "$1" = "-a" ] && [ -n "${UET_TEST_ACTIVATE_STATE:-}" ]; then touch "$UET_TEST_ACTIVATE_STATE"; fi\necho "ctl $*"\n',
        )
        make_shim(str(agent_dir), "dsa_query", shims.get("__dsa_query__", 'echo "AgentStatus.dsmUrl: dsm://mgr:443/"\n'))
    full_env = dict(os.environ)
    full_env["PATH"] = f"{shim_dir}:{full_env['PATH']}"
    full_env["UET_AGENT_DIR"] = str(agent_dir)
    full_env["UET_SLEEP_SECS"] = "0"
    full_env.update(env or {})
    proc = subprocess.run(["bash", PAYLOAD] + (args or []),
                          capture_output=True, text=True, env=full_env, timeout=60)
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "{}"
    return proc, json.loads(line)


def test_dry_run_healthy_host(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n',
               "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "safe", "--dry-run"],
    )
    assert proc.returncode == 3
    assert res["schema"] == "uet-result/3"
    assert res["dry_run"] is True
    assert res["checks"]["installed"] is True
    assert res["checks"]["service_running"] is True
    assert res["checks"]["activated"] is True
    assert res["outcome"] == "NO_ACTION_NEEDED"


def test_dry_run_not_installed(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": "exit 3\n", "id": "echo 0\n"},
        agent_installed=False,
        args=["--dry-run"],
    )
    assert proc.returncode == 3
    assert res["checks"]["installed"] is False
    assert res["outcome"] == "STILL_BROKEN"


def test_not_root_is_blocked_for_real_run(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": "exit 3\n", "id": "echo 501\n"},
        agent_installed=True,
        args=["--mode", "safe"],
    )
    assert proc.returncode == 2
    assert res["outcome"] == "BLOCKED"
    assert "not_root" in res["blockers"]


def test_single_json_line_on_stdout(tmp_path):
    proc, _ = run_payload(
        tmp_path,
        shims={"systemctl": "exit 0\n", "id": "echo 0\n"},
        agent_installed=True,
        args=["--dry-run"],
    )
    json_lines = [l for l in proc.stdout.strip().splitlines() if l.startswith("{")]
    assert len(json_lines) == 1


def test_safe_mode_starts_stopped_service(tmp_path):
    # systemctl: is-active fails first time, succeeds after "start" ran (state file)
    state = tmp_path / "state"
    shim = f'''
STATE="{state}"
if [ "$1" = "start" ]; then touch "$STATE"; exit 0; fi
if [ "$1" = "is-active" ]; then [ -f "$STATE" ] && exit 0 || exit 3; fi
exit 0
'''
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": shim, "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "safe"],
    )
    assert proc.returncode == 0
    assert "service_start" in res["actions"]
    assert res["outcome"] == "FIXED"


def test_safe_mode_reactivates_unactivated_agent(tmp_path):
    # dsa_query reports no dsmUrl until dsa_control -a has run. Reactivating
    # against a manager requires a manager URL to target; a raw (unpatched)
    # payload has an empty UET_DSM_URL sentinel and must correctly refuse to
    # guess one (see test_no_dsm_url_blocks_reactivation below). So, same
    # technique as test_install_mode_runs_embedded_deploy: patch the sentinel
    # into a throwaway copy of the payload to exercise the reactivation path.
    state = tmp_path / "activated"
    payload_text = open(PAYLOAD).read().replace(
        'UET_DSM_URL=""  # __UET_DSM_URL__', 'UET_DSM_URL="dsm://mgr:443/"')
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    dsa_query = f'[ -f "{state}" ] && echo "AgentStatus.dsmUrl: dsm://mgr:443/" || echo "not activated"\n'
    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", "exit 0\n")
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(
        str(agent_dir), "dsa_control",
        'if [ "$1" = "-a" ] && [ -n "${UET_TEST_ACTIVATE_STATE:-}" ]; then touch "$UET_TEST_ACTIVATE_STATE"; fi\necho "ctl $*"\n',
    )
    make_shim(str(agent_dir), "dsa_query", dsa_query)
    # Credentials arrive via env, which the payload captures before the embedded
    # slots overwrite them. Reactivation needs BOTH a manager URL and
    # tenantID/token: a bare `-a <url>` cannot activate against multi-tenant SWP.
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
               UET_SKIP_MANAGER_CHECK="1",
               UET_ACTIVATION_ARGS="tenantID:T1 token:TOK1",
               UET_TEST_ACTIVATE_STATE=str(state))
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert "reactivate" in res["actions"]
    assert res["outcome"] == "FIXED"


def test_missing_activation_args_blocks_reactivation(tmp_path):
    # Reactivation requires BOTH a manager URL and tenantID/token credentials.
    # An unpatched payload has neither, and the ladder must refuse rather than
    # fire a bare `-a`, which cannot activate against multi-tenant SWP.
    state = tmp_path / "activated"
    dsa_query = f'[ -f "{state}" ] && echo "AgentStatus.dsmUrl: dsm://mgr:443/" || echo "not activated"\n'
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": "exit 0\n", "id": "echo 0\n",
               "__dsa_query__": dsa_query},
        agent_installed=True,
        args=["--mode", "safe"],
        env={"UET_TEST_ACTIVATE_STATE": str(state)},
    )
    assert "reactivate" not in res["actions"]
    assert "no_activation_args" in res["blockers"]
    assert res["outcome"] == "STILL_BROKEN"


def test_no_install_without_install_mode(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": "exit 3\n", "id": "echo 0\n"},
        agent_installed=False,
        args=["--mode", "safe"],
    )
    assert proc.returncode == 0
    assert res["outcome"] == "STILL_BROKEN"
    assert "needs_install_mode" in res["blockers"]
    assert res["actions"] == []


def test_install_mode_runs_embedded_deploy(tmp_path):
    marker = tmp_path / "deployed"
    import base64
    deploy = f'#!/usr/bin/env bash\ntouch "{marker}"\n'
    b64 = base64.b64encode(deploy.encode()).decode()
    payload_text = open(PAYLOAD).read().replace(
        'UET_DEPLOY_B64=""  # __UET_DEPLOY_B64__', f'UET_DEPLOY_B64="{b64}"')
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)
    # run patched copy directly
    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", "exit 3\n")
    make_shim(str(shim_dir), "id", "echo 0\n")
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(tmp_path / "ds_agent"), UET_SLEEP_SECS="0")
    proc = subprocess.run(["bash", str(patched), "--mode", "install"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert marker.exists()
    assert "run_deployment_script" in res["actions"]
    # agent still won't look installed afterwards (shim doesn't create it) -> STILL_BROKEN is honest
    assert res["outcome"] in ("INSTALLED", "STILL_BROKEN")


def test_bare_mode_flag_is_blocked(tmp_path):
    # `--mode` with no value must not crash on unbound $2 under `set -u`,
    # and must not spin forever on a stuck `shift 2`.
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": "exit 0\n", "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode"],
    )
    json_lines = [l for l in proc.stdout.strip().splitlines() if l.startswith("{")]
    assert len(json_lines) == 1
    assert proc.returncode == 2
    assert res["outcome"] == "BLOCKED"
    assert "bad_mode" in res["blockers"]


def _patch_sentinels(dsm_url=None, deploy_b64=None):
    text = open(PAYLOAD).read()
    if dsm_url is not None:
        text = text.replace('UET_DSM_URL=""  # __UET_DSM_URL__', f'UET_DSM_URL="{dsm_url}"')
    if deploy_b64 is not None:
        text = text.replace('UET_DEPLOY_B64=""  # __UET_DEPLOY_B64__', f'UET_DEPLOY_B64="{deploy_b64}"')
    return text


def test_foreign_manager_real_run_is_blocked(tmp_path):
    # dsa_query reports activation against a manager that does not match the
    # embedded UET_DSM_URL sentinel. The payload must refuse to touch this
    # agent at all: no reactivate, no heartbeat, just a block.
    payload_text = _patch_sentinels(dsm_url="dsm://mgr:443/")
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    make_shim(str(agent_dir), "dsa_query", 'echo "AgentStatus.dsmUrl: dsm://foreignmgr:443/"\n')
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
               UET_SKIP_MANAGER_CHECK="1")
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert proc.returncode == 2
    assert res["outcome"] == "BLOCKED"
    assert "foreign_manager" in res["blockers"]
    assert "reactivate" not in res["actions"]
    assert "heartbeat" not in res["actions"]


def test_foreign_manager_dry_run_is_blocked(tmp_path):
    payload_text = _patch_sentinels(dsm_url="dsm://mgr:443/")
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    make_shim(str(agent_dir), "dsa_query", 'echo "AgentStatus.dsmUrl: dsm://foreignmgr:443/"\n')
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
               UET_SKIP_MANAGER_CHECK="1")
    proc = subprocess.run(["bash", str(patched), "--mode", "safe", "--dry-run"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert proc.returncode == 3
    assert res["outcome"] == "BLOCKED"
    assert "foreign_manager" in res["blockers"]


def test_matching_manager_is_not_foreign(tmp_path):
    # Same manager the sentinel expects: must NOT be flagged foreign, and
    # since the agent is already healthy, must be a clean no-op.
    payload_text = _patch_sentinels(dsm_url="dsm://mgr:443/")
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    make_shim(str(agent_dir), "dsa_query", 'echo "AgentStatus.dsmUrl: dsm://mgr:443/"\n')
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
               UET_SKIP_MANAGER_CHECK="1")
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert proc.returncode == 0
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "foreign_manager" not in res["blockers"]


def test_foreign_manager_same_host_different_port_not_foreign(tmp_path):
    # POLICY CHANGE (live-verified 2026-07-08): the agent records the manager
    # endpoint it actually talks to, which on SWP differs from the activation
    # URL in scheme AND host — exact host:port equality flags every correctly
    # activated agent as foreign. Managers are now compared by registrable
    # domain, so the same host on a different port is the same admin realm,
    # NOT foreign. (This supersedes the old substring/port-prefix concern:
    # domain comparison never does substring matching at all.)
    payload_text = _patch_sentinels(dsm_url="dsm://mgr:443/")
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    make_shim(str(agent_dir), "dsa_query", 'echo "AgentStatus.dsmUrl: dsm://mgr:4433/"\n')
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
               UET_SKIP_MANAGER_CHECK="1")
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert proc.returncode == 0
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "foreign_manager" not in res["blockers"]


def test_reinstall_mode_runs_deploy_when_reactivation_fails(tmp_path):
    # Agent installed and service running, but dsa_query never reports
    # activation even after a reactivate attempt (no UET_TEST_ACTIVATE_STATE).
    # --mode reinstall must fall through to the embedded deployment script
    # because installed=true; --mode safe with the same setup must not.
    marker = tmp_path / "deployed"
    import base64
    deploy = f'#!/usr/bin/env bash\ntouch "{marker}"\n'
    b64 = base64.b64encode(deploy.encode()).decode()
    payload_text = _patch_sentinels(dsm_url="dsm://mgr:443/", deploy_b64=b64)
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    make_shim(str(agent_dir), "dsa_query", 'echo "not activated"\n')
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
               UET_SKIP_MANAGER_CHECK="1")

    proc = subprocess.run(["bash", str(patched), "--mode", "reinstall"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert "run_deployment_script" in res["actions"]
    assert marker.exists()

    # Same setup, safe mode: must not touch the deployment script.
    marker.unlink()
    proc2 = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=env, timeout=60)
    res2 = json.loads(proc2.stdout.strip().splitlines()[-1])
    assert "run_deployment_script" not in res2["actions"]
    assert not marker.exists()


def test_add_blocker_is_idempotent(tmp_path):
    # manager_unreachable must be added at most once even though diagnose()
    # runs twice within a single invocation (the initial diagnose, then again
    # after safe_fixes starts the stopped service) — add_blocker must dedupe
    # rather than appending a duplicate entry each time it fires.
    state = tmp_path / "state"
    payload_text = _patch_sentinels(dsm_url="dsm://127.0.0.1:1/")
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    # systemctl: is-active fails first time, succeeds after "start" ran
    # (same state-file technique as test_safe_mode_starts_stopped_service).
    shim = f'''
STATE="{state}"
if [ "$1" = "start" ]; then touch "$STATE"; exit 0; fi
if [ "$1" = "is-active" ]; then [ -f "$STATE" ] && exit 0 || exit 3; fi
exit 0
'''
    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", shim)
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    make_shim(str(agent_dir), "dsa_query", 'echo "not activated"\n')
    # This test needs the reachability probe ON — the duplicate blocker it
    # checks for is produced by it. 127.0.0.1:1 refuses instantly, so it stays
    # offline and deterministic, and the agent reports unactivated so the
    # foreign-manager check (needs activated=true) cannot short-circuit first.
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0")
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    assert res["blockers"].count("manager_unreachable") == 1


def test_service_start_waits_for_query_readiness(tmp_path):
    # Live-verified failure (TrendAI-East 2026-07-08): right after a service
    # start, dsa_query needs several seconds before it reports status; a single
    # post-start diagnose misreads "not ready" as "not activated" and escalates
    # to reactivation. The payload must poll for readiness instead.
    state = tmp_path / "state"
    counter = tmp_path / "count"
    systemctl = f'''
STATE="{state}"
if [ "$1" = "start" ]; then touch "$STATE"; exit 0; fi
if [ "$1" = "is-active" ]; then [ -f "$STATE" ] && exit 0 || exit 3; fi
exit 0
'''
    dsa_query = f'''
C="{counter}"
n=$(cat "$C" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$C"
if [ "$n" -lt 3 ]; then echo "not activated"; else echo "AgentStatus.dsmUrl: dsm://mgr:443/"; fi
'''
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": systemctl, "id": "echo 0\n",
               "__dsa_query__": dsa_query},
        agent_installed=True,
        args=["--mode", "safe"],
    )
    assert res["outcome"] == "FIXED"
    assert "service_start" in res["actions"]
    assert "reactivate" not in res["actions"]


def _run_reactivation_case(tmp_path, activation_args_sentinel=True):
    """Shared harness: running agent, persistently-unactivated until
    dsa_control -a runs; dsa_control logs every invocation to ctl.log."""
    state = tmp_path / "activated"
    ctl_log = tmp_path / "ctl.log"
    payload_text = _patch_sentinels(dsm_url="dsm://mgr:443/")
    if activation_args_sentinel:
        payload_text = payload_text.replace(
            'UET_ACTIVATION_ARGS=""  # __UET_ACTIVATION_ARGS__',
            'UET_ACTIVATION_ARGS="tenantID:T-1 token:K-1"')
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)

    dsa_query = f'[ -f "{state}" ] && echo "AgentStatus.dsmUrl: dsm://mgr:443/" || echo "not activated"\n'
    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", "exit 0\n")
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(
        str(agent_dir), "dsa_control",
        f'echo "$*" >> "{ctl_log}"\n'
        'if [ "$1" = "-a" ] && [ -n "${UET_TEST_ACTIVATE_STATE:-}" ]; then touch "$UET_TEST_ACTIVATE_STATE"; fi\n'
        'echo "ctl $*"\n',
    )
    make_shim(str(agent_dir), "dsa_query", dsa_query)
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
               UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
               UET_SKIP_MANAGER_CHECK="1",
               UET_TEST_ACTIVATE_STATE=str(state))
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=env, timeout=60)
    res = json.loads(proc.stdout.strip().splitlines()[-1])
    calls = ctl_log.read_text().splitlines() if ctl_log.exists() else []
    return res, calls


def test_reactivation_passes_tenant_credentials(tmp_path):
    # Bare `dsa_control -a dsm://...` cannot activate against multi-tenant
    # SWP (403 "activate agent first" / indefinite hang, live-verified
    # 2026-07-08). The embedded activation args must ride along.
    res, calls = _run_reactivation_case(tmp_path)
    assert res["outcome"] == "FIXED"
    assert "reactivate" in res["actions"]
    activate_calls = [c for c in calls if c.startswith("-a ")]
    assert activate_calls, f"no dsa_control -a call logged: {calls}"
    assert "tenantID:T-1" in activate_calls[0]
    assert "token:K-1" in activate_calls[0]


def test_reactivation_does_not_reset_agent(tmp_path):
    # `dsa_control -r` deactivates the agent — destructive if the diagnosis
    # was wrong, and never necessary before a credentialed -a (live-verified:
    # plain tenanted -a reactivates a deactivated agent fine).
    res, calls = _run_reactivation_case(tmp_path)
    assert not [c for c in calls if c.startswith("-r")], f"reset called: {calls}"


def test_all_timeout_calls_use_kill_flag():
    # GNU timeout without -k sends a single SIGTERM; dsa_control ignores it
    # and timeout then waits forever (live-verified: a `timeout 300
    # dsa_control -a` still running 20+ min later). Every bounded call must
    # pass -k so a KILL follows.
    import re
    text = open(PAYLOAD).read()
    bare = [l.strip() for l in text.splitlines()
            if not l.strip().startswith("#")
            and re.search(r"(^|[^A-Za-z_(])timeout +[0-9]", l)]
    assert bare == [], f"timeout calls missing -k: {bare}"


def test_error_trap_emits_on_uncaught_crash(tmp_path):
    # UET_TEST_FORCE_CRASH forces an early uncaught exit before any normal
    # flow can emit. The EXIT trap must still print exactly one parseable JSON
    # line with outcome ERROR.
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": "exit 0\n", "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "safe"],
        env={"UET_TEST_FORCE_CRASH": "1"},
    )
    json_lines = [l for l in proc.stdout.strip().splitlines() if l.startswith("{")]
    assert len(json_lines) == 1
    assert res["schema"] == "uet-result/3"
    assert res["outcome"] == "ERROR"


def test_json_escape_strips_control_bytes(tmp_path):
    # dsa_query emitting a raw control byte must not break JSON output.
    dsa_query = "printf 'AgentStatus\\x01dsmUrl: dsm://mgr:443/'\n"
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n',
               "id": "echo 0\n",
               "__dsa_query__": dsa_query},
        agent_installed=True,
        args=["--mode", "safe", "--dry-run"],
    )
    assert proc.returncode == 3
    assert res["checks"]["activated"] is True
    assert "\x01" not in res["checks"]["agent_status_raw"]


# ---- real-agent dsa_query output shape (live-captured 2026-07-08) ----
# Real GetAgentStatus output opens with an index of field NAMES; the dsmUrl
# VALUE appears far past 400 chars, and its scheme is https:// (the regional
# workload endpoint), not the dsm:// activation URL from the deploy script.
REAL_QUERY_OUTPUT = (
    "".join(f"AgentStatus.{i}: fieldName{i}\n" for i in range(1, 40))  # >400 chars of index
    + "AgentStatus.agentState: green\n"
    + "AgentStatus.dsmUrl: https://agents-004.workload.us-1.cloudone.trendmicro.com:443/\n"
)


def _run_with_query_output(tmp_path, query_output, dsm_url="dsm://agents.deepsecurity.trendmicro.com:443/",
                           env=None):
    payload_text = _patch_sentinels(dsm_url=dsm_url)
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)
    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    qf = tmp_path / "query_output.txt"
    qf.write_text(query_output)
    make_shim(str(agent_dir), "dsa_query", f'cat "{qf}"\n')
    # Skip the manager reachability probe by default. These tests set a real
    # manager URL to exercise the foreign-manager domain comparison, which used to
    # mean the probe fired a live TCP connect — so the suite silently depended on
    # egress, and now that reachability feeds the outcome it would flip results
    # between a networked and an air-gapped machine. Tests that care about
    # reachability set UET_SKIP_MANAGER_CHECK=0 and point at an unroutable host.
    full_env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
                    UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
                    UET_SKIP_MANAGER_CHECK="1")
    full_env.update(env or {})
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=full_env, timeout=60)
    return proc, json.loads(proc.stdout.strip().splitlines()[-1])


def test_activation_detected_beyond_status_raw_truncation(tmp_path):
    # Activation must be judged on the FULL dsa_query output; the cap applies
    # only to the reported agent_status_raw field. The cap is pinned low here on
    # purpose — the default is now well above the fixture length, so without
    # forcing it this would no longer exercise truncation at all.
    proc, res = _run_with_query_output(tmp_path, REAL_QUERY_OUTPUT,
                                       env={"UET_STATUS_RAW_CAP": "400"})
    assert res["checks"]["activated"] is True
    assert len(res["checks"]["agent_status_raw"]) <= 400
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "foreign_manager" not in res["blockers"]


def test_status_value_fields_are_parsed_not_discarded(tmp_path):
    # The values used to be thrown away with the 400-char truncation, which is
    # why a console-degraded host could only ever look green. agentState must be
    # surfaced even though it sits past the field-name index.
    proc, res = _run_with_query_output(tmp_path, REAL_QUERY_OUTPUT)
    assert res["checks"]["agent_state"] == "green"


def test_index_line_naming_dsmUrl_is_not_activation(tmp_path):
    # The key-index section can NAME the dsmUrl field without a value; only a
    # "dsmUrl: <scheme>://" value line proves activation.
    out = "AgentStatus.5: dsmUrl\nAgentStatus.agentState: red\n"
    proc, res = _run_with_query_output(tmp_path, out)
    assert res["checks"]["activated"] is False


def test_same_vendor_domain_https_manager_is_not_foreign(tmp_path):
    # https://agents-004.workload.us-1.cloudone.trendmicro.com vs the
    # dsm://agents.deepsecurity.trendmicro.com activation URL: same
    # registrable domain -> same manager family -> not foreign.
    proc, res = _run_with_query_output(tmp_path, REAL_QUERY_OUTPUT)
    assert "foreign_manager" not in res["blockers"]


def test_on_prem_manager_is_foreign(tmp_path):
    out = ("AgentStatus.agentState: green\n"
           "AgentStatus.dsmUrl: https://dsm.corp.example.com:4119/\n")
    proc, res = _run_with_query_output(tmp_path, out)
    assert proc.returncode == 2
    assert res["outcome"] == "BLOCKED"
    assert "foreign_manager" in res["blockers"]


# --- schema uet-result/2: module visibility and the heartbeat short-circuit ---

# Mirrors a real agent's value block, captured live from a console-degraded
# RHEL 7 host: agentState is green and the drivers report hooked even though the
# console flags "Anti-Malware Engine with Basic Functions".
LIVE_QUERY_OUTPUT = (
    "".join(f"AgentStatus.{i}: fieldName{i}\n" for i in range(1, 15))
    + "AgentStatus.agentState: green\n"
    + "AgentStatus.auStatus: 2\n"
    + "AgentStatus.driverChecked: 7\n"
    + "AgentStatus.driverHooked: 7\n"
    + "AgentStatus.currentTime: 1785771972\n"
    + "AgentStatus.lastAgentToManagerSession: 1785771571\n"
    + "AgentStatus.dsmUrl: https://agents-004.workload.us-1.cloudone.trendmicro.com:443/\n"
)


def test_core_healthy_host_still_gets_a_heartbeat(tmp_path):
    # Regression guard for the bug this schema bump exists to fix: healthy()
    # short-circuited to NO_ACTION_NEEDED *before* the fix ladder, so the one
    # safe idempotent action that clears MQTT-offline / SPS-disconnected never
    # fired on the hosts it would have helped.
    proc, res = _run_with_query_output(tmp_path, LIVE_QUERY_OUTPUT)
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "heartbeat" in res["actions"]


def test_dry_run_never_sends_a_heartbeat(tmp_path):
    # --dry-run must stay strictly read-only, including the new heartbeat path.
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n',
               "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "safe", "--dry-run"],
    )
    assert proc.returncode == 3
    assert res["actions"] == []


def test_heartbeat_age_is_computed_from_status_fields(tmp_path):
    # Freshness of manager comms, independent of `activated` — which stays true
    # on a host that has silently stopped checking in.
    proc, res = _run_with_query_output(tmp_path, LIVE_QUERY_OUTPUT)
    assert res["checks"]["heartbeat_age_sec"] == 401
    assert res["checks"]["driver_hooked"] == "7"
    assert res["checks"]["au_status"] == "2"
    assert "heartbeat_stale" not in res["notes"]


def test_stale_heartbeat_is_noted(tmp_path):
    out = (LIVE_QUERY_OUTPUT
           .replace("currentTime: 1785771972", "currentTime: 1785871972"))
    proc, res = _run_with_query_output(tmp_path, out)
    assert res["checks"]["heartbeat_age_sec"] > 1800
    assert "heartbeat_stale" in res["notes"]


def test_unverified_modules_are_flagged_not_silently_passed(tmp_path):
    # A core-healthy verdict must say out loud that module state was not
    # checked, so a raw JSON file read off a jump box (with no console
    # cross-check to hand) cannot be mistaken for "the console shows green".
    proc, res = _run_with_query_output(tmp_path, LIVE_QUERY_OUTPUT)
    assert "modules_not_verified" in res["notes"]
    assert res["checks"]["am_mode"] == "unknown"


def test_am_basic_functions_evidence_downgrades_to_degraded(tmp_path):
    # Event 2209 in the agent's own log is the authoritative local artifact for
    # basic-functions mode; there is no dsa_query counter that reports it.
    diag = tmp_path / "diag"
    diag.mkdir()
    (diag / "ds_agent.log").write_text(
        "2026-08-03 10:00:00 [AMSP] event 2209 Anti-Malware engine has only "
        "basic functions available\n")
    proc, res = _run_with_query_output(tmp_path, LIVE_QUERY_OUTPUT,
                                       env={"UET_DIAG_DIR": str(diag)})
    assert res["checks"]["am_mode"] == "basic"
    assert res["outcome"] == "DEGRADED"
    assert "am_basic_functions_detected" in res["notes"]
    assert "modules_not_verified" not in res["notes"]


def test_am_mode_never_claims_kernel_mode(tmp_path):
    # Deliberate asymmetry: absence of basic-functions evidence is NOT proof of
    # kernel mode. Claiming it would rebuild the false confidence that let a
    # console-degraded host report clean.
    proc, res = _run_with_query_output(tmp_path, LIVE_QUERY_OUTPUT)
    assert res["checks"]["am_mode"] in ("unknown", "basic")


def test_kernel_is_reported_for_offline_support_lookup(tmp_path):
    # The Y/Δ supported-kernel verdict is a manager-side lookup, so the payload
    # only has to carry the kernel string back accurately.
    proc, res = _run_with_query_output(tmp_path, LIVE_QUERY_OUTPUT)
    assert res["checks"]["kernel"]


def test_refresh_mode_restarts_service_to_retry_driver_load(tmp_path):
    ctl_log = tmp_path / "systemctl.log"
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": f'echo "$*" >> "{ctl_log}"\n'
                            'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n',
               "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "refresh"],
    )
    calls = ctl_log.read_text() if ctl_log.exists() else ""
    assert "restart ds_agent" in calls
    assert "service_restart" in res["actions"]


def test_bad_mode_still_rejected(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": "exit 0\n", "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "nonsense"],
    )
    assert proc.returncode == 2
    assert "bad_mode" in res["blockers"]


def test_collect_diag_writes_a_bundle(tmp_path):
    out = tmp_path / "diag-out.txt"
    proc, res = _run_with_query_output(
        tmp_path, LIVE_QUERY_OUTPUT,
        env={"UET_COLLECT_DIAG": "1", "UET_DIAG_OUT": str(out)})
    assert out.exists()
    assert res["diag_file"] == str(out)
    assert "collect_diag" in res["actions"]
    body = out.read_text()
    assert "GetAgentStatus" in body


def test_unreachable_manager_is_not_no_action_needed(tmp_path):
    # rev2 could emit NO_ACTION_NEEDED while simultaneously carrying a
    # manager_unreachable blocker — a self-contradictory result. Seen in
    # production on a Windows run across WINHOST01 / WINHOST02 / WINHOST03, all of
    # which the console lists as Offline; an agent that is locally fine but cannot
    # reach the manager is the likely cause, and no restart or reactivation fixes
    # it. The URL keeps the real trendmicro.com domain so the foreign-manager
    # check still passes (a 127.0.0.1 manager reads as a different admin domain
    # and returns BLOCKED first), but port 1 is never reachable either way.
    proc, res = _run_with_query_output(
        tmp_path, LIVE_QUERY_OUTPUT,
        dsm_url="dsm://agents.deepsecurity.trendmicro.com:1/",
        env={"UET_SKIP_MANAGER_CHECK": "0"})
    assert res["checks"]["manager_reachable"] is False
    assert "manager_unreachable" in res["blockers"]
    assert res["outcome"] == "DEGRADED"


def test_skipped_manager_check_does_not_degrade(tmp_path):
    # A probe that never ran must stay null and must not be read as a failure.
    proc, res = _run_with_query_output(tmp_path, LIVE_QUERY_OUTPUT)
    assert res["checks"]["manager_reachable"] is None
    assert "manager_unreachable" not in res["blockers"]
    assert res["outcome"] == "NO_ACTION_NEEDED"


def _run_with_component_info(tmp_path, component_output, status_output=None,
                             env=None):
    # dsa_query shim that answers GetComponentInfo and GetAgentStatus
    # differently, mirroring the real agent.
    payload_text = _patch_sentinels(dsm_url="dsm://agents.deepsecurity.trendmicro.com:443/")
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)
    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", 'echo "ctl $*"\n')
    sf = tmp_path / "status_output.txt"
    sf.write_text(status_output if status_output is not None else LIVE_QUERY_OUTPUT)
    cf = tmp_path / "component_output.txt"
    cf.write_text(component_output)
    make_shim(str(agent_dir), "dsa_query",
              f'if [ "$2" = "GetComponentInfo" ]; then cat "{cf}"; else cat "{sf}"; fi\n')
    full_env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
                    UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
                    UET_SKIP_MANAGER_CHECK="1")
    full_env.update(env or {})
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=full_env, timeout=60)
    return proc, json.loads(proc.stdout.strip().splitlines()[-1])


def test_componentinfo_driver_offline_is_authoritative(tmp_path):
    # Component.AM.mode from GetComponentInfo decides am_mode, before any log
    # grep (live-verified 2026-08-07: separated five genuinely driver-offline
    # hosts from four false positives).
    proc, res = _run_with_component_info(
        tmp_path, "Component.AM.driverOffline: true\nComponent.AM.mode: driver-offline\n")
    assert res["checks"]["am_mode"] == "basic"
    assert res["checks"]["am_evidence"] == "componentinfo:Component.AM.mode=driver-offline"
    assert res["outcome"] == "DEGRADED"
    assert "am_basic_functions_detected" in res["notes"]


def test_componentinfo_am_on_wins_over_stale_log_lines(tmp_path):
    # A recovered host may still carry a historical 2209 line in its log; the
    # agent's own current verdict (mode: on) must win, so the host is not
    # re-flagged forever.
    diag = tmp_path / "diag"
    diag.mkdir()
    (diag / "ds_agent.log").write_text(
        "2026-05-01 10:00:00 [AMSP] event 2209 Anti-Malware engine has only "
        "basic functions available\n")
    proc, res = _run_with_component_info(
        tmp_path, "Component.AM.driverOffline: false\nComponent.AM.mode: on\n",
        env={"UET_DIAG_DIR": str(diag)})
    assert res["checks"]["am_mode"] == "on"
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "am_basic_functions_detected" not in res["notes"]
    assert "modules_not_verified" not in res["notes"]


def test_timestamp_digits_do_not_false_positive_am_basic(tmp_path):
    # Regression, live case 2026-08-07: four healthy hosts were flagged
    # am_basic because the unanchored `2209` grep matched digits inside
    # microsecond timestamps (e.g. "02:24:18.742209"). With GetComponentInfo
    # yielding nothing, the log fallback must not fire on such lines.
    diag = tmp_path / "diag"
    diag.mkdir()
    (diag / "ds_agent.log").write_text(
        "2026-08-06 02:24:18.742209 [-0500]: [Error/1] | tls layer error\n"
        "2026-08-07 08:15:14.220932 [-0500]: [dsa.PluginUtils/5] | no local entry\n")
    proc, res = _run_with_component_info(tmp_path, "", env={"UET_DIAG_DIR": str(diag)})
    assert res["checks"]["am_mode"] == "unknown"
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "am_basic_functions_detected" not in res["notes"]


def test_log_fallback_still_fires_on_real_event_2209(tmp_path):
    # The fallback must keep catching a genuine standalone 2209 event token
    # when GetComponentInfo is unavailable.
    diag = tmp_path / "diag"
    diag.mkdir()
    (diag / "ds_agent.log").write_text(
        "2026-08-03 10:00:00 [AMSP] event 2209 raised\n")
    proc, res = _run_with_component_info(tmp_path, "", env={"UET_DIAG_DIR": str(diag)})
    assert res["checks"]["am_mode"] == "basic"
    assert res["checks"]["am_evidence"].startswith("log:")
    assert res["outcome"] == "DEGRADED"


def test_hex_thread_ids_do_not_false_positive_am_basic(tmp_path):
    # Agent log lines end in hex thread:name tails (e.g.
    # "5B7:7F49F22090700:dsa.MetricsSvc"); 2209 inside a hex ID — adjacent to
    # hex letters on either side — must not trip the fallback.
    diag = tmp_path / "diag"
    diag.mkdir()
    (diag / "ds_agent.log").write_text(
        "2026-08-07 01:10:04 [-0500]: [Error/1] | x509 error | 5B7:2209F700:dsa.MetricsSvc\n"
        "2026-08-07 01:12:04 [-0500]: [Error/1] | x509 error | 5B7:7F2209A00:dsa.Scheduler_0009\n"
        "2026-08-07 01:14:04 [-0500]: [dsa/5] | reg probe 0x2209 ok\n")
    proc, res = _run_with_component_info(tmp_path, "", env={"UET_DIAG_DIR": str(diag)})
    assert res["checks"]["am_mode"] == "unknown"
    assert "am_basic_functions_detected" not in res["notes"]


def test_event_2209_with_punctuation_boundaries_still_matches(tmp_path):
    # Genuine event lines keep matching: space/pipe/parenthesis boundaries.
    diag = tmp_path / "diag"
    diag.mkdir()
    (diag / "ds_agent.log").write_text(
        "2026-08-03 10:00:00 [-0500]: [Warning/2] | event (2209) raised: basic functions\n")
    proc, res = _run_with_component_info(tmp_path, "", env={"UET_DIAG_DIR": str(diag)})
    assert res["checks"]["am_mode"] == "basic"
    assert res["outcome"] == "DEGRADED"


def test_dry_run_stopped_service_enumerates_plan_sh(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": 'if [ "$1" = "is-active" ]; then exit 3; fi\nexit 0\n',
               "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "safe", "--dry-run"],
    )
    assert proc.returncode == 3
    assert res["outcome"] == "STILL_BROKEN"
    assert "service_start" in res["planned"]
    assert "heartbeat" in res["planned"]
    assert res["actions"] == []
    # no creds embedded and none in env: a needed reactivation would be blocked
    assert "reactivation_unavailable_no_credentials" in res["notes"]


def test_dry_run_healthy_plans_heartbeat(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n',
               "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "safe", "--dry-run"],
    )
    assert proc.returncode == 3
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "heartbeat" in res["planned"]
    assert res["actions"] == []


def test_dry_run_refresh_plans_driver_reload_restart(tmp_path):
    proc, res = run_payload(
        tmp_path,
        shims={"systemctl": 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n',
               "id": "echo 0\n"},
        agent_installed=True,
        args=["--mode", "refresh", "--dry-run"],
    )
    assert proc.returncode == 3
    assert "service_restart" in res["planned"]
    assert res["actions"] == []


# --- rev5: heartbeat outcome, agent-version provenance, promoted AM versions ---

# `dsa_query -c GetPluginVersion` is a documented command ("version information
# of the agent and protection modules") but Trend publishes no output schema, so
# the SHAPE of this fixture is synthetic and the payload's parse of it is
# deliberately conservative. What is real: the four-part build format
# (20.0.3.860, read live from the SWP API for Windows hosts seen in production
# on 2026-08-17), and the requirement that a protection MODULE's version must
# never be reported as the agent's. The module line is placed first on purpose,
# so a naive "first version-looking number" parse fails this fixture.
PLUGIN_VERSION_OUTPUT = (
    "PluginVersion.AM: 20.0.3.1234\n"
    "PluginVersion.Agent: 20.0.3.860\n"
    "PluginVersion.FWDPI: 20.0.3.5678\n"
)

# Trimmed verbatim from PRODHOST02's live rev4 `component_info_raw`
# (2026-08-12). Two things matter and both are real: the pattern INDEX is not
# stable across hosts (Spyware/Grayware was pattern.10 on PRODHOST01 and
# pattern.11 here), and the interesting entries sit past the 1200-char reported
# cap — Spyware/Grayware starts at offset 1694 of this fixture.
REAL_COMPONENT_INFO = (
    "Component.AM.cap.Qrestore: true\n"
    "Component.AM.cap.realtime: true\n"
    "Component.AM.cap.spyware: true\n"
    "Component.AM.configurations: 11\n"
    "Component.AM.driverOffline: false\n"
    "Component.AM.licenseExpiry: 2147483647\n"
    "Component.AM.mode: on\n"
    "Component.AM.moduleStatus: -1\n"
    "Component.AM.scan.Manual: 2\n"
    "Component.AM.scan.Quick: 3\n"
    "Component.AM.scan.Realtime: 1\n"
    "Component.AM.scan.Scheduled: 4\n"
    "Component.AM.scanStatus: 4\n"
    "Component.AM.scanType: 0\n"
    "Component.AM.version.engine.ATSE: 24.580.1013\n"
    "Component.AM.version.pattern.1.name: Platform Configuration Pattern\n"
    "Component.AM.version.pattern.1.version: 5.5.1000\n"
    "Component.AM.version.pattern.2.name: Trusted Certificate Authorities Pattern\n"
    "Component.AM.version.pattern.2.version: 1.00007.00\n"
    "Component.AM.version.pattern.3.name: Advanced Threat Correlation Pattern\n"
    "Component.AM.version.pattern.3.version: 1.704.00\n"
    "Component.AM.version.pattern.4.name: IntelliTrap Exception Pattern\n"
    "Component.AM.version.pattern.4.version: 2.469.00\n"
    "Component.AM.version.pattern.5.name: Behavior Monitoring Event Filtering Pattern\n"
    "Component.AM.version.pattern.5.version: 1.2.2144\n"
    "Component.AM.version.pattern.6.name: IntelliTrap Pattern\n"
    "Component.AM.version.pattern.6.version: 0.261.00\n"
    "Component.AM.version.pattern.7.name: Behavior Monitoring Detection Pattern\n"
    "Component.AM.version.pattern.7.version: 2.101.00\n"
    "Component.AM.version.pattern.8.name: Memory Inspection Pattern\n"
    "Component.AM.version.pattern.8.version: 1.301.00\n"
    "Component.AM.version.pattern.9.name: Policy Enforcement Pattern\n"
    "Component.AM.version.pattern.9.version: 1.1.1015\n"
    "Component.AM.version.pattern.10.name: Spyware Active Monitoring Pattern\n"
    "Component.AM.version.pattern.10.version: 1.417.00\n"
    "Component.AM.version.pattern.11.name: Spyware/Grayware Pattern\n"
    "Component.AM.version.pattern.11.version: 18.33\n"
    "Component.AM.version.pattern.12.name: Damage Cleanup Template\n"
    "Component.AM.version.pattern.12.version: 1578\n"
    "Component.AM.version.pattern.13.name: Damage Cleanup Engine Configuration\n"
    "Component.AM.version.pattern.13.version: 17.3\n"
    "Component.AM.version.pattern.14.name: Real-time Scan Flow Pattern\n"
    "Component.AM.version.pattern.14.version: 200005\n"
    "Component.AM.version.pattern.15.name: Smart Scan Agent Pattern\n"
    "Component.AM.version.pattern.15.version: 21.245.00\n"
)


def _run_rev5(tmp_path, query_output=None, component_output=None, dsa_control_body=None,
              plugin_output=None, env=None):
    """A core-healthy Linux host whose dsa_control, GetAgentStatus,
    GetComponentInfo and GetPluginVersion answers are all independently
    controllable. rpm and dpkg-query are shimmed to fail so the agent-version
    cascade is deterministic on any dev box.
    """
    payload_text = _patch_sentinels(dsm_url="dsm://agents.deepsecurity.trendmicro.com:443/")
    patched = tmp_path / "patched.sh"
    patched.write_text(payload_text)
    shim_dir = tmp_path / "bin"; shim_dir.mkdir(exist_ok=True)
    make_shim(str(shim_dir), "systemctl", 'if [ "$1" = "is-active" ]; then exit 0; fi\nexit 0\n')
    make_shim(str(shim_dir), "id", "echo 0\n")
    make_shim(str(shim_dir), "rpm", "exit 1\n")
    make_shim(str(shim_dir), "dpkg-query", "exit 1\n")
    agent_dir = tmp_path / "ds_agent"; agent_dir.mkdir(exist_ok=True)
    make_shim(str(agent_dir), "dsa_control", dsa_control_body or 'echo "ctl $*"\n')
    sf = tmp_path / "status.txt"
    sf.write_text(query_output if query_output is not None else LIVE_QUERY_OUTPUT)
    cf = tmp_path / "component.txt"
    cf.write_text(component_output if component_output is not None else "Component.AM.mode: on\n")
    pf = tmp_path / "plugin.txt"
    pf.write_text(plugin_output if plugin_output is not None else PLUGIN_VERSION_OUTPUT)
    make_shim(str(agent_dir), "dsa_query",
              f'case "$2" in\n'
              f'  GetComponentInfo) cat "{cf}" ;;\n'
              f'  GetPluginVersion) cat "{pf}" ;;\n'
              f'  *) cat "{sf}" ;;\n'
              f'esac\n')
    full_env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}",
                    UET_AGENT_DIR=str(agent_dir), UET_SLEEP_SECS="0",
                    UET_SKIP_MANAGER_CHECK="1")
    full_env.update(env or {})
    proc = subprocess.run(["bash", str(patched), "--mode", "safe"],
                          capture_output=True, text=True, env=full_env, timeout=60)
    return proc, json.loads(proc.stdout.strip().splitlines()[-1])


# heartbeat_age_sec 6083 — PRODHOST01's real post-heartbeat age on 2026-08-12.
STALE_HB_QUERY_OUTPUT = LIVE_QUERY_OUTPUT.replace(
    "currentTime: 1785771972", "currentTime: 1785777654")


def test_failed_heartbeat_is_not_reported_as_no_action_needed(tmp_path):
    # Live case, PRODHOST01 2026-08-12: `dsa_control -m` returned
    # "HTTP Status: 403 - Forbidden - untrusted peer." and rev4 still emitted
    # NO_ACTION_NEEDED with actions:["heartbeat"], because send_heartbeat threw
    # the command's output at stderr and recorded the action unconditionally.
    proc, res = _run_rev5(
        tmp_path,
        dsa_control_body='if [ "$1" = "-m" ]; then\n'
                         '  echo "HTTP Status: 403 - Forbidden - untrusted peer."\n'
                         '  exit 1\nfi\necho "ctl $*"\n')
    assert res["checks"]["heartbeat_result"] == "failed"
    assert "heartbeat" not in res["actions"]
    assert "heartbeat_failed" in res["notes"]
    assert "untrusted peer" in res["checks"]["heartbeat_error"]
    assert res["outcome"] == "DEGRADED"


def test_heartbeat_failure_is_caught_even_when_exit_status_is_zero(tmp_path):
    # dsa_control's exit status is not a dependable failure signal, so a non-2xx
    # "HTTP Status:" line in its own output counts too. Reading an HTTP status
    # code is arithmetic on an observed string, not interpretation of an
    # undocumented field.
    proc, res = _run_rev5(
        tmp_path,
        dsa_control_body='if [ "$1" = "-m" ]; then\n'
                         '  echo "HTTP Status: 403 - Forbidden - untrusted peer."\n'
                         '  exit 0\nfi\necho "ctl $*"\n')
    assert res["checks"]["heartbeat_result"] == "failed"
    assert "heartbeat_failed" in res["notes"]
    # "untrusted peer" has its own remediation (manager-side reactivation
    # settings, not a restart), so it earns a distinct note.
    assert "manager_rejected_untrusted_peer" in res["notes"]
    assert res["outcome"] == "DEGRADED"


def test_heartbeat_that_does_not_advance_the_session_is_unconfirmed(tmp_path):
    # The structural half of the same defect: a heartbeat can exit clean and
    # still not land. PRODHOST01's age was still 6083s after the
    # post-heartbeat re-read, and rev4 read that as NO_ACTION_NEEDED.
    proc, res = _run_rev5(tmp_path, query_output=STALE_HB_QUERY_OUTPUT)
    assert res["checks"]["heartbeat_age_sec"] == 6083
    assert res["checks"]["heartbeat_result"] == "unconfirmed"
    assert "heartbeat_not_confirmed" in res["notes"]
    assert "heartbeat" in res["actions"]  # the command itself did succeed
    assert res["outcome"] == "DEGRADED"


def test_fresh_heartbeat_with_no_room_to_improve_is_not_flagged(tmp_path):
    # Guard on the false positive the confirm check could introduce: a host that
    # checked in 401s ago is fresh, so an unchanged age is not evidence of a
    # failed check-in. "Did not improve" only counts once the age is also past
    # the stale threshold.
    proc, res = _run_rev5(tmp_path)
    assert res["checks"]["heartbeat_age_sec"] == 401
    assert res["checks"]["heartbeat_result"] == "ok"
    assert "heartbeat_not_confirmed" not in res["notes"]
    assert res["outcome"] == "NO_ACTION_NEEDED"


def test_agent_version_falls_back_to_documented_plugin_query(tmp_path):
    # rpm/dpkg are the primary sources; when neither answers, the documented
    # GetPluginVersion query is the fallback. The reported string must carry its
    # provenance, and a module's version must not be mistaken for the agent's.
    proc, res = _run_rev5(tmp_path)
    assert res["checks"]["agent_version"] == "20.0.3.860"
    assert res["checks"]["agent_version_source"] == "GetPluginVersion"


def test_engine_and_pattern_versions_are_promoted_to_first_class_fields(tmp_path):
    # rev4 captured these only inside component_info_raw, capped at 1200 chars
    # and truncated mid-field on healthy hosts seen in production, so comparing
    # engine/pattern levels between two hosts meant hand-parsing a truncated
    # blob. Pairs are keyed by NAME because the index shifts between hosts.
    proc, res = _run_rev5(tmp_path, component_output=REAL_COMPONENT_INFO)
    assert res["checks"]["am_engine_atse"] == "24.580.1013"
    pats = dict(p.split("=", 1) for p in res["checks"]["am_patterns"].split(";"))
    assert pats["Spyware/Grayware Pattern"] == "18.33"
    assert pats["Damage Cleanup Template"] == "1578"
    assert pats["Smart Scan Agent Pattern"] == "21.245.00"
    # ...and all of that came from past the reported cap.
    assert len(res["checks"]["component_info_raw"]) <= 1200
    assert REAL_COMPONENT_INFO.index("Spyware/Grayware Pattern") > 1200
