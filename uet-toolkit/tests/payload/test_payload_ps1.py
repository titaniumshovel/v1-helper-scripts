from __future__ import annotations
import base64
import json
import os
import shutil
import subprocess
import pytest

PAYLOAD = os.path.join(os.path.dirname(__file__), "..", "..", "payloads", "check-fix-agent.ps1")

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh required")


def _patch_sentinels(dsm_url=None, deploy_b64=None, payload=PAYLOAD):
    text = open(payload).read()
    if dsm_url is not None:
        text = text.replace('$UetDsmUrl = ""  # __UET_DSM_URL__', f'$UetDsmUrl = "{dsm_url}"')
    if deploy_b64 is not None:
        text = text.replace('$UetDeployB64 = ""  # __UET_DEPLOY_B64__', f'$UetDeployB64 = "{deploy_b64}"')
    return text


def make_agent_dir(tmp_path, installed, dsa_query_output='AgentStatus.dsmUrl: dsm://mgr:443/', name="dsagent"):
    agent_dir = tmp_path / name
    if installed:
        agent_dir.mkdir(exist_ok=True)
        (agent_dir / "dsa_control.cmd").write_text("@echo ctl %*\n")
        (agent_dir / "dsa_query.cmd").write_text(f"@echo {dsa_query_output}\n")
        # pwsh on POSIX can't run .cmd; the payload calls sentinel-named .ps1
        # shims when present.
        (agent_dir / "dsa_control.ps1").write_text(
            'if ($args[0] -eq "-a" -and $env:UET_TEST_ACTIVATE_STATE) '
            '{ New-Item -ItemType File -Force $env:UET_TEST_ACTIVATE_STATE | Out-Null }\n'
            'Write-Output "ctl $args"'
        )
        (agent_dir / "dsa_query.ps1").write_text(
            'if ($env:UET_TEST_ACTIVATE_STATE -and -not (Test-Path $env:UET_TEST_ACTIVATE_STATE)) '
            '{ Write-Output "not activated" } '
            f'else {{ Write-Output "{dsa_query_output}" }}'
        )
    return agent_dir


def run_ps(tmp_path, agent_installed: bool, args=None, env=None, payload=PAYLOAD,
           agent_dir=None, dsa_query_output='AgentStatus.dsmUrl: dsm://mgr:443/'):
    if agent_dir is None:
        agent_dir = make_agent_dir(tmp_path, agent_installed, dsa_query_output=dsa_query_output)
    full_env = dict(os.environ)
    full_env["UET_AGENT_DIR"] = str(agent_dir)
    full_env["UET_IS_ADMIN"] = full_env.get("UET_IS_ADMIN", "1")  # test override
    full_env["UET_SLEEP_SECS"] = "0"
    full_env.update(env or {})
    proc = subprocess.run(["pwsh", "-NoProfile", "-File", payload] + (args or []),
                          capture_output=True, text=True, env=full_env, timeout=120)
    lines = [l for l in proc.stdout.strip().splitlines() if l.startswith("{")]
    return proc, (json.loads(lines[-1]) if lines else {})


def test_dry_run_healthy(tmp_path):
    proc, res = run_ps(tmp_path, agent_installed=True,
                       args=["-Mode", "safe", "-DryRun"],
                       env={"UET_SERVICE_STATE": "Running"})
    assert proc.returncode == 3
    assert res["schema"] == "uet-result/3"
    assert res["checks"]["installed"] is True
    assert res["outcome"] == "NO_ACTION_NEEDED"
    # dry run must enumerate what a real run would do (rev2 gap #4)
    assert "heartbeat" in res["planned"]
    assert res["actions"] == []


def test_not_installed_dry_run(tmp_path):
    proc, res = run_ps(tmp_path, agent_installed=False, args=["-DryRun"],
                       env={"UET_SERVICE_STATE": "None"})
    assert proc.returncode == 3
    assert res["checks"]["installed"] is False
    assert res["outcome"] == "STILL_BROKEN"


def test_not_admin_blocked(tmp_path):
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_IS_ADMIN": "0", "UET_SERVICE_STATE": "Stopped"})
    assert proc.returncode == 2
    assert res["outcome"] == "BLOCKED" and "not_admin" in res["blockers"]


def test_single_json_line_on_stdout(tmp_path):
    proc, _ = run_ps(tmp_path, agent_installed=True, args=["-DryRun"],
                     env={"UET_SERVICE_STATE": "Running"})
    json_lines = [l for l in proc.stdout.strip().splitlines() if l.startswith("{")]
    assert len(json_lines) == 1


def test_install_mode_runs_embedded_deploy(tmp_path):
    marker = tmp_path / "deployed.txt"
    deploy = f'New-Item -ItemType File -Force "{marker}" | Out-Null'
    b64 = base64.b64encode(deploy.encode()).decode()
    text = open(PAYLOAD).read().replace(
        '$UetDeployB64 = ""  # __UET_DEPLOY_B64__', f'$UetDeployB64 = "{b64}"')
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    proc, res = run_ps(tmp_path, agent_installed=False, args=["-Mode", "install"],
                       env={"UET_SERVICE_STATE": "None"}, payload=str(patched))
    assert marker.exists()
    assert "run_deployment_script" in res["actions"]


def test_bad_mode_is_blocked_without_bypassing_contract(tmp_path):
    # No [ValidateSet]: an invalid -Mode must still produce exactly one JSON
    # line on stdout and a clean exit, not a parameter-binding error.
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "bogus"],
                       env={"UET_SERVICE_STATE": "Running"})
    assert proc.returncode == 2
    assert res.get("schema") == "uet-result/3"
    assert res["outcome"] == "BLOCKED"
    assert "bad_mode" in res["blockers"]


def test_no_install_without_install_mode(tmp_path):
    proc, res = run_ps(tmp_path, agent_installed=False, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "None"})
    assert proc.returncode == 0
    assert res["outcome"] == "STILL_BROKEN"
    assert "needs_install_mode" in res["blockers"]
    assert res["actions"] == []


def test_reinstall_mode_runs_deploy_when_reactivation_fails(tmp_path):
    # Agent installed and service running, but dsa_query never reports
    # activation even after a reactivate attempt. -Mode reinstall must fall
    # through to the embedded deployment script because installed=true;
    # -Mode safe with the same setup must not.
    marker = tmp_path / "deployed.txt"
    deploy = f'New-Item -ItemType File -Force "{marker}" | Out-Null'
    b64 = base64.b64encode(deploy.encode()).decode()
    text = _patch_sentinels(dsm_url="dsm://mgr:443/", deploy_b64=b64)
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)

    agent_dir = make_agent_dir(tmp_path, True, dsa_query_output="not activated")
    env = {"UET_SERVICE_STATE": "Running"}

    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "reinstall"], env=env,
                       payload=str(patched), agent_dir=agent_dir)
    assert "run_deployment_script" in res["actions"]
    assert marker.exists()

    marker.unlink()
    proc2, res2 = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"], env=env,
                        payload=str(patched), agent_dir=agent_dir)
    assert "run_deployment_script" not in res2["actions"]
    assert not marker.exists()


def test_foreign_manager_same_host_different_port_not_foreign(tmp_path):
    # POLICY CHANGE (live-verified 2026-07-08): managers are compared by
    # registrable domain, not exact host:port — the agent records the endpoint
    # it actually talks to, which on SWP differs from the activation URL in
    # scheme AND host. Same host, different port = same admin realm.
    text = _patch_sentinels(dsm_url="dsm://mgr:443/")
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Running", "UET_SKIP_MANAGER_CHECK": "1"},
                       payload=str(patched),
                       dsa_query_output="AgentStatus.dsmUrl: dsm://mgr:4433/")
    assert proc.returncode == 0
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "foreign_manager" not in res["blockers"]
    # a core-healthy host still gets a check-in (rev2 skipped it)
    assert "heartbeat" in res["actions"]


def test_matching_manager_case_and_slash_variance_is_not_foreign(tmp_path):
    text = _patch_sentinels(dsm_url="DSM://MGR:443")
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Running", "UET_SKIP_MANAGER_CHECK": "1"},
                       payload=str(patched),
                       dsa_query_output="AgentStatus.dsmUrl: dsm://mgr:443/")
    assert proc.returncode == 0
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "foreign_manager" not in res["blockers"]


def test_foreign_manager_dry_run_is_blocked(tmp_path):
    text = _patch_sentinels(dsm_url="dsm://mgr:443/")
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe", "-DryRun"],
                       env={"UET_SERVICE_STATE": "Running"}, payload=str(patched),
                       dsa_query_output="AgentStatus.dsmUrl: dsm://foreignmgr:443/")
    assert proc.returncode == 3
    assert res["outcome"] == "BLOCKED"
    assert "foreign_manager" in res["blockers"]


def test_mode_is_case_insensitive_and_normalized(tmp_path):
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "SAFE", "-DryRun"],
                       env={"UET_SERVICE_STATE": "Running"})
    assert proc.returncode == 3
    assert res["mode"] == "safe"

    proc2, res2 = run_ps(tmp_path, agent_installed=True, args=["-Mode", "BOGUS"],
                        env={"UET_SERVICE_STATE": "Running"})
    assert proc2.returncode == 2
    assert res2["outcome"] == "BLOCKED"
    assert "bad_mode" in res2["blockers"]


def test_control_bytes_stripped_from_agent_status(tmp_path):
    # dsa_query .ps1 shim emitting a raw control byte must not break JSON output.
    agent_dir = tmp_path / "dsagent"
    agent_dir.mkdir()
    (agent_dir / "dsa_control.cmd").write_text("@echo ctl %*\n")
    (agent_dir / "dsa_query.cmd").write_text("@echo AgentStatus\n")
    (agent_dir / "dsa_control.ps1").write_text('Write-Output "ctl $args"')
    (agent_dir / "dsa_query.ps1").write_text(
        'Write-Output ("AgentStatus" + [char]1 + "dsmUrl: dsm://mgr:443/")'
    )
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe", "-DryRun"],
                       env={"UET_SERVICE_STATE": "Running"}, agent_dir=agent_dir)
    assert proc.returncode == 3
    assert res["checks"]["activated"] is True
    assert "\x01" not in res["checks"]["agent_status_raw"]


def test_error_trap_emits_on_uncaught_crash(tmp_path):
    # UET_TEST_FORCE_CRASH forces a terminating error before any normal flow
    # can emit. The finally block must still print exactly one parseable JSON
    # line with outcome ERROR.
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Running", "UET_TEST_FORCE_CRASH": "1"})
    json_lines = [l for l in proc.stdout.strip().splitlines() if l.startswith("{")]
    assert len(json_lines) == 1
    assert res["schema"] == "uet-result/3"
    assert res["outcome"] == "ERROR"


def test_blocker_dedupe_manager_unreachable(tmp_path):
    # manager_unreachable must be added at most once even though Invoke-Diagnose
    # runs multiple times within a single invocation (initial diagnose, again
    # after the service is started, and again after a reactivate attempt).
    text = _patch_sentinels(dsm_url="dsm://127.0.0.1:1/")
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Stopped"}, payload=str(patched),
                       dsa_query_output="not activated")
    assert res["blockers"].count("manager_unreachable") == 1


def test_service_start_waits_for_query_readiness(tmp_path):
    # Mirror of the sh test: dsa_query needs time after a service start; a
    # single post-start diagnose misreads "not ready" as "not activated" and
    # escalates to reactivation.
    counter = tmp_path / "count.txt"
    agent_dir = make_agent_dir(tmp_path, True)
    (agent_dir / "dsa_query.ps1").write_text(
        f'$c = "{counter}"\n'
        '$n = if (Test-Path $c) { [int](Get-Content $c) } else { 0 }\n'
        '$n++; Set-Content $c $n\n'
        'if ($n -lt 3) { Write-Output "not activated" } '
        'else { Write-Output "AgentStatus.dsmUrl: dsm://mgr:443/" }\n'
    )
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Stopped"}, agent_dir=agent_dir)
    assert res["outcome"] == "FIXED"
    assert "service_start" in res["actions"]
    assert "reactivate" not in res["actions"]


def _run_reactivation_case_ps1(tmp_path):
    state = tmp_path / "activated.txt"
    ctl_log = tmp_path / "ctl.log"
    text = _patch_sentinels(dsm_url="dsm://mgr:443/").replace(
        '$UetActivationArgs = ""  # __UET_ACTIVATION_ARGS__',
        '$UetActivationArgs = "tenantID:T-1 token:K-1"')
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)

    agent_dir = make_agent_dir(tmp_path, True)
    (agent_dir / "dsa_control.ps1").write_text(
        f'Add-Content "{ctl_log}" ($args -join " ")\n'
        'if ($args[0] -eq "-a" -and $env:UET_TEST_ACTIVATE_STATE) '
        '{ New-Item -ItemType File -Force $env:UET_TEST_ACTIVATE_STATE | Out-Null }\n'
        'Write-Output "ctl $args"\n'
    )
    (agent_dir / "dsa_query.ps1").write_text(
        'if ($env:UET_TEST_ACTIVATE_STATE -and (Test-Path $env:UET_TEST_ACTIVATE_STATE)) '
        '{ Write-Output "AgentStatus.dsmUrl: dsm://mgr:443/" } '
        'else { Write-Output "not activated" }\n'
    )
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Running",
                            "UET_TEST_ACTIVATE_STATE": str(state),
                            "UET_SKIP_MANAGER_CHECK": "1"},
                       payload=str(patched), agent_dir=agent_dir)
    calls = ctl_log.read_text().splitlines() if ctl_log.exists() else []
    return res, calls


def test_reactivation_passes_tenant_credentials(tmp_path):
    res, calls = _run_reactivation_case_ps1(tmp_path)
    assert res["outcome"] == "FIXED"
    assert "reactivate" in res["actions"]
    activate_calls = [c for c in calls if c.startswith("-a ")]
    assert activate_calls, f"no dsa_control -a call logged: {calls}"
    assert "tenantID:T-1" in activate_calls[0]
    assert "token:K-1" in activate_calls[0]


def test_reactivation_does_not_reset_agent(tmp_path):
    res, calls = _run_reactivation_case_ps1(tmp_path)
    assert not [c for c in calls if c.startswith("-r")], f"reset called: {calls}"


# Long enough that the dsmUrl VALUE line sits past the 1200-char reported cap:
# activation must still be detected because parsing runs on the FULL output.
REAL_QUERY_OUTPUT = (
    "".join(f"AgentStatus.{i}: fieldName{i}\n" for i in range(1, 60))
    + "AgentStatus.agentState: green\n"
    + "AgentStatus.dsmUrl: https://agents-004.workload.us-1.cloudone.trendmicro.com:443/\n"
)


def _run_with_query_file(tmp_path, query_output,
                         dsm_url="dsm://agents.deepsecurity.trendmicro.com:443/"):
    text = _patch_sentinels(dsm_url=dsm_url)
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    qf = tmp_path / "query_output.txt"
    qf.write_text(query_output)
    agent_dir = make_agent_dir(tmp_path, True)
    (agent_dir / "dsa_query.ps1").write_text(f'Get-Content "{qf}" | Write-Output\n')
    return run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                  env={"UET_SERVICE_STATE": "Running", "UET_SKIP_MANAGER_CHECK": "1"},
                  payload=str(patched), agent_dir=agent_dir)


def test_activation_detected_beyond_raw_cap(tmp_path):
    assert len(REAL_QUERY_OUTPUT) > 1200  # dsmUrl value line past the cap
    proc, res = _run_with_query_file(tmp_path, REAL_QUERY_OUTPUT)
    assert res["checks"]["activated"] is True
    assert len(res["checks"]["agent_status_raw"]) <= 1200
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert "foreign_manager" not in res["blockers"]


def test_index_line_naming_dsmUrl_is_not_activation(tmp_path):
    out = "AgentStatus.5: dsmUrl\nAgentStatus.agentState: red\n"
    proc, res = _run_with_query_file(tmp_path, out)
    assert res["checks"]["activated"] is False


def test_on_prem_manager_is_foreign(tmp_path):
    out = ("AgentStatus.agentState: green\n"
           "AgentStatus.dsmUrl: https://dsm.corp.example.com:4119/\n")
    proc, res = _run_with_query_file(tmp_path, out)
    assert proc.returncode == 2
    assert res["outcome"] == "BLOCKED"
    assert "foreign_manager" in res["blockers"]


def _make_component_aware_agent_dir(tmp_path, component_output,
                                    status_output="AgentStatus.dsmUrl: dsm://mgr:443/"):
    # dsa_query shim that answers GetComponentInfo and GetAgentStatus differently.
    agent_dir = make_agent_dir(tmp_path, True)
    (agent_dir / "dsa_query.ps1").write_text(
        'if ($args -contains "GetComponentInfo") '
        f'{{ Write-Output "{component_output}" }} '
        f'else {{ Write-Output "{status_output}" }}\n'
    )
    return agent_dir


def test_am_driver_offline_is_degraded(tmp_path):
    # Component.AM.mode is authoritative (live-verified against nine hosts):
    # a core-healthy agent whose AM driver is offline must return DEGRADED,
    # never NO_ACTION_NEEDED.
    agent_dir = _make_component_aware_agent_dir(tmp_path, "Component.AM.mode: driver-offline")
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Running"}, agent_dir=agent_dir)
    assert proc.returncode == 0
    assert res["outcome"] == "DEGRADED"
    assert res["checks"]["am_mode"] == "basic"
    assert res["checks"]["am_evidence"] == "componentinfo:Component.AM.mode=driver-offline"
    assert "am_basic_functions_detected" in res["notes"]


def test_am_mode_on_is_not_degraded(tmp_path):
    agent_dir = _make_component_aware_agent_dir(tmp_path, "Component.AM.mode: on")
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Running"}, agent_dir=agent_dir)
    assert proc.returncode == 0
    assert res["outcome"] == "NO_ACTION_NEEDED"
    assert res["checks"]["am_mode"] == "on"
    assert "am_basic_functions_detected" not in res["notes"]
    assert "modules_not_verified" not in res["notes"]


def test_healthy_but_manager_unreachable_is_degraded(tmp_path):
    # The rev2 contradiction: NO_ACTION_NEEDED with a manager_unreachable
    # blocker attached. rev4 must report DEGRADED instead.
    text = _patch_sentinels(dsm_url="dsm://127.0.0.1:1/")
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Running"}, payload=str(patched),
                       dsa_query_output="AgentStatus.dsmUrl: dsm://127.0.0.1:443/")
    assert proc.returncode == 0
    assert res["outcome"] == "DEGRADED"
    assert "manager_unreachable" in res["blockers"]


def test_dry_run_stopped_service_enumerates_plan(tmp_path):
    proc, res = run_ps(tmp_path, agent_installed=True,
                       args=["-Mode", "safe", "-DryRun"],
                       env={"UET_SERVICE_STATE": "Stopped"})
    assert proc.returncode == 3
    assert res["outcome"] == "STILL_BROKEN"
    assert "service_start" in res["planned"]
    assert res["actions"] == []


def test_service_start_failure_is_noted_not_logged_as_action(tmp_path):
    # rev2 logged "service_start" unconditionally; a start that does not take
    # (live case: a failed agent upgrade) must be distinguishable.
    proc, res = run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                       env={"UET_SERVICE_STATE": "Stopped",
                            "UET_TEST_START_FAILS": "1", "UET_READY_TRIES": "1"})
    assert proc.returncode == 0
    assert res["outcome"] == "STILL_BROKEN"
    assert "service_start" not in res["actions"]
    assert "service_start_failed" in res["notes"]


# --- rev5: heartbeat outcome, agent-version provenance, promoted AM versions ---

from test_payload_sh import PLUGIN_VERSION_OUTPUT, REAL_COMPONENT_INFO  # noqa: E402

# Trimmed verbatim from PRODHOST01's live rev4 agent_status_raw (2026-08-12).
# Two real details drive the driver-field fix: Windows DSA NAMES driverState in
# its field index ("AgentStatus.15: driverState") and then never emits a value
# line for it, while driverHooked and driverChecked both carry values.
# currentTime - lastAgentToManagerSession = 6083, the real stale age.
WIN_QUERY_OUTPUT = (
    "AgentStatus.13: driverHooked\n"
    "AgentStatus.15: driverState\n"
    "AgentStatus.agentState: green\n"
    "AgentStatus.auStatus: 2\n"
    "AgentStatus.currentTime: 1786547918\n"
    "AgentStatus.driverChecked: 7\n"
    "AgentStatus.driverHooked: 7\n"
    "AgentStatus.lastAgentToManagerSession: 1786541835\n"
    "AgentStatus.dsmUrl: https://agents-004.workload.us-1.cloudone.trendmicro.com:443/\n"
)

# Same host, but checked in 401s ago instead of 6083s.
WIN_FRESH_QUERY_OUTPUT = WIN_QUERY_OUTPUT.replace(
    "currentTime: 1786547918", "currentTime: 1786542236")


def _run_win_rev5(tmp_path, status_output=None, component_output=None,
                  dsa_control_body=None, plugin_output=None, env=None):
    text = _patch_sentinels(dsm_url="dsm://agents.deepsecurity.trendmicro.com:443/")
    patched = tmp_path / "patched.ps1"
    patched.write_text(text)
    agent_dir = make_agent_dir(tmp_path, True)
    sf = tmp_path / "status.txt"
    sf.write_text(status_output if status_output is not None else WIN_QUERY_OUTPUT)
    cf = tmp_path / "component.txt"
    cf.write_text(component_output if component_output is not None else "Component.AM.mode: on\n")
    pf = tmp_path / "plugin.txt"
    pf.write_text(plugin_output if plugin_output is not None else PLUGIN_VERSION_OUTPUT)
    (agent_dir / "dsa_query.ps1").write_text(
        f'if ($args -contains "GetComponentInfo") {{ Get-Content -Raw "{cf}" }}\n'
        f'elseif ($args -contains "GetPluginVersion") {{ Get-Content -Raw "{pf}" }}\n'
        f'else {{ Get-Content -Raw "{sf}" }}\n')
    if dsa_control_body is not None:
        (agent_dir / "dsa_control.ps1").write_text(dsa_control_body)
    full_env = {"UET_SERVICE_STATE": "Running", "UET_SKIP_MANAGER_CHECK": "1"}
    full_env.update(env or {})
    return run_ps(tmp_path, agent_installed=True, args=["-Mode", "safe"],
                  env=full_env, payload=str(patched), agent_dir=agent_dir)


def test_failed_heartbeat_is_not_reported_as_no_action_needed_ps1(tmp_path):
    # Live case, PRODHOST01 2026-08-12: the manual `dsa_control -m` returned
    # "HTTP Status: 403 - Forbidden - untrusted peer." while rev4 reported
    # NO_ACTION_NEEDED with actions:["heartbeat"] — Send-Heartbeat piped the
    # result to Out-Null and then recorded the action regardless.
    proc, res = _run_win_rev5(
        tmp_path,
        dsa_control_body='if ($args[0] -eq "-m") {\n'
                         '  Write-Output "HTTP Status: 403 - Forbidden - untrusted peer."\n'
                         '  exit 1\n}\n'
                         'Write-Output "ctl $args"\n')
    assert res["checks"]["heartbeat_result"] == "failed"
    assert "heartbeat" not in res["actions"]
    assert "heartbeat_failed" in res["notes"]
    assert "untrusted peer" in res["checks"]["heartbeat_error"]
    assert res["outcome"] == "DEGRADED"


def test_heartbeat_failure_is_caught_even_when_exit_status_is_zero_ps1(tmp_path):
    proc, res = _run_win_rev5(
        tmp_path,
        dsa_control_body='if ($args[0] -eq "-m") {\n'
                         '  Write-Output "HTTP Status: 403 - Forbidden - untrusted peer."\n'
                         '  exit 0\n}\n'
                         'Write-Output "ctl $args"\n')
    assert res["checks"]["heartbeat_result"] == "failed"
    assert "heartbeat_failed" in res["notes"]
    assert "manager_rejected_untrusted_peer" in res["notes"]
    assert "local_peer_auth_403" not in res["notes"]
    assert res["checks"]["hb"] == "manager_rejected_untrusted_peer"
    assert res["outcome"] == "DEGRADED"


def test_loopback_untrusted_403_is_local_not_manager_reject_ps1(tmp_path):
    # Live case (2026-08-25): a host whose forced heartbeat answered
    # "403 - Forbidden - untrusted peer." on the agent's OWN loopback server
    # held no manager-reject event, and its scheduler sessions were all HTTP
    # 200. A 403 string alone cannot carry the mgr-reject note when the error
    # is a local peer-auth refusal on port 4118 / "not allowed".
    proc, res = _run_win_rev5(
        tmp_path,
        dsa_control_body='if ($args[0] -eq "-m") {\n'
                         '  Write-Output "Process not authenticated (Executable \'cmd.exe\' not allowed)"\n'
                         '  Write-Output "Incoming connection on interface :::4118"\n'
                         '  Write-Output "HTTP Status: 403 - Forbidden - untrusted peer."\n'
                         '  exit 1\n}\n'
                         'Write-Output "ctl $args"\n')
    assert res["checks"]["heartbeat_result"] == "failed"
    assert "heartbeat_failed" in res["notes"]
    assert "local_peer_auth_403" in res["notes"]
    assert "manager_rejected_untrusted_peer" not in res["notes"]
    assert res["checks"]["hb"] == "local_peer_auth_403"
    assert res["outcome"] == "DEGRADED"


def test_fresh_heartbeat_with_403_is_local_artifact_ps1(tmp_path):
    # A forced check-in that returns a 403 on a host whose scheduler session
    # is FRESH means the manager accepts this agent — so the 403 is a local
    # peer-auth artifact, never a manager reject. The age is the tiebreaker.
    proc, res = _run_win_rev5(tmp_path, status_output=WIN_FRESH_QUERY_OUTPUT,
                              dsa_control_body='if ($args[0] -eq "-m") {\n'
                                               '  Write-Output "HTTP Status: 403 - '
                                               'Forbidden - untrusted peer."\n'
                                               '  exit 1\n}\n'
                                               'Write-Output "ctl $args"\n')
    assert res["checks"]["heartbeat_result"] == "failed"
    assert "heartbeat_failed" in res["notes"]
    assert "local_peer_auth_403" in res["notes"]
    assert "manager_rejected_untrusted_peer" not in res["notes"]
    assert res["checks"]["hb"] == "local_peer_auth_403"
    assert res["outcome"] == "DEGRADED"


def test_fresh_heartbeat_ok_with_no_403_is_fine_ps1(tmp_path):
    # A clean forced check-in on a fresh host: heartbeat_result ok, no 403, hb
    # stays as the age-fresh confirmation (ok_fresh), outcome NO_ACTION_NEEDED.
    proc, res = _run_win_rev5(tmp_path, status_output=WIN_FRESH_QUERY_OUTPUT)
    assert res["checks"]["heartbeat_result"] == "ok"
    assert res["checks"]["heartbeat_age_sec"] == 401
    assert res["checks"]["hb"] == "ok_fresh"
    assert "manager_rejected_untrusted_peer" not in res["notes"]
    assert "local_peer_auth_403" not in res["notes"]
    assert res["outcome"] == "NO_ACTION_NEEDED"


def test_heartbeat_that_does_not_advance_the_session_is_unconfirmed_ps1(tmp_path):
    proc, res = _run_win_rev5(tmp_path)
    assert res["checks"]["heartbeat_age_sec"] == 6083
    assert res["checks"]["heartbeat_result"] == "unconfirmed"
    assert "heartbeat_not_confirmed" in res["notes"]
    assert "heartbeat" in res["actions"]
    assert res["outcome"] == "DEGRADED"


def test_fresh_heartbeat_with_no_room_to_improve_is_not_flagged_ps1(tmp_path):
    proc, res = _run_win_rev5(tmp_path, status_output=WIN_FRESH_QUERY_OUTPUT)
    assert res["checks"]["heartbeat_age_sec"] == 401
    assert res["checks"]["heartbeat_result"] == "ok"
    assert "heartbeat_not_confirmed" not in res["notes"]
    assert res["outcome"] == "NO_ACTION_NEEDED"


def test_driver_state_is_replaced_by_hooked_and_checked(tmp_path):
    # driver_state was empty on healthy hosts seen in production because Windows
    # DSA only ever names the field in its index. driverHooked/driverChecked carry
    # real values and bring Windows to parity with the Linux payload.
    proc, res = _run_win_rev5(tmp_path)
    assert "driver_state" not in res["checks"]
    assert res["checks"]["driver_hooked"] == "7"
    assert res["checks"]["driver_checked"] == "7"


def test_agent_version_is_reported_not_left_blank(tmp_path):
    # agent_version was empty on Windows hosts seen in production: rev4 read
    # ds_agent.exe's ProductVersion, which Trend's binary leaves unset. The
    # build number was central to diagnosing them, so the payload now walks a
    # cascade of sources and records which one answered.
    proc, res = _run_win_rev5(tmp_path)
    assert res["checks"]["agent_version"] == "20.0.3.860"
    assert res["checks"]["agent_version_source"] == "GetPluginVersion"


def test_engine_and_pattern_versions_are_promoted_to_first_class_fields_ps1(tmp_path):
    proc, res = _run_win_rev5(tmp_path, component_output=REAL_COMPONENT_INFO)
    assert res["checks"]["am_engine_atse"] == "24.580.1013"
    pats = dict(p.split("=", 1) for p in res["checks"]["am_patterns"].split(";"))
    assert pats["Spyware/Grayware Pattern"] == "18.33"
    assert pats["Damage Cleanup Template"] == "1578"
    assert pats["Smart Scan Agent Pattern"] == "21.245.00"
    assert len(res["checks"]["component_info_raw"]) <= 1200


def test_collect_diag_bundle_records_agent_version_provenance(tmp_path):
    # Mirror of the Linux test_collect_diag_writes_a_bundle, which Windows never
    # had. The bundle carries the raw GetPluginVersion dump and names the source
    # agent_version came from, so a blank agent_version in a result can be told
    # apart from a source that answered with nothing.
    out = tmp_path / "diag-out.txt"
    proc, res = _run_win_rev5(tmp_path, env={"UET_COLLECT_DIAG": "1",
                                             "UET_DIAG_OUT": str(out)})
    assert out.exists()
    assert res["diag_file"] == str(out)
    assert "collect_diag" in res["actions"]
    body = out.read_text()
    assert "GetAgentStatus" in body
    assert "GetPluginVersion" in body
    assert "20.0.3.860 (source: GetPluginVersion)" in body
