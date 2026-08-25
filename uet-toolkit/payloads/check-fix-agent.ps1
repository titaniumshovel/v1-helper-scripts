# payloads/check-fix-agent.ps1 -- uet payload (Windows), schema uet-result/3
# PowerShell 5.1 compatible. stdout: exactly one JSON line. stderr: chatter.
#
# SCOPE, read this before trusting an outcome: this payload sees the AGENT, not
# the manager's view of the agent's MODULES. NO_ACTION_NEEDED means "the agent
# core is healthy AND no module-level fault was detected locally", NOT "the
# console will show green". A core-healthy host with a locally detectable,
# script-unfixable fault (Anti-Malware driver offline, manager unreachable)
# returns DEGRADED instead — the rev2 schema reported those hosts as
# NO_ACTION_NEEDED with a contradictory blocker attached, which misled reads
# of three real hosts. Read notes[] for what was left unverified.
#
# This payload never reboots the host, in any mode. The only service it ever
# touches is ds_agent.
[CmdletBinding()]
param(
    [string]$Mode = $(if ($env:UET_MODE) { $env:UET_MODE } else { "safe" }),
    [switch]$DryRun,
    [switch]$CollectDiag
)
if ($env:UET_DRY_RUN -eq "1") { $DryRun = $true }
if ($env:UET_COLLECT_DIAG -eq "1") { $CollectDiag = $true }
$Mode = ("$Mode").ToLowerInvariant()

$Schema = "uet-result/3"
$AgentDir = if ($env:UET_AGENT_DIR) { $env:UET_AGENT_DIR } else { "C:\Program Files\Trend Micro\Deep Security Agent" }

# Operator-set env values are captured BEFORE the embedded slots below, because
# `uet` rewrites those slot lines at generation time and would otherwise clobber
# them. This lets one file serve both flows: orchestrated runs get the values
# baked in, customer self-service runs pass them as env vars. Keeping it to one
# file matters — the shipped rev3 copy drifted from the tested template exactly
# here (mirrors the same prelude in check-fix-agent.sh).
$EnvDsmUrl = $env:UET_DSM_URL
$EnvDeployB64 = $env:UET_DEPLOY_B64
$EnvActivationArgs = $env:UET_ACTIVATION_ARGS

$UetDsmUrl = ""  # __UET_DSM_URL__
$UetDeployB64 = ""  # __UET_DEPLOY_B64__
$UetActivationArgs = ""  # __UET_ACTIVATION_ARGS__

if (-not $UetDsmUrl) { $UetDsmUrl = $EnvDsmUrl }
if (-not $UetDeployB64) { $UetDeployB64 = $EnvDeployB64 }
if (-not $UetActivationArgs) { $UetActivationArgs = $EnvActivationArgs }

# Windows PowerShell 5.1 only ships "powershell.exe"; pwsh (Core, used to run
# this payload's test suite on non-Windows dev boxes) only ships "pwsh". Pick
# the right child-process executable so embedded/child invocations work in
# both environments without relying on pwsh-only syntax like `??`.
$PsExe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell" }

$Actions = New-Object System.Collections.ArrayList
$Planned = New-Object System.Collections.ArrayList
$Blockers = New-Object System.Collections.ArrayList
$Notes = New-Object System.Collections.ArrayList
$Checks = [ordered]@{ installed = $false; service_running = $false; activated = $false;
             manager_reachable = $null; disk_free_mb = 0; os_version = ""; agent_version = "";
             agent_version_source = ""; agent_state = ""; driver_hooked = ""; driver_checked = "";
             au_status = ""; heartbeat_age_sec = $null; heartbeat_result = ""; heartbeat_error = "";
             am_mode = "unknown"; am_evidence = ""; am_engine_atse = ""; am_patterns = "";
             agent_status_raw = ""; component_info_raw = ""; hb = "" }
$Outcome = "ERROR"
$script:Foreign = $false
$script:Emitted = $false
$script:DiagFile = ""
$script:AgentStatusFull = ""
$script:ComponentInfoFull = ""
$script:LastToolExit = $null
# Reported raw fields are capped AFTER capture; all parsing runs on the full
# text. Matches the Linux payload's component_info_raw cap.
$RawCap = if ($env:UET_STATUS_RAW_CAP) { [int]$env:UET_STATUS_RAW_CAP } else { 1200 }

function Write-Log($msg) { [Console]::Error.WriteLine("uet: $msg") }

function Get-SleepSecs([int]$Default) {
    if ($env:UET_SLEEP_SECS -ne $null -and $env:UET_SLEEP_SECS -ne '') { return [int]$env:UET_SLEEP_SECS }
    return $Default
}

function Add-Blocker([string]$Name) {
    if (-not ($Blockers -contains $Name)) { [void]$Blockers.Add($Name) }
}

function Add-Note([string]$Name) {
    if (-not ($Notes -contains $Name)) { [void]$Notes.Add($Name) }
}

# Strip control characters except newline (ConvertTo-Json escapes the kept
# newlines as \n); the rev2 payload deleted newlines outright, which collapsed
# the multi-line dsa_query dump into one useless run-on string.
function Clear-Raw([string]$Text) {
    if ($null -eq $Text) { return "" }
    return ($Text -replace "[\x00-\x09\x0B-\x1F\x7F]", "")
}

function Limit-Raw([string]$Text) {
    if ($null -eq $Text) { return "" }
    return $Text.Substring(0, [Math]::Min($RawCap, $Text.Length))
}

function Emit-Result($ExitCode) {
    $script:Emitted = $true
    # Invariant, enforced last: NO_ACTION_NEEDED cannot coexist with a blocker
    # or a detected module fault (the rev2 contradiction).
    if ($Outcome -eq "NO_ACTION_NEEDED" -and ($Blockers.Count -gt 0 -or
        ($Notes -contains "am_basic_functions_detected") -or
        ($Notes -contains "heartbeat_failed") -or
        ($Notes -contains "heartbeat_not_confirmed"))) {
        $Outcome = "DEGRADED"
    }
    $obj = [ordered]@{
        schema = $Schema; host = [System.Net.Dns]::GetHostName(); mode = $Mode
        dry_run = [bool]$DryRun; checks = $Checks
        actions = @($Actions); planned = @($Planned); blockers = @($Blockers)
        notes = @($Notes); diag_file = $script:DiagFile; outcome = $Outcome
    }
    ($obj | ConvertTo-Json -Compress -Depth 5) | Write-Output
    exit $ExitCode
}

function Test-IsAdmin {
    if ($env:UET_IS_ADMIN) { return $env:UET_IS_ADMIN -eq "1" }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AgentServiceState {
    if ($env:UET_SERVICE_STATE) { return $env:UET_SERVICE_STATE }  # test hook
    $svc = Get-Service -Name "ds_agent" -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return "None" }
    return "$($svc.Status)"
}

# The tool's exit status is recorded alongside its output, because a caller that
# only reads stdout cannot tell a successful command from a failed one. $null
# means no tool was found to run.
function Invoke-AgentTool([string]$tool, [string[]]$ToolArgs) {
    # Prefer .ps1 shim (tests), then .cmd (real agent)
    $ps1 = Join-Path $AgentDir "$tool.ps1"
    $cmd = Join-Path $AgentDir "$tool.cmd"
    $script:LastToolExit = $null
    if (Test-Path $ps1) {
        $o = (& $PsExe -NoProfile -File $ps1 @ToolArgs 2>&1 | Out-String)
        $script:LastToolExit = $LASTEXITCODE
        return $o
    }
    if (Test-Path $cmd) {
        $o = (& $cmd @ToolArgs 2>&1 | Out-String)
        $script:LastToolExit = $LASTEXITCODE
        return $o
    }
    return ""
}

function Get-HostPort([string]$DsmUrl) {
    $hp = $DsmUrl -replace "^dsm://", ""
    $hp = $hp -replace "/.*$", ""
    return $hp.ToLowerInvariant()
}

function Get-UrlHost([string]$Url) {
    $h = $Url -replace "^[A-Za-z][A-Za-z0-9+.-]*://", ""
    $h = $h -replace "/.*$", ""
    $h = $h -replace ":\d+$", ""
    return $h.ToLowerInvariant()
}

function Get-DomainSuffix([string]$HostName) {
    $labels = $HostName.Split(".")
    if ($labels.Length -ge 2) { return ($labels[-2..-1] -join ".") }
    return $HostName
}

# Pull one VALUE line out of dsa_query -c GetAgentStatus. Real output opens
# with an index of field NAMES ("AgentStatus.13: agentState") and puts values
# further down ("AgentStatus.agentState: green"); anchoring on the field name
# after the dot matches only the value line, never the index.
function Get-StatusField([string]$Name) {
    $m = [regex]::Match($script:AgentStatusFull, ("AgentStatus\." + [regex]::Escape($Name) + ":\s*(\S+)"))
    if ($m.Success) { return $m.Groups[1].Value }
    return ""
}

# Anti-Malware mode. Reports "on" or "basic" only on the agent's own
# GetComponentInfo verdict (Component.AM.mode / Component.AM.driverOffline),
# which is authoritative — live-verified against nine Linux hosts where it
# separated five genuinely driver-offline agents from four false positives.
# No log-grep fallback on Windows: if GetComponentInfo yields nothing the mode
# stays "unknown" and no am note is emitted. Never inferred.
function Set-AmMode {
    $Checks.am_mode = "unknown"; $Checks.am_evidence = ""
    $m = [regex]::Match($script:ComponentInfoFull, 'Component\.AM\.mode:\s*(\S+)')
    $offline = ""
    $o = [regex]::Match($script:ComponentInfoFull, 'Component\.AM\.driverOffline:\s*(\S+)')
    if ($o.Success) { $offline = $o.Groups[1].Value }
    if ($m.Success) {
        $mode = $m.Groups[1].Value
        if ($mode -eq "on" -and $offline -ne "true") { $Checks.am_mode = "on" }
        else { $Checks.am_mode = "basic" }
        $Checks.am_evidence = "componentinfo:Component.AM.mode=$mode"
    } elseif ($offline -eq "true") {
        $Checks.am_mode = "basic"
        $Checks.am_evidence = "componentinfo:Component.AM.driverOffline=true"
    }
}

# Agent build number WITH provenance. rev4 read only ds_agent.exe's
# ProductVersion, which Trend's binary leaves unset — agent_version came back
# empty on production Windows hosts, on a run where the build number was
# central to the diagnosis. Sources are tried most-verifiable first and the
# winner is named, because a build number with no stated source is exactly the
# sort of claim this kind of diagnosis cannot afford.
function Get-AgentVersion {
    $exe = Join-Path $AgentDir "ds_agent.exe"
    if (Test-Path $exe) {
        try {
            $vi = (Get-Item $exe).VersionInfo
            if ("$($vi.FileVersion)".Trim()) { return @("$($vi.FileVersion)".Trim(), "FileVersion") }
            if ("$($vi.ProductVersion)".Trim()) { return @("$($vi.ProductVersion)".Trim(), "ProductVersion") }
        } catch {}
    }
    # HKLM\SOFTWARE\Trend Micro\Deep Security Agent -- note the SPACE in "Trend
    # Micro"; that is the spelling in Trend's own Integrity Monitoring rule
    # examples. The value NAME is not documented anywhere, so several candidates
    # are tried and a miss simply yields nothing rather than a guess.
    try {
        $k = Get-ItemProperty -Path "HKLM:\SOFTWARE\Trend Micro\Deep Security Agent" -ErrorAction Stop
        foreach ($n in @("InstalledVersion", "Version", "ProductVersion", "CurrentVersion")) {
            if (($k.PSObject.Properties.Name -contains $n) -and "$($k.$n)".Trim()) {
                return @("$($k.$n)".Trim(), "registry")
            }
        }
    } catch {}
    # `dsa_query -c GetPluginVersion` is documented as returning "version
    # information of the agent and protection modules", but its output schema is
    # not published — so only a version-shaped string on a line that names the
    # agent is accepted, which keeps a protection module's version from being
    # reported as the agent's.
    if ($Checks.installed -and $Checks.service_running) {
        $out = Invoke-AgentTool "dsa_query" @("-c", "GetPluginVersion")
        foreach ($line in ($out -split "`n")) {
            if ($line -match '(?i)agent') {
                $m = [regex]::Match($line, '\d+\.\d+\.\d+([.-]\d+)?')
                if ($m.Success) { return @($m.Value, "GetPluginVersion") }
            }
        }
    }
    return @("", "")
}

# Promote the Anti-Malware engine and pattern levels out of the raw dump into
# named fields. rev4 captured them only inside component_info_raw, which is
# capped and was truncated mid-field on healthy production hosts, so
# comparing two hosts' pattern levels meant hand-parsing a cut-off blob. Pairs
# are keyed by pattern NAME, never by the agent's index: the index is not stable
# across hosts (Spyware/Grayware was pattern.10 on PRODHOST01 and pattern.11
# on PRODHOST02).
function Set-ComponentVersions {
    $Checks.am_engine_atse = ""
    $Checks.am_patterns = ""
    $m = [regex]::Match($script:ComponentInfoFull, 'Component\.AM\.version\.engine\.ATSE:\s*(\S+)')
    if ($m.Success) { $Checks.am_engine_atse = $m.Groups[1].Value }
    $names = @{}; $vers = @{}
    foreach ($x in [regex]::Matches($script:ComponentInfoFull,
                   'Component\.AM\.version\.pattern\.(\d+)\.name:[ \t]*([^\n]+)')) {
        $names[$x.Groups[1].Value] = $x.Groups[2].Value.Trim()
    }
    foreach ($x in [regex]::Matches($script:ComponentInfoFull,
                   'Component\.AM\.version\.pattern\.(\d+)\.version:[ \t]*([^\n]+)')) {
        $vers[$x.Groups[1].Value] = $x.Groups[2].Value.Trim()
    }
    $pairs = @()
    foreach ($k in $names.Keys) {
        if ($vers.ContainsKey($k)) { $pairs += "$($names[$k])=$($vers[$k])" }
    }
    if ($pairs.Count -gt 0) { $Checks.am_patterns = Limit-Raw (($pairs | Sort-Object) -join ";") }
}

function Invoke-Diagnose {
    $Checks.installed = (Test-Path (Join-Path $AgentDir "dsa_control.cmd")) -or (Test-Path (Join-Path $AgentDir "dsa_control.ps1"))
    $state = Get-AgentServiceState
    $Checks.service_running = ($state -eq "Running")
    $Checks.activated = $false
    $script:Foreign = $false
    $script:AgentStatusFull = ""
    $script:ComponentInfoFull = ""

    if (-not $Checks.os_version) {
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $Checks.os_version = ("$($os.Caption) $($os.Version)").Trim()
        } catch { $Checks.os_version = [System.Environment]::OSVersion.VersionString }
    }
    # The build number cannot change mid-run, so the first source that answers
    # wins and later diagnose passes (the post-heartbeat confirm re-reads) skip
    # the lookup rather than re-querying the agent each time.
    if (-not $Checks.agent_version) {
        $av, $avs = Get-AgentVersion
        $Checks.agent_version = $av
        $Checks.agent_version_source = $avs
    }

    if ($Checks.installed -and $Checks.service_running) {
        $script:AgentStatusFull = Clear-Raw (Invoke-AgentTool "dsa_query" @("-c", "GetAgentStatus"))
        $Checks.agent_status_raw = Limit-Raw $script:AgentStatusFull
        $script:ComponentInfoFull = Clear-Raw (Invoke-AgentTool "dsa_query" @("-c", "GetComponentInfo"))
        $Checks.component_info_raw = Limit-Raw $script:ComponentInfoFull

        $Checks.agent_state = Get-StatusField "agentState"
        # driverHooked / driverChecked, NOT driverState: Windows DSA names
        # driverState in its field index ("AgentStatus.15: driverState") and then
        # never emits a value line for it, so rev4's driver_state was empty on
        # every host. These two carry real values and match the Linux payload.
        $Checks.driver_hooked = Get-StatusField "driverHooked"
        $Checks.driver_checked = Get-StatusField "driverChecked"
        $Checks.au_status = Get-StatusField "auStatus"

        # Heartbeat freshness proves manager comms independently of
        # `activated`, which stays true on a host that has silently stopped
        # checking in.
        $now = Get-StatusField "currentTime"
        $last = Get-StatusField "lastAgentToManagerSession"
        $Checks.heartbeat_age_sec = $null
        if ($now -match '^\d+$' -and $last -match '^\d+$') {
            $Checks.heartbeat_age_sec = [long]$now - [long]$last
        }

        # Activation is proven only by a dsmUrl VALUE line ("dsmUrl: <scheme>://").
        # Real agents (live-captured) open with an index of field NAMES — which
        # mentions dsmUrl with no value — so judge on the FULL output; the cap
        # applies only to the reported agent_status_raw field.
        if ($script:AgentStatusFull -match "dsmUrl:\s*[A-Za-z][A-Za-z0-9+.-]*://") { $Checks.activated = $true }
        # Activated, but against OUR manager? The agent records the endpoint it
        # actually talks to, which on SWP differs from the activation URL in
        # both scheme (https:// vs dsm://) and host (regional
        # agents-NNN.workload... vs the agents.deepsecurity... redirector) —
        # live-verified, so exact host:port equality is unsatisfiable. Compare
        # the registrable domain (last two labels): "foreign" means a manager
        # in a different admin domain (e.g. an on-prem DSM), never touched.
        if ($Checks.activated -and $UetDsmUrl) {
            $expected = Get-DomainSuffix (Get-UrlHost $UetDsmUrl)
            $m = [regex]::Match($script:AgentStatusFull, 'dsmUrl:\s*([A-Za-z][A-Za-z0-9+.-]*://[^\s"]+)')
            $actualHost = ""
            if ($m.Success) { $actualHost = Get-UrlHost $m.Groups[1].Value }
            if ([string]::IsNullOrEmpty($actualHost) -or (Get-DomainSuffix $actualHost) -ne $expected) {
                $script:Foreign = $true
            }
        }
    }
    Set-AmMode
    Set-ComponentVersions
    try {
        $drive = Get-PSDrive -Name C -ErrorAction Stop
        $Checks.disk_free_mb = [int]($drive.Free / 1MB)
    } catch { $Checks.disk_free_mb = 0 }
    if ($UetDsmUrl -and $env:UET_SKIP_MANAGER_CHECK -ne "1") {
        $hp2 = Get-HostPort $UetDsmUrl
        $parts = $hp2.Split(":"); $mh = $parts[0]
        $mp = if ($parts.Length -gt 1) { [int]$parts[1] } else { 4120 }
        try {
            $client = New-Object Net.Sockets.TcpClient
            $iar = $client.BeginConnect($mh, $mp, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(5000) -and $client.Connected) { $Checks.manager_reachable = $true }
            else { $Checks.manager_reachable = $false; Add-Blocker "manager_unreachable" }
            $client.Close()
        } catch { $Checks.manager_reachable = $false; Add-Blocker "manager_unreachable" }
    }
}

# Test-Healthy is deliberately AGENT-core only. See the SCOPE note at the top:
# the caller must also consult Test-Degraded / notes[] before concluding a
# host is fine.
function Test-Healthy { $Checks.installed -and $Checks.service_running -and $Checks.activated }

# A core-healthy host that nonetheless has a real, script-unfixable fault.
# A heartbeat that errored, or that never moved the agent's own
# lastAgentToManagerSession, counts too: the check-in is the one thing this
# payload does that proves manager comms, so discarding its result is how a host
# the console listed as Offline came back NO_ACTION_NEEDED.
# Only an explicit `$false` counts for manager_reachable; $null means the
# probe did not run.
function Test-Degraded {
    ($Checks.am_mode -eq "basic") -or ($Checks.manager_reachable -eq $false) -or
    ($Checks.heartbeat_result -eq "failed") -or ($Checks.heartbeat_result -eq "unconfirmed")
}

# Record what this run could and could not establish, so a human reading the
# raw JSON (with no console cross-check in front of them) is not misled by a
# core-healthy verdict.
function Invoke-Annotate {
    if ($Checks.am_mode -eq "basic") { Add-Note "am_basic_functions_detected" }
    elseif ($Checks.am_mode -eq "unknown" -and $Checks.service_running) { Add-Note "modules_not_verified" }
    $stale = if ($env:UET_HEARTBEAT_STALE_SECS) { [long]$env:UET_HEARTBEAT_STALE_SECS } else { 1800 }
    if ($Checks.heartbeat_age_sec -ne $null -and $Checks.heartbeat_age_sec -gt $stale) { Add-Note "heartbeat_stale" }
    $minDisk = if ($env:UET_MIN_DISK_MB) { [int]$env:UET_MIN_DISK_MB } else { 500 }
    if ($Checks.disk_free_mb -lt $minDisk) { Add-Note "low_disk" }
}

# A check-in, and then proof that it landed. rev4 piped the command's output to
# Out-Null, ignored its exit status, and recorded the action unconditionally — so
# a production host whose `dsa_control -m` answered "HTTP Status: 403 - Forbidden -
# untrusted peer.", was reported as NO_ACTION_NEEDED with actions:["heartbeat"].
# Two independent failure signals are checked, because neither alone suffices:
#   1. the command failed  -- non-zero exit, or a non-2xx "HTTP Status:" line in
#      its own output (dsa_control's exit status is not dependable, and reading an
#      HTTP status code off observed output is arithmetic, not an interpretation
#      of an undocumented field);
#   2. the check-in did not land -- the agent's own heartbeat age did not improve.
# Signal 2 only counts once the age is ALSO past the stale threshold: a static age
# on a host that checked in a minute ago is not evidence of failure, and the
# status field can lag a successful session by a few seconds. The confirm re-read
# therefore polls for improvement instead of judging on a single sample.
function Send-Heartbeat {
    $before = $Checks.heartbeat_age_sec
    $Checks.heartbeat_result = ""
    $Checks.heartbeat_error = ""
    $Checks.hb = ""
    $out = Invoke-AgentTool "dsa_control" @("-m")
    $rc = $script:LastToolExit
    if ("$out".Trim()) { Write-Log "dsa_control -m: $("$out".Trim())" }

    $failed = $false
    if ($null -ne $rc -and $rc -ne 0) { $failed = $true }
    $m = [regex]::Match("$out", 'HTTP Status:\s*(\d{3})')
    if ($m.Success -and $m.Groups[1].Value -notmatch '^2') { $failed = $true }
    # "untrusted peer" on a forced check-in is ambiguous between a manager-side
    # reject (documented events 771 "Contact by Unrecognized Client" / 716
    # "Reactivation Attempted by Unknown Agent") and the agent's own local
    # loopback management server (port 4118) refusing the forced heartbeat from
    # a local process it does not recognize as authenticated — live-verified on
    # a host whose routine scheduler sessions to the manager were all HTTP 200
    # while its forced `dsa_control -m` answered "403 - Forbidden - untrusted
    # peer." on the loopback listener. The scheduler heartbeat age is the
    # tiebreaker: a manager that accepts the agent's own sessions (age fresh)
    # did not just reject it per-check-in — a 403 then is a local peer-auth
    # artifact. Only a 403 with a stale session is a manager-reject candidate.
    $stale = if ($env:UET_HEARTBEAT_STALE_SECS) { [long]$env:UET_HEARTBEAT_STALE_SECS } else { 1800 }
    $loopback = ("$out" -match '(?i)untrusted peer') -and ("$out" -match '(?i)loopback|4118|not allowed')
    if ($failed) {
        $Checks.heartbeat_result = "failed"
        $first = (("$out" -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
        if (-not "$first".Trim()) { $first = "dsa_control -m exited $rc" }
        $Checks.heartbeat_error = "$first".Trim().Substring(0, [Math]::Min(200, "$first".Trim().Length))
        Add-Note "heartbeat_failed"
        # Poll the agent's own session age so the classification reads the
        # CURRENT freshness, not the stale value captured before the forced
        # check-in.
        $tries = if ($env:UET_HEARTBEAT_CONFIRM_TRIES) { [int]$env:UET_HEARTBEAT_CONFIRM_TRIES } else { 3 }
        while ($tries -gt 0) {
            Start-Sleep -Seconds (Get-SleepSecs 5)
            Invoke-Diagnose
            if ($Checks.heartbeat_age_sec -ne $null) { break }
            $tries--
        }
        $age = $Checks.heartbeat_age_sec
        if ("$out" -match '(?i)untrusted peer') {
            if ($age -ne $null -and $age -lt $stale) {
                # Session fresh -> manager accepts this agent -> not a reject.
                $Checks.hb = "local_peer_auth_403"
                Add-Note "local_peer_auth_403"
            } elseif ($loopback) {
                $Checks.hb = "local_peer_auth_403"
                Add-Note "local_peer_auth_403"
            } else {
                # 403 + stale/unreadable session, no local markers -> the
                # documented manager-side reject path (771/716); documented fix
                # is reactivation settings, not a restart.
                $Checks.hb = "manager_rejected_untrusted_peer"
                Add-Note "manager_rejected_untrusted_peer"
            }
        } else {
            $Checks.hb = "error"
        }
        return
    }

    [void]$Actions.Add("heartbeat")
    $Checks.heartbeat_result = "ok"
    $tries = if ($env:UET_HEARTBEAT_CONFIRM_TRIES) { [int]$env:UET_HEARTBEAT_CONFIRM_TRIES } else { 3 }
    while ($tries -gt 0) {
        Start-Sleep -Seconds (Get-SleepSecs 5)
        Invoke-Diagnose
        if ($null -eq $before -or $null -eq $Checks.heartbeat_age_sec) { return }
        if ($Checks.heartbeat_age_sec -lt $before) { break }
        $tries--
    }
    # A successful forced check-in whose scheduler session is fresh is NOT a
    # manager reject; a loopback 403 in the utility output is then a local
    # artifact and must not carry the mgr-reject note.
    if ($Checks.heartbeat_age_sec -ne $null -and $Checks.heartbeat_age_sec -lt $stale) {
        $Checks.hb = "ok_fresh"
    }
    if ($null -eq $before -or $null -eq $Checks.heartbeat_age_sec) { return }
    if ($Checks.heartbeat_age_sec -ge $before -and $Checks.heartbeat_age_sec -gt $stale) {
        $Checks.heartbeat_result = "unconfirmed"
        Add-Note "heartbeat_not_confirmed"
    }
}

function Invoke-CollectDiag {
    $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $hostName = [System.Net.Dns]::GetHostName()
    $out = if ($env:UET_DIAG_OUT) { $env:UET_DIAG_OUT } else { Join-Path ([IO.Path]::GetTempPath()) "uet-diag-$hostName-$epoch.txt" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("=== uet diag $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) ===")
    [void]$sb.AppendLine("--- os ---");             [void]$sb.AppendLine("$($Checks.os_version)")
    [void]$sb.AppendLine("--- agent version ---")
    $src = if ($Checks.agent_version_source) { $Checks.agent_version_source } else { "none" }
    [void]$sb.AppendLine("$($Checks.agent_version) (source: $src)")
    [void]$sb.AppendLine("--- dsa_query GetPluginVersion ---")
    [void]$sb.AppendLine((Invoke-AgentTool "dsa_query" @("-c", "GetPluginVersion")))
    [void]$sb.AppendLine("--- dsa_query GetAgentStatus ---")
    [void]$sb.AppendLine((Invoke-AgentTool "dsa_query" @("-c", "GetAgentStatus")))
    [void]$sb.AppendLine("--- dsa_query GetComponentInfo ---")
    [void]$sb.AppendLine((Invoke-AgentTool "dsa_query" @("-c", "GetComponentInfo")))
    $pd = if ($env:ProgramData) { $env:ProgramData } else { [IO.Path]::GetTempPath() }
    $diagDir = if ($env:UET_DIAG_DIR) { $env:UET_DIAG_DIR } else { Join-Path $pd "Trend Micro\Deep Security Agent\diag" }
    [void]$sb.AppendLine("--- agent log tails ($diagDir) ---")
    if (Test-Path $diagDir) {
        Get-ChildItem -Path $diagDir -Filter "ds_agent*.log" -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$sb.AppendLine("  [$($_.FullName)]")
            [void]$sb.AppendLine((Get-Content $_.FullName -Tail 200 -ErrorAction SilentlyContinue | Out-String))
        }
    } else { [void]$sb.AppendLine("  (diag dir not found)") }

    # The heartbeat channel and the telemetry channel fail independently. A
    # host whose scheduler heartbeats to the manager succeed (HTTP 200) can
    # still be reporting "403 - Forbidden - untrusted peer." and "CA is not
    # trusted"/"unknown authority" on the DSA-Connect / MQTT / iothub /
    # Endpoint Basecamp path — live-verified on the host that motivated this.
    # Capture the CA/trust evidence and the precise 403 context so the two
    # reads are distinguishable without a second remote session.
    $loguePatterns = @('untrusted peer', 'not allowed', 'HeartbeatNow', '4118',
                      'iothub', 'DSA-Connect', 'CA is not trusted', 'install_root_ca',
                      'unknown authority', 'getIothubData', 'healthz')
    function Append-LogTail([System.Text.StringBuilder]$b, [string]$Path, [int]$Tail, [string[]]$Patterns) {
        if (-not (Test-Path $Path)) { [void]$b.AppendLine("  (missing $Path)"); return }
        [void]$b.AppendLine("  [$Path]")
        $lines = Get-Content -Path $Path -Tail $Tail -ErrorAction SilentlyContinue
        foreach ($l in $lines) {
            if ($Patterns.Count -eq 0 -or ("$l" -match ($Patterns -join '|'))) { [void]$b.AppendLine($l) }
        }
    }
    Append-LogTail $sb (Join-Path $diagDir "ds_agent.log") 200 $loguePatterns
    Append-LogTail $sb (Join-Path $diagDir "ds_agent-err.log") 200 $loguePatterns
    $xbc = Join-Path $pd "Trend Micro\Deep Security Agent\EndpointBasecamp.log"
    Append-LogTail $sb $xbc 200 $loguePatterns

    [void]$sb.AppendLine("--- Trusted Root Certification Authorities ---")
    try {
        $roots = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue
        foreach ($c in $roots) {
            [void]$sb.AppendLine("  thumbprint=$($c.Thumbprint) subject='$($c.Subject)' notafter=$($c.NotAfter)")
        }
        if (-not $roots) { [void]$sb.AppendLine("  (no Trusted Root entries readable)") }
    } catch { [void]$sb.AppendLine("  (Trusted Root read failed: $($_.Exception.Message))") }
    try {
        Set-Content -Path $out -Value $sb.ToString() -Encoding UTF8
        $script:DiagFile = $out
        [void]$Actions.Add("collect_diag")
        Write-Log "diagnostics written to $out"
    } catch { Write-Log "collect-diag failed: $($_.Exception.Message)" }
}

function Invoke-SafeFixes {
    if ($Checks.installed -and -not $Checks.service_running) {
        Write-Log "starting ds_agent service"
        if (-not $env:UET_SERVICE_STATE) { Start-Service -Name "ds_agent" -ErrorAction SilentlyContinue }
        elseif ($env:UET_TEST_START_FAILS -ne "1") { $env:UET_SERVICE_STATE = "Running" }  # test hook
        # dsa_query needs a few seconds after a service start before it
        # reports status; poll for readiness instead of misreading "not ready
        # yet" as "not activated" and escalating to an unnecessary
        # reactivation (live-verified failure mode on Linux; same risk here).
        $tries = if ($env:UET_READY_TRIES) { [int]$env:UET_READY_TRIES } else { 6 }
        while ($tries -gt 0) {
            Start-Sleep -Seconds (Get-SleepSecs 5)
            Invoke-Diagnose
            if ($Checks.activated) { break }
            $tries--
        }
        # The action is recorded only if the service actually came up; a start
        # that did not take gets a note instead. rev2 logged "service_start"
        # unconditionally, which made a host whose service refused to start
        # (live case: a failed agent upgrade) read as if the fix had applied.
        if ($Checks.service_running) { [void]$Actions.Add("service_start") }
        else { Add-Note "service_start_failed" }
    }
    if ($Checks.installed -and $Checks.service_running -and -not $Checks.activated) {
        if ($UetDsmUrl -and $UetActivationArgs) {
            Write-Log "reactivating agent"
            # No `dsa_control -r` first: reset deactivates the agent
            # (destructive if the diagnosis was wrong), and a credentialed -a
            # activates a deactivated agent without it. Bare -a without the
            # embedded tenantID/token cannot activate against multi-tenant SWP.
            $aArgs = @("-a", $UetDsmUrl) + @($UetActivationArgs -split " " | Where-Object { $_ })
            Invoke-AgentTool "dsa_control" $aArgs | Out-Null
            [void]$Actions.Add("reactivate")
            Start-Sleep -Seconds (Get-SleepSecs 10)
            Invoke-Diagnose
        } else { Add-Blocker "no_dsm_url_embedded" }
    }
    if (Test-Healthy) { Send-Heartbeat }
}

function Invoke-DeploymentScript {
    if (-not $UetDeployB64) { Add-Blocker "no_deployment_script_embedded"; return }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("uet-deploy-" + [guid]::NewGuid().ToString("N") + ".ps1")
    [IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String($UetDeployB64))
    Write-Log "running deployment script $tmp"
    if ($PsExe -eq "powershell") {
        & $PsExe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1 | ForEach-Object { [Console]::Error.WriteLine($_) }
    } else {
        & $PsExe -NoProfile -File $tmp 2>&1 | ForEach-Object { [Console]::Error.WriteLine($_) }
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    [void]$Actions.Add("run_deployment_script")
    Start-Sleep -Seconds (Get-SleepSecs 10)
    Invoke-Diagnose
}

# Enumerate, for -DryRun, the actions a real safe-mode run would attempt from
# the current diagnosis, plus any pre-flight blockers already visible. rev2
# emitted empty actions/blockers unconditionally in dry run, so a dry run
# could not tell the operator what was about to happen or what was missing.
function Invoke-PlanEnumeration {
    if ($Checks.installed) {
        if (-not $Checks.service_running) {
            [void]$Planned.Add("service_start")
            if (-not ($UetDsmUrl -and $UetActivationArgs)) {
                # Activation state is unknowable while the service is down; if
                # a reactivation turns out to be needed, it would be blocked.
                Add-Note "reactivation_unavailable_no_credentials"
            }
        } elseif (-not $Checks.activated) {
            [void]$Planned.Add("reactivate")
            if (-not ($UetDsmUrl -and $UetActivationArgs)) { Add-Blocker "no_dsm_url_embedded" }
        }
        [void]$Planned.Add("heartbeat")
        if (-not (Test-Healthy) -and $Mode -eq "reinstall") { [void]$Planned.Add("run_deployment_script") }
    } else {
        switch ($Mode) {
            "safe"    { Add-Blocker "needs_install_mode" }
            "install" { [void]$Planned.Add("run_deployment_script") }
        }
    }
    if (($Planned -contains "run_deployment_script") -and -not $UetDeployB64) {
        Add-Blocker "no_deployment_script_embedded"
    }
}

# ---- main ----
# Wrap the whole flow so that any unexpected terminating error still yields
# exactly one JSON result line: the finally block emits OUTCOME=ERROR unless a
# normal Emit-Result already fired (tracked by $script:Emitted).
try {
    # Test hook: force a terminating error before any normal flow, to prove
    # the finally block still emits an ERROR result line.
    if ($env:UET_TEST_FORCE_CRASH) { throw "forced crash (test hook)" }

    switch ($Mode) {
        "safe" {}
        "reinstall" {}
        "install" {}
        default { Add-Blocker "bad_mode"; $Outcome = "BLOCKED"; Emit-Result 2 }
    }

    Invoke-Diagnose
    Write-Log "diagnose: installed=$($Checks.installed) service=$($Checks.service_running) activated=$($Checks.activated) am_mode=$($Checks.am_mode) hb_age=$($Checks.heartbeat_age_sec)"

    # Foreign-manager agents are never touched, in any mode, dry-run or not.
    if ($script:Foreign) {
        Add-Blocker "foreign_manager"
        Invoke-Annotate
        $Outcome = "BLOCKED"
        if ($DryRun) { Emit-Result 3 } else { Emit-Result 2 }
    }

    # Diagnostics collection is read-only, so it is allowed in -DryRun. It
    # needs admin rights to read the agent's logs.
    if ($CollectDiag -and (Test-IsAdmin)) { Invoke-CollectDiag }

    if ($DryRun) {
        Invoke-PlanEnumeration
        Invoke-Annotate
        if (-not (Test-Healthy)) { $Outcome = "STILL_BROKEN" }
        elseif (Test-Degraded) { $Outcome = "DEGRADED" }
        else { $Outcome = "NO_ACTION_NEEDED" }
        Emit-Result 3
    }

    if (-not (Test-IsAdmin)) { Add-Blocker "not_admin"; Invoke-Annotate; $Outcome = "BLOCKED"; Emit-Result 2 }

    # A core-healthy host still gets a check-in, and the status is re-read
    # afterwards before the verdict. rev2 returned NO_ACTION_NEEDED here
    # without ever firing the one safe, idempotent action that clears
    # module-level faults — and without flagging a host the console showed
    # Offline (live case: a script-healthy host whose check-ins were not
    # arriving).
    if (Test-Healthy) {
        # Send-Heartbeat owns the post-check-in re-read now, so that a check-in
        # whose result was an error, or which never moved the agent's heartbeat
        # age, cannot be reported as a success.
        Send-Heartbeat
        Invoke-Annotate
        if (Test-Degraded) { $Outcome = "DEGRADED" } else { $Outcome = "NO_ACTION_NEEDED" }
        Emit-Result 0
    }

    $WasInstalled = $Checks.installed
    Invoke-SafeFixes

    if (-not (Test-Healthy)) {
        switch ($Mode) {
            "install"   { if (-not $Checks.installed) { Invoke-DeploymentScript } }
            "reinstall" { if ($Checks.installed) { Invoke-DeploymentScript } }
            "safe"      { if (-not $Checks.installed) { Add-Blocker "needs_install_mode" } }
        }
    }

    Invoke-Annotate
    if (Test-Healthy) {
        if (Test-Degraded) { $Outcome = "DEGRADED" }
        elseif (-not $WasInstalled) { $Outcome = "INSTALLED" }
        else { $Outcome = "FIXED" }
        Emit-Result 0
    }
    $Outcome = "STILL_BROKEN"
    Emit-Result 0
} finally {
    if (-not $script:Emitted) {
        $Outcome = "ERROR"
        Emit-Result 1
    }
}
