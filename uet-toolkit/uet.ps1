# uet.ps1 -- PowerShell 5.1-compatible UET command-line port.
# Commands: triage, run, collect, delete. Secrets are read from environment,
# key files, or an interactive prompt; never written to logs.
[CmdletBinding()]
param(
    [string]$Command = "help",
    [string]$Config = "uet.toml",
    [string]$KeyFile = "",
    [string]$SwpKeyFile = "",
    [string]$Workdir = "",
    [string]$AxoniusCsv = "",
    [string]$ApprovedCsv = "",
    [string]$Transport = "ssh",
    [string]$Mode = "safe",
    [string]$Bucket = "",
    [int]$Canary = 0,
    [switch]$DryRun,
    [switch]$Execute,
    [switch]$AllowPublicTarget,
    [switch]$AllowNonStale,
    [switch]$NoDns,
    [int]$DnsTimeout = 5,
    [int]$DnsWorkers = 32,
    [int]$SettleAttempts = 3,
    [int]$SettleDelay = 60,
    [switch]$NoDispatch
)

$script:UetRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:UetRequestOverride = $null

function Write-UetLog([string]$Message) { [Console]::Error.WriteLine("uet: $Message") }
function ConvertTo-UetArray($Value) { if ($null -eq $Value) { return @() }; return @($Value) }
function Get-UetProperty($Object, [string]$Name, $Default = $null) {
    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name -and $null -ne $Object.$Name) { return $Object.$Name }
    return $Default
}
function ConvertTo-UetInt($Value, [int]$Default = 0) { try { return [int]$Value } catch { return $Default } }
function Get-UetNowIso { return [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Get-UetSafeName([string]$Name) { return [regex]::Replace($Name, "[^A-Za-z0-9_.-]", "_") }

function ConvertFrom-UetTomlValue([string]$Text) {
    $s = ($Text -replace "\s+#.*$", "").Trim()
    if ($s -match '^"(.*)"$') { return $Matches[1].Replace('\"','"').Replace('\\','\') }
    if ($s -match "^'(.*)'$") { return $Matches[1] }
    if ($s -match '^\[(.*)\]$') {
        $inside = $Matches[1].Trim(); if (-not $inside) { return @() }
        $parts = [regex]::Split($inside, ',(?=(?:[^\"'']|\"[^\"]*\"|''[^'']*'')*$)')
        return @($parts | ForEach-Object { ConvertFrom-UetTomlValue $_ })
    }
    if ($s -match '^(?i:true|false)$') { return $s.ToLowerInvariant() -eq 'true' }
    if ($s -match '^-?\d+$') { return [int64]$s }
    if ($s -match '^-?\d+\.\d+$') { return [double]$s }
    return $s
}

function ConvertFrom-UetToml([string]$Path) {
    $root = [ordered]@{}; $section = $root
    if (-not (Test-Path -LiteralPath $Path)) { return $root }
    foreach ($raw in Get-Content -LiteralPath $Path) {
        $line = ($raw -replace '\s+#.*$', '').Trim()
        if (-not $line) { continue }
        if ($line -match '^\[([^\]]+)\]$') {
            $section = $root
            foreach ($part in $Matches[1].Split('.')) {
                if (-not ($section.Contains($part))) { $section[$part] = [ordered]@{} }
                $section = $section[$part]
            }
            continue
        }
        if ($line -match '^([^=]+)=(.*)$') { $section[$Matches[1].Trim()] = ConvertFrom-UetTomlValue $Matches[2] }
    }
    return $root
}

function Get-UetConfig([string]$Path = "uet.toml") {
    $c = [ordered]@{ v1_base_url = "https://api.xdr.trendmicro.com"; swp_base_url = ""; stale_days = 90; snapshot_max_age_hours = 12; concurrency = 10; workdir = "uet-data"; ssh_user = "root"; ssm_region = ""; allowed_cidrs = @() }
    $raw = ConvertFrom-UetToml $Path
    if ($Workdir) { $c.workdir = $Workdir } elseif ($raw.Contains('workdir')) { $c.workdir = [string]$raw.workdir }
    if ($raw.Contains('v1') -and $raw.v1.Contains('base_url')) { $c.v1_base_url = [string]$raw.v1.base_url }
    if ($raw.Contains('swp') -and $raw.swp.Contains('base_url')) { $c.swp_base_url = [string]$raw.swp.base_url }
    if ($raw.Contains('triage')) { foreach ($k in @('stale_days','snapshot_max_age_hours')) { if ($raw.triage.Contains($k)) { $c[$k] = [int]$raw.triage[$k] } } }
    if ($raw.Contains('run')) {
        foreach ($k in @('concurrency','ssh_user','ssm_region','allowed_cidrs')) { if ($raw.run.Contains($k)) { $c[$k] = $raw.run[$k] } }
    }
    return [pscustomobject]$c
}

function Get-UetSecret([string]$EnvName, [string]$KeyFile = "", [switch]$Prompt) {
    $value = [Environment]::GetEnvironmentVariable($EnvName)
    if (-not $value -and $KeyFile) {
        if (-not (Test-Path -LiteralPath $KeyFile)) { throw "secret file not found: $KeyFile" }
        $value = (Get-Content -LiteralPath $KeyFile -Raw).Trim()
    }
    if (-not $value -and $Prompt) { $value = Read-Host "$EnvName (input hidden only when supported)" }
    if (-not $value) { throw "secret $EnvName not found; set $EnvName, pass a key file, or provide it interactively" }
    return $value.Trim()
}

function Invoke-UetRequest {
    param([ValidateSet('GET','POST','DELETE')] [string]$Method, [string]$Uri, [hashtable]$Headers, $Body = $null, [int]$MaxTries = 5)
    if ($script:UetRequestOverride) { return & $script:UetRequestOverride $Method $Uri $Headers $Body }
    $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 20 -Compress } else { $null }
    $last = $null
    for ($attempt = 0; $attempt -lt $MaxTries; $attempt++) {
        try {
            $params = @{ Method = $Method; Uri = $Uri; Headers = $Headers; TimeoutSec = 60; ErrorAction = 'Stop' }
            if ($null -ne $json) { $params.Body = $json; $params.ContentType = 'application/json' }
            $resp = Invoke-WebRequest @params
            if ([int]$resp.StatusCode -ge 400) { throw "HTTP $($resp.StatusCode): $($resp.Content)" }
            if ($resp.Content) { return ($resp.Content | ConvertFrom-Json) }
            return $null
        } catch {
            $last = $_
            $code = 0
            if ($_.Exception.Response) { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
            if ($code -notin @(429,500,502,503,504) -or $attempt -eq ($MaxTries - 1)) { throw }
            Start-Sleep -Seconds ([Math]::Min([Math]::Pow(2,$attempt),30))
        }
    }
    throw $last
}
function Get-UetV1Headers([string]$Key) { return @{ Authorization = "Bearer $Key" } }
function Get-UetSwpHeaders([string]$Key) { return @{ 'api-secret-key' = $Key; 'api-version' = 'v1' } }

function Get-UetV1Endpoints([string]$BaseUrl, [string]$Key) {
    $uri = "$($BaseUrl.TrimEnd('/'))/v3.0/endpointSecurity/endpoints?top=200"; $out = @()
    while ($uri) { $d = Invoke-UetRequest GET $uri (Get-UetV1Headers $Key); $out += @(Get-UetProperty $d items @()); $uri = [string](Get-UetProperty $d nextLink '') }
    return @($out)
}
function Get-UetSwpComputers([string]$BaseUrl, [string]$Key) {
    $uri = "$($BaseUrl.TrimEnd('/'))/api/computers/search?expand=computerStatus"; $out = @(); $last = 0
    while ($true) {
        $body = @{ maxItems = 1000; sortByObjectID = $true; searchCriteria = @(@{ fieldName='ID'; idValue=$last; idTest='greater-than' }) }
        $d = Invoke-UetRequest POST $uri (Get-UetSwpHeaders $Key) $body; $items = @(Get-UetProperty $d computers @()); if ($items.Count -eq 0) { break }; $out += $items; $last = [int]$items[-1].ID
    }
    return @($out)
}
function Get-UetSwpComputer([string]$BaseUrl,[string]$Key,[int]$Id) { return Invoke-UetRequest GET "$($BaseUrl.TrimEnd('/'))/api/computers/$Id?expand=computerStatus" (Get-UetSwpHeaders $Key) }
function Remove-UetSwpComputer([string]$BaseUrl,[string]$Key,[int]$Id) { $null = Invoke-UetRequest DELETE "$($BaseUrl.TrimEnd('/'))/api/computers/$Id" (Get-UetSwpHeaders $Key); return $true }
function Get-UetDeploymentScript([string]$BaseUrl,[string]$Key,[string]$Platform) {
    $d = Invoke-UetRequest POST "$($BaseUrl.TrimEnd('/'))/api/agentdeploymentscripts" (Get-UetSwpHeaders $Key) @{ platform=$Platform; activationRequired=$true; validateCertificateRequired=$true }; return [string]$d.scriptBody
}

function Get-UetShortName([string]$Name) { return (($Name -split '\.')[0]).ToLowerInvariant() }
function Get-UetSwpAgentGuid($Computer) { $v = Get-UetProperty $Computer agentGUID ''; if (-not $v) { $v = Get-UetProperty $Computer agentGuid '' }; return $v }
function Get-UetSwpCloudId($Computer) { $ec2 = Get-UetProperty $Computer ec2VirtualMachineSummary $null; if ($ec2 -and $ec2.instanceID) { return [string]$ec2.instanceID }; if ($Computer.azureVMId) { return [string]$Computer.azureVMId }; return $null }
function Build-UetEndpointIndex($Endpoints) {
    $idx = @{ by_guid=@{}; by_cloud_id=@{}; by_hostname=@{}; by_ip=@{} }
    foreach ($ep in $Endpoints) {
        if ($ep.agentGuid) { $idx.by_guid[[string]$ep.agentGuid] = $ep }
        $cid = Get-UetProperty (Get-UetProperty $ep eppAgent $null).virtualMachineDetails $null
        if ($cid -and $cid.cloudInstanceId) { $idx.by_cloud_id[[string]$cid.cloudInstanceId] = $ep }
        $name = ([string](Get-UetProperty $ep endpointName '')).ToLowerInvariant()
        if ($name) { foreach ($key in @($name,(Get-UetShortName $name))) { if ($idx.by_hostname.ContainsKey($key) -and $idx.by_hostname[$key] -ne $ep) { $idx.by_hostname[$key] = $null } else { $idx.by_hostname[$key] = $ep } } }
        if ($ep.lastUsedIp) { $idx.by_ip[[string]$ep.lastUsedIp] = $ep }
    }
    return $idx
}
function Find-UetMatch($Computer,$Index) {
    $guid = Get-UetSwpAgentGuid $Computer; if ($guid -and $Index.by_guid.ContainsKey($guid)) { return @($Index.by_guid[$guid],'agent_guid') }
    $cid = Get-UetSwpCloudId $Computer; if ($cid -and $Index.by_cloud_id.ContainsKey($cid)) { return @($Index.by_cloud_id[$cid],'cloud_id') }
    foreach ($field in @('hostName','displayName')) { $name = ([string](Get-UetProperty $Computer $field '')).ToLowerInvariant(); if ($name) { foreach ($key in @($name,(Get-UetShortName $name))) { if ($Index.by_hostname.ContainsKey($key) -and $null -ne $Index.by_hostname[$key]) { return @($Index.by_hostname[$key],'hostname') } } } }
    $ip = [string](Get-UetProperty $Computer lastIPUsed ''); if ($ip -and $Index.by_ip.ContainsKey($ip)) { return @($Index.by_ip[$ip],'ip') }
    return @($null,'none')
}
function Test-UetV1Connected($Endpoint) { foreach ($k in @('eppAgent','edrSensor')) { $x = Get-UetProperty $Endpoint $k $null; if ($x -and (Get-UetProperty $x lastConnectedDateTime '')) { return $true } }; return $false }
function Get-UetAxoniusHosts([string]$Path) { $h = @{}; if (-not $Path) { return $h }; foreach ($r in (Import-Csv -LiteralPath $Path)) { if ($r.hostname) { $s = Get-UetShortName $r.hostname; if ($s -and $s -notmatch '^\d+$' -and $s -ne 'localhost') { $h[$s] = $true } } }; return $h }
function Get-UetLiveness($Computer,$Match,$Axonius,[switch]$NoDns) {
    foreach ($field in @('hostName','displayName')) { $s=Get-UetShortName ([string](Get-UetProperty $Computer $field '')); if ($Axonius.ContainsKey($s)) { return $true } }
    if ($Match -and $Match.agentGuid -and (Test-UetV1Connected $Match)) { return $true }
    if ($NoDns) { return $null }
    $host = [string](Get-UetProperty $Computer hostName ''); if (-not $host) { return $null }
    foreach ($name in @($host,(Get-UetShortName $host))) { try { $null = [System.Net.Dns]::GetHostAddresses($name); return $null } catch [System.Net.Sockets.SocketException] {} catch { return $null } }
    return $false
}
function Get-UetClassification($Computer,$Liveness,[long]$NowMs,[int]$StaleDays) {
    $status=[string](Get-UetProperty (Get-UetProperty $Computer computerStatus $null) agentStatus 'unknown'); $fp=Get-UetProperty $Computer agentFingerPrint ''; $last=Get-UetProperty $Computer lastAgentCommunication $null; $days=$null; if ($last) { $days=($NowMs-[double]$last)/86400000 }
    if ($fp -and $status -eq 'active') { return $null }
    $ev = New-Object System.Collections.ArrayList; [void]$ev.Add("swp:agentStatus=$status"); if ($null -ne $days) {[void]$ev.Add(('swp:offline_days={0:0}' -f $days))} else {[void]$ev.Add('swp:never_communicated')}; if ($Liveness -eq $true) {[void]$ev.Add('liveness:host_appears_live')} elseif ($Liveness -eq $false) {[void]$ev.Add('liveness:host_appears_gone')} else {[void]$ev.Add('liveness:unknown')}
    if (-not $fp) { [void]$ev.Add('swp:never_activated'); if ($Liveness -eq $false) { return [pscustomobject]@{bucket='STALE';evidence=@($ev);recommended_mode='none'} }; if ($Liveness -eq $true) { return [pscustomobject]@{bucket='NEEDS_INSTALL';evidence=@($ev);recommended_mode='install'} }; return [pscustomobject]@{bucket='INVESTIGATE';evidence=@($ev);recommended_mode='none'} }
    if ($Liveness -eq $true) { return [pscustomobject]@{bucket='NEEDS_REPAIR';evidence=@($ev);recommended_mode='safe'} }
    $stale=($null -ne $days -and $days -gt $StaleDays); if ($stale -and $Liveness -eq $false) { return [pscustomobject]@{bucket='STALE';evidence=@($ev);recommended_mode='none'} }; if (-not $stale -and $null -ne $days) { return [pscustomobject]@{bucket='NEEDS_REPAIR';evidence=@($ev);recommended_mode='safe'} }; if ($null -eq $days -and $Liveness -eq $false) { return [pscustomobject]@{bucket='STALE';evidence=@($ev);recommended_mode='none'} }; return [pscustomobject]@{bucket='INVESTIGATE';evidence=@($ev);recommended_mode='none'}
}

function Write-UetSnapshots([string]$Dir,$Name,$Data) { $d=Join-Path $Dir 'snapshots'; New-Item -ItemType Directory -Force $d | Out-Null; $p=Join-Path $d ("$Name-"+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.json'); $Data | ConvertTo-Json -Depth 30 | Set-Content -Encoding UTF8 $p; return $p }
function Write-UetWorklist($Items,[string]$Dir) {
    New-Item -ItemType Directory -Force $Dir | Out-Null; $payload=[ordered]@{schema='uet-worklist/1';generated=(Get-UetNowIso);items=@($Items)}; $payload | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 (Join-Path $Dir 'worklist.json')
    $Items | ForEach-Object { [pscustomobject]@{hostname=$_.hostname;swp_id=$_.swp_id;agent_guid=$_.agent_guid;ips=($_.ips -join ';');os=$_.os;bucket=$_.bucket;evidence=($_.evidence -join ';');recommended_mode=$_.recommended_mode;match_tier=$_.match_tier} } | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Dir 'worklist.csv')
}
function Read-UetWorklist([string]$Path) { $d=Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json; if ($d.schema -ne 'uet-worklist/1') { throw "unexpected worklist schema: $($d.schema)" }; return @($d.items) }

function Get-UetTemplate([string]$Name) { $p=Join-Path $script:UetRoot (Join-Path 'payloads' $Name); if (-not (Test-Path $p)) { throw "payload template not found: $p" }; return Get-Content -Raw -LiteralPath $p }
function Get-UetDsmUrl([string]$Script) { $m=[regex]::Match($Script,'dsm://[^\s''"]+'); if($m.Success){return $m.Value};return '' }
function Get-UetActivationArgs([string]$Script) { foreach($line in ($Script -split "`n")){ $m=[regex]::Match($line,'dsa_control["'']?\s+-a\s+\S+((?:\s+"[^"]+")+)',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase);if($m.Success){return (([regex]::Matches($m.Groups[1].Value,'"([^"]+)"')|ForEach-Object{$_.Groups[1].Value}) -join ' ')}};return '' }
function Embed-UetPayload([string]$Text,[string]$Dsm,[string]$DeployB64,[string]$Activation,[ValidateSet('sh','ps1')][string]$Style) {
    if ($Style -eq 'sh') {
        $pairs = @(
            @('UET_DSM_URL=""  # __UET_DSM_URL__', ('UET_DSM_URL="{0}"' -f $Dsm)),
            @('UET_DEPLOY_B64=""  # __UET_DEPLOY_B64__', ('UET_DEPLOY_B64="{0}"' -f $DeployB64)),
            @('UET_ACTIVATION_ARGS=""  # __UET_ACTIVATION_ARGS__', ('UET_ACTIVATION_ARGS="{0}"' -f $Activation))
        )
    } else {
        $pairs = @(
            @('$UetDsmUrl = ""  # __UET_DSM_URL__', ('$UetDsmUrl = "{0}"' -f $Dsm)),
            @('$UetDeployB64 = ""  # __UET_DEPLOY_B64__', ('$UetDeployB64 = "{0}"' -f $DeployB64)),
            @('$UetActivationArgs = ""  # __UET_ACTIVATION_ARGS__', ('$UetActivationArgs = "{0}"' -f $Activation))
        )
    }
    foreach ($p in $pairs) {
        if ($Text.IndexOf($p[0], [StringComparison]::Ordinal) -lt 0) { throw "payload sentinel missing: $($p[0])" }
        $Text = $Text.Replace($p[0], $p[1])
    }
    return $Text
}
function Write-UetGeneratedPayloads([string]$Dir,[string]$SwpBase,[string]$Key) {
    $out=Join-Path $Dir 'payloads';New-Item -ItemType Directory -Force $out|Out-Null
    foreach($x in @(@('linux','check-fix-agent.sh','sh','check-fix-agent-linux.sh'),@('windows','check-fix-agent.ps1','ps1','check-fix-agent-windows.ps1'))){$body=Get-UetDeploymentScript $SwpBase $Key $x[0];$b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body));$txt=Embed-UetPayload (Get-UetTemplate $x[1]) (Get-UetDsmUrl $body) $b64 (Get-UetActivationArgs $body) $x[2];$p=Join-Path $out $x[3];[IO.File]::WriteAllText($p,$txt,(New-Object Text.UTF8Encoding($false)));try{icacls $p /inheritance:r /grant:r "$env:USERNAME:(R,W)"|Out-Null}catch{}}
}

function Invoke-UetTriage([object]$Cfg,[string]$V1Key,[string]$SwpKey) {
    if (-not $Cfg.swp_base_url) { throw '[swp] base_url missing in config' }; $v1=Get-UetV1Endpoints $Cfg.v1_base_url $V1Key; $swp=Get-UetSwpComputers $Cfg.swp_base_url $SwpKey; Write-UetSnapshots $Cfg.workdir 'v1-endpoints' $v1|Out-Null;Write-UetSnapshots $Cfg.workdir 'swp-computers' $swp|Out-Null
    $ax=Get-UetAxoniusHosts $AxoniusCsv;$idx=Build-UetEndpointIndex $v1;$items=@();$now=([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds());foreach($comp in $swp){$hit=Find-UetMatch $comp $idx;$match=$hit[0];$tier=$hit[1];$live=Get-UetLiveness $comp $match $ax -NoDns:$NoDns;$cls=Get-UetClassification $comp $live $now $Cfg.stale_days;if($null -eq $cls){continue};$host=[string](Get-UetProperty $comp hostName (Get-UetProperty $comp displayName "swp-$($comp.ID)"));$os=[string](Get-UetProperty $comp platform '');if(((-not $os)-or $os -match '(?i)unknown') -and $match -and $match.osPlatform){$os=$match.osPlatform};$ev=@($cls.evidence)+@("match:$tier");if($live -eq $false){$ev+=@('liveness:dns_unresolved')};$items+=,[pscustomobject]@{hostname=$host;swp_id=[int]$comp.ID;agent_guid=[string](Get-UetSwpAgentGuid $comp);ips=@([string](Get-UetProperty $comp lastIPUsed '')|Where-Object{$_});os=$os;bucket=$cls.bucket;evidence=$ev;recommended_mode=$cls.recommended_mode;match_tier=$tier}}
    Write-UetWorklist $items $Cfg.workdir;Write-UetGeneratedPayloads $Cfg.workdir $Cfg.swp_base_url $SwpKey;Write-Output "worklist written: $(Join-Path $Cfg.workdir 'worklist.json')";return $items
}

function Test-UetAllowedIp([string]$Ip,$AllowedCidrs) { try{$a=[Net.IPAddress]::Parse($Ip);if($a.IsIPv4MappedToIPv6){$a=$a.MapToIPv4()};if($a.IsLoopback -or $a.IsLinkLocal -or $a.IsPrivate){return $true};foreach($cidr in @($AllowedCidrs)){try{$parts=$cidr.Split('/');$net=[Net.IPAddress]::Parse($parts[0]);$prefix=[int]$parts[1];$bytes=$a.GetAddressBytes();$nb=$net.GetAddressBytes();$full=[Math]::Floor($prefix/8);$rem=$prefix%8;$ok=$true;for($i=0;$i -lt $full;$i++){if($bytes[$i] -ne $nb[$i]){$ok=$false;break}};if($ok -and $rem -gt 0 -and (($bytes[$full] -band (0xFF -shl (8-$rem))) -ne ($nb[$full] -band (0xFF -shl (8-$rem))))){$ok=$false};if($ok){return $true}}catch{throw "invalid allowed CIDR: $cidr"}}}catch{return $false};return $false }
function Resolve-UetTarget($Item,$Cfg,[switch]$Allow) { foreach($ip in @($Item.ips)){if(Test-UetAllowedIp $ip $Cfg.allowed_cidrs){return $ip}};$h=[string]$Item.hostname;if(Test-UetAllowedIp $h $Cfg.allowed_cidrs){return $h};if($Allow){return $h};try{$ip=([Net.Dns]::GetHostAddresses($h)|Select-Object -First 1).IPAddressToString}catch{throw "target refused ${h}: hostname does not resolve"};if(-not(Test-UetAllowedIp $ip $Cfg.allowed_cidrs)){throw "target refused ${h}: resolves to public address $ip"};return $h }
function Invoke-UetHost($Item,[string]$Payload,[string]$TransportName,[string]$Mode,[bool]$Dry,[object]$Cfg,[string]$Target) {
    if($TransportName -eq 'ssh'){ $args=@('-o','BatchMode=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=accept-new',"$($Cfg.ssh_user)@$Target",("sudo -n bash -s -- --mode $Mode"+$(if($Dry){' --dry-run'}else{''})));$p=Start-Process -FilePath 'ssh' -ArgumentList $args -RedirectStandardInput $Payload -RedirectStandardOutput ([IO.Path]::GetTempFileName()) -RedirectStandardError ([IO.Path]::GetTempFileName()) -Wait -PassThru;return $p.ExitCode }
    if($TransportName -eq 'winrm'){ $script=Get-Content -Raw -LiteralPath $Payload;$sb=[scriptblock]::Create($script);try{$o=Invoke-Command -ComputerName $Target -ScriptBlock $sb -ArgumentList @('-Mode',$Mode) -ErrorAction Stop;return 0}catch{Write-UetLog $_;return 1} }
    if($TransportName -eq 'ssm'){ throw 'ssm transport requires AWS tooling; use ssh or winrm in this PowerShell port' }
    throw "unknown transport: $TransportName"
}
function Invoke-UetRun([object]$Cfg) {
    $items=Read-UetWorklist (Join-Path $Cfg.workdir 'worklist.json');if($Bucket){$items=@($items|Where-Object{$_.bucket -eq $Bucket})};$todo=@();$results=Join-Path $Cfg.workdir 'results';New-Item -ItemType Directory -Force $results|Out-Null;$seen=@{};foreach($i in $items){$safe=Get-UetSafeName $i.hostname;if((Test-Path (Join-Path $results "$safe.json")) -or $seen.ContainsKey($safe)){continue};$seen[$safe]=$true;$todo+=,$i};if($Canary -gt 0){$todo=@($todo|Select-Object -First $Canary)};foreach($i in $todo){$target=$null;$err=$null;try{$target=Resolve-UetTarget $i $Cfg -Allow:$AllowPublicTarget}catch{$err=$_.Exception.Message};$safe=Get-UetSafeName $i.hostname;if($err){"rc=126`nstdout:`n`nstderr:`ntarget refused: $err"|Set-Content (Join-Path $results "$safe.error.txt");continue};$isWin=($Transport -eq 'winrm' -or ([string]$i.os -match '(?i)windows'));$p=Join-Path $Cfg.workdir ('payloads/'+$(if($isWin){'check-fix-agent-windows.ps1'}else{'check-fix-agent-linux.sh'}));if(-not(Test-Path $p)){throw "payload not found: $p — run triage first"};try{$rc=Invoke-UetHost $i $p $Transport $Mode $DryRun $Cfg $target;"rc=$rc"|Out-Null}catch{$rc=1};$path=Join-Path $results "$safe.error.txt";"rc=$rc`nstdout:`n`nstderr:`n"|Set-Content $path};Write-Output "ran $($todo.Count) hosts; results in $results"
}
function Get-UetResultJson($Path) { try{return (Get-Content -Raw -LiteralPath $Path|ConvertFrom-Json)}catch{return $null} }
function Invoke-UetCollect([object]$Cfg,[string]$SwpKey) {
    $items=Read-UetWorklist (Join-Path $Cfg.workdir 'worklist.json');$rows=@();$rd=Join-Path $Cfg.workdir 'results';foreach($i in $items){$safe=Get-UetSafeName $i.hostname;$r=Get-UetResultJson (Join-Path $rd "$safe.json");$out='NOT_RUN';$actions=@();$blockers=@();if($r){$out=[string]$r.outcome;$actions=@($r.actions);$blockers=@($r.blockers)}elseif(Test-Path (Join-Path $rd "$safe.error.txt")){$out='TRANSPORT_ERROR'};$rows+=,[pscustomobject]@{hostname=$i.hostname;swp_id=$i.swp_id;bucket=$i.bucket;evidence=($i.evidence -join ';');outcome=$out;actions=($actions -join ';');blockers=($blockers -join ';');console_status='unknown';verified=$false}}
    $status=@{};foreach($c in (Get-UetSwpComputers $Cfg.swp_base_url $SwpKey)){$status[[int]$c.ID]=[string](Get-UetProperty (Get-UetProperty $c computerStatus $null) agentStatus 'unknown')};foreach($r in $rows){$r.console_status=if($status.ContainsKey([int]$r.swp_id)){$status[[int]$r.swp_id]}else{'gone'};$r.verified=($r.outcome -in @('FIXED','INSTALLED','NO_ACTION_NEEDED') -and $r.console_status -eq 'active')};$p=Join-Path $Cfg.workdir 'final-report.csv';$rows|Export-Csv -NoTypeInformation -Encoding UTF8 $p;Write-Output "final report: $p";return $rows
}
function Invoke-UetDelete([object]$Cfg,[string]$SwpKey) {
    if(-not $ApprovedCsv){throw '-ApprovedCsv is required'};$all=Import-Csv -LiteralPath $ApprovedCsv;if(-not $all){Write-Output 'nothing approved; no action taken';return};if(-not($all[0].PSObject.Properties.Name -contains 'approved')){throw "CSV must contain an approved column"};$rows=@($all|Where-Object{([string]$_.approved).Trim().ToLowerInvariant() -eq 'yes'});if(-not $AllowNonStale){if(-not($all[0].PSObject.Properties.Name -contains 'bucket')){throw "CSV has no bucket column; pass -AllowNonStale to override"};$bad=@($rows|Where-Object{([string]$_.bucket).Trim().ToUpperInvariant() -ne 'STALE'});if($bad.Count){throw "$($bad.Count) approved row(s) are not STALE; pass -AllowNonStale only deliberately"}}
$backup=@();$parsed=@();foreach($r in $rows){try{$id=[int]$r.swp_id}catch{continue};try{$backup+=, (Get-UetSwpComputer $Cfg.swp_base_url $SwpKey $id);$parsed+=,[pscustomobject]@{row=$r;id=$id}}catch{Write-UetLog ("backup failed for {0}: {1}" -f $id,$_.Exception.Message)}};New-Item -ItemType Directory -Force $Cfg.workdir|Out-Null;$bp=Join-Path $Cfg.workdir ('delete-backup-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.json');$backup|ConvertTo-Json -Depth 30|Set-Content -Encoding UTF8 $bp;if(-not $Execute){Write-Output "DRY RUN: would delete $($parsed.Count) computers (backup: $bp)";return};$n=0;foreach($x in $parsed){try{Remove-UetSwpComputer $Cfg.swp_base_url $SwpKey $x.id|Out-Null;$n++}catch{Write-UetLog "delete failed for $($x.id): $($_.Exception.Message)"}};Write-Output "deleted $n/$($parsed.Count) computers; backup: $bp"
}

if (-not $NoDispatch) {
    try {
        $cfg=Get-UetConfig $Config
        switch ($Command.ToLowerInvariant()) {
            'triage' { $v1=Get-UetSecret 'V1_API_KEY' $KeyFile -Prompt; $swp=Get-UetSecret 'SWP_API_SECRET' $SwpKeyFile -Prompt; Invoke-UetTriage $cfg $v1 $swp|Out-Null }
            'run' { Invoke-UetRun $cfg }
            'collect' { $swp=Get-UetSecret 'SWP_API_SECRET' $SwpKeyFile -Prompt; Invoke-UetCollect $cfg $swp|Out-Null }
            'delete' { $swp=Get-UetSecret 'SWP_API_SECRET' $SwpKeyFile -Prompt; Invoke-UetDelete $cfg $swp }
            default { Write-Output 'uet.ps1 commands: triage, run, collect, delete'; Write-Output 'use -Command <command> -Config uet.toml' }
        }
        exit 0
    } catch { [Console]::Error.WriteLine("error: $($_.Exception.Message)"); exit 1 }
}
