# bulk-delete.ps1 -- standalone SWP computer deletion tool.
# Input CSV must contain swp_id and hostname. Dry-run is the default; use
# -Execute only after reviewing the backup and preview. The API key is prompted
# for unless SWP_API_SECRET is already set.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$Csv,
    [string]$BaseUrl = "",
    [string]$ApiKey = "",
    [switch]$Execute,
    [switch]$SkipConfirmation,
    [int]$BatchSize = 50,
    [string]$BackupPath = ""
)

function Fail([string]$Message) { throw $Message }
function Read-Secret {
    if ($ApiKey) { return $ApiKey.Trim() }
    if ($env:SWP_API_SECRET) { return $env:SWP_API_SECRET.Trim() }
    $secure = Read-Host "SWP API key" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
function Request([string]$Method,[string]$Uri,[hashtable]$Headers,$Body=$null) {
    $p=@{Method=$Method;Uri=$Uri;Headers=$Headers;TimeoutSec=60;ErrorAction='Stop'}
    if ($null -ne $Body) { $p.Body=$Body|ConvertTo-Json -Depth 20 -Compress;$p.ContentType='application/json' }
    $r=Invoke-WebRequest @p
    if ([int]$r.StatusCode -ge 400) { throw "HTTP $($r.StatusCode): $($r.Content)" }
    if ($r.Content) { return $r.Content|ConvertFrom-Json }
    return $null
}
function Get-Computer([string]$Base,[hashtable]$Headers,[int]$Id) { Request GET "$($Base.TrimEnd('/'))/api/computers/$Id?expand=computerStatus" $Headers }
function Delete-Computer([string]$Base,[hashtable]$Headers,[int]$Id) { Request DELETE "$($Base.TrimEnd('/'))/api/computers/$Id" $Headers|Out-Null }

try {
    if (-not (Test-Path -LiteralPath $Csv)) { Fail "CSV not found: $Csv" }
    if (-not $BaseUrl) { $BaseUrl=$env:SWP_BASE_URL }
    if (-not $BaseUrl) { Fail "provide -BaseUrl or set SWP_BASE_URL" }
    $rows=@(Import-Csv -LiteralPath $Csv)
    if (-not $rows.Count) { Write-Output 'CSV is empty; no action taken'; exit 0 }
    $fields=@($rows[0].PSObject.Properties.Name)
    foreach($required in @('swp_id','hostname')) { if ($fields -notcontains $required) { Fail "CSV must contain '$required'" } }
    $targets=@()
    foreach($row in $rows){$id=0;if(-not[int]::TryParse(([string]$row.swp_id),[ref]$id)){Fail "invalid swp_id '$($row.swp_id)' for $($row.hostname)"};$targets+=,[pscustomobject]@{id=$id;hostname=[string]$row.hostname}}
    $key=Read-Secret;$headers=@{'api-secret-key'=$key;'api-version'='v1'}
    $records=@();$errors=@()
    foreach($t in $targets){try{$records+=,(Get-Computer $BaseUrl $headers $t.id)}catch{$errors+=,"backup swp_id=$($t.id) $($_.Exception.Message)"}}
    if(-not $BackupPath){$BackupPath=Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $Csv)) ('delete-backup-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.json')}
    $records|ConvertTo-Json -Depth 30|Set-Content -Encoding UTF8 $BackupPath
    Write-Output "backup: $BackupPath ($($records.Count) records)"
    if($errors.Count){$errors|ForEach-Object{Write-Warning $_};Fail 'backup failed for one or more rows; nothing was deleted'}
    Write-Output "preview: $($targets.Count) computers"
    $targets|ForEach-Object{Write-Output ("  swp_id={0} hostname={1}" -f $_.id,$_.hostname)}
    if(-not $Execute){Write-Output 'DRY RUN: no API deletes issued. Re-run with -Execute after reviewing the preview.';exit 0}
    if(-not $SkipConfirmation){$answer=Read-Host "Type DELETE to remove these $($targets.Count) computers";if($answer -cne 'DELETE'){Write-Output 'confirmation did not match; no action taken';exit 0}}
    $deleted=0
    for($offset=0;$offset -lt $targets.Count;$offset+=$BatchSize){$batch=@($targets|Select-Object -Skip $offset -First $BatchSize);foreach($t in $batch){try{Delete-Computer $BaseUrl $headers $t.id;$deleted++;Write-Output "deleted swp_id=$($t.id) hostname=$($t.hostname)"}catch{Write-Warning "delete failed swp_id=$($t.id): $($_.Exception.Message)"}}}
    Write-Output "deleted $deleted/$($targets.Count); backup: $BackupPath"
    if($deleted -ne $targets.Count){exit 1};exit 0
} catch { [Console]::Error.WriteLine("error: $($_.Exception.Message)");exit 1 }
