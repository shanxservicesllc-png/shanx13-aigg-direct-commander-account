param(
 [string]$Service = 'https://shanx13-aigg-direct-commander-agent.henry-shannon.workers.dev'
)
$ErrorActionPreference='Stop'
$node=Get-Command node -ErrorAction SilentlyContinue
if(-not $node){throw 'Node.js 24 is required to run this customer agent. No installation was performed.'}
$workspace=Read-Host 'Enter the full path of the folder this device may access (it MUST already exist)'
if(-not (Test-Path -LiteralPath $workspace -PathType Container)){throw 'Approved workspace folder does not exist.'}
$workspace=(Resolve-Path -LiteralPath $workspace).Path
$secure=Read-Host 'Paste your one-time device enrollment token (hidden input)' -AsSecureString
$pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try{$token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)}
finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)}
if($token -cnotmatch '^[a-f0-9]{96}$'){throw 'Invalid one-time token format.'}
$service=$Service.TrimEnd('/')
if(-not $service.StartsWith('https://')){throw 'A verified HTTPS service is required.'}
try {
 $response=Invoke-RestMethod -Method POST -Uri ($service+'/api/agent/control/bootstrap') -ContentType 'application/json' -Headers @{Authorization=('Bearer '+$token)} -Body '{}' -TimeoutSec 15 -MaximumRedirection 0
 if($response.device_id -notmatch '^[A-Za-z0-9_-]{3,100}$' -or $response.tenant_id -notmatch '^[A-Za-z0-9_-]{3,100}$' -or $response.mode -ne 'STOP'){throw 'Service did not return a safe initial device state.'}
} catch {
 Write-Host 'Cannot verify this device against the commercial service. No credentials or configuration were saved. Confirm account access before retrying.' -ForegroundColor Yellow
 exit 1
}
$private=Join-Path $PSScriptRoot 'Device Data'
if(Test-Path -LiteralPath $private){throw 'Existing device enrollment found; do not overwrite credentials. Use the existing agent or inspect enrollment.'}
New-Item -ItemType Directory -Path $private |Out-Null
$dpapi=ConvertTo-SecureString $token -AsPlainText -Force | ConvertFrom-SecureString
[IO.File]::WriteAllText((Join-Path $private 'Device Token.dpapi'),$dpapi,[Text.UTF8Encoding]::new($false))
$config=[ordered]@{serviceUrl=$service;tenantId=$response.tenant_id;deviceId=$response.device_id;workspaceRoot=$workspace;journalPath=(Join-Path $private 'Device Journal.ndjson')}
[IO.File]::WriteAllText((Join-Path $private 'Device Config.json'),($config | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
$token=$null
Write-Host 'Customer device enrolled locally. Device remains in STOP until you explicitly authorize LIMITED or GO.' -ForegroundColor Green
Write-Host ('Device: '+$response.device_id)
Write-Host ('Customer workspace: '+$workspace)
