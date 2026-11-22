$ErrorActionPreference='Stop'
$private=Join-Path $PSScriptRoot 'Device Data'
$configFile=Join-Path $private 'Device Config.json'
$encryptedFile=Join-Path $private 'Device Token.dpapi'
if(!(Test-Path -LiteralPath $configFile) -or !(Test-Path -LiteralPath $encryptedFile)){throw 'Device has not been locally enrolled. Run Initialize ShanX13 Device.ps1 on THIS computer.'}
$config=Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
$chosen=Read-Host 'Choose STOP (no remote control), LIMITED (read-only), or GO (allow locally approved new files)'
$chosen=$chosen.Trim().ToUpperInvariant()
if($chosen -notin @('STOP','LIMITED','GO')){throw 'Invalid mode; no agent started.'}
if($chosen -eq 'STOP'){Write-Host 'STOP selected. This does not contact other devices.';exit 0}
if($chosen -eq 'GO'){
 $confirm=Read-Host 'Confirm that ONLY creating new files in the selected customer workspace is authorized. Type YES'
 if($confirm -ne 'YES'){throw 'Write authorization not granted.'}
}
$secure=Get-Content -LiteralPath $encryptedFile -Raw |ConvertTo-SecureString
$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try{$env:SHANX_AGENT_TOKEN=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}
finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}
$env:SHANX_AGENT_MODE=$chosen
$env:SHANX_AGENT_CONFIG=$configFile
$env:SHANX_AGENT_WRITE_APPROVED=if($chosen -eq 'GO'){'YES'}else{'NO'}
try {
 & node (Join-Path $PSScriptRoot 'customer-device-runner.mjs')
 if($LASTEXITCODE -ne 0){throw 'Agent reported an error. Verify device and cloud state before retrying.'}
}finally {
 Remove-Item Env:SHANX_AGENT_TOKEN -ErrorAction SilentlyContinue
 Remove-Item Env:SHANX_AGENT_MODE -ErrorAction SilentlyContinue
 Remove-Item Env:SHANX_AGENT_WRITE_APPROVED -ErrorAction SilentlyContinue
 Remove-Item Env:SHANX_AGENT_CONFIG -ErrorAction SilentlyContinue
}
