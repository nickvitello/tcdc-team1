# Prefer a reviewed local checkout. For remote use, set $Ref to the same SHA as this bootstrap.
$ErrorActionPreference='Stop'
$Ref=if($Ref){$Ref}else{'main'}
if($Ref -notmatch '^[A-Za-z0-9._-]+$'){ throw 'Invalid revision' }
$box=if($Box){$Box}else{$env:COMPUTERNAME}
$raw="https://raw.githubusercontent.com/nickvitello/tcdc-team1/$Ref/windows"
$dir=Join-Path $env:TEMP ('tcdc-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  foreach($file in 'harden.ps1','watch-agent.ps1','ad-harden.ps1','common.ps1'){
    Invoke-WebRequest "$raw/$file" -OutFile (Join-Path $dir $file) -UseBasicParsing -TimeoutSec 60
    if((Get-Item (Join-Path $dir $file)).Length -eq 0){ throw "Empty module: $file" }
  }
  # Invoke the script in PowerShell, not through a native -File boundary. No array coercion.
  & (Join-Path $dir 'harden.ps1') -Box $box
  Write-Host 'DC: run C:\tcdc-baseline\ad-harden.ps1 to establish and review AD group baselines.'
} finally {
  Remove-Item $dir -Recurse -Force
}
