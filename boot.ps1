# Prefer a reviewed local checkout. For remote use, set $Ref to the same SHA as this bootstrap.
$ErrorActionPreference='Stop'
if($Ref -notmatch '^[0-9a-fA-F]{40}$'){ throw 'Set $Ref to a reviewed 40-character commit SHA before downloading' }
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
  & (Join-Path $dir 'harden.ps1') -Box $box -AcceptInitialState:([bool]$AcceptInitialState) -Rebaseline:([bool]$Rebaseline)
  Write-Host 'DC: review AD groups, then run C:\tcdc-baseline\ad-harden.ps1 -AcceptInitialState to capture their baseline.'
} finally {
  Remove-Item $dir -Recurse -Force
}
