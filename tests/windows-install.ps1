# CI ONLY: actual install/task execution on a disposable GitHub-hosted Windows runner.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){ throw 'Requires disposable GitHub Actions runner' }
if(Test-Path 'C:\tcdc-baseline'){ throw 'Refusing existing baseline' }
$repo=Split-Path $PSScriptRoot -Parent
function Wait-Watcher {
  $deadline=(Get-Date).AddSeconds(60)
  do {
    Start-Sleep -Seconds 2
    $task=Get-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\'
    $info=Get-ScheduledTaskInfo -TaskName 'TCDC-Watch' -TaskPath '\'
  } while(($task.State -eq 'Running' -or $info.LastRunTime.Year -lt 2020) -and (Get-Date) -lt $deadline)
  if($task.State -eq 'Running' -or $info.LastTaskResult -ne 0){ throw "Watcher runtime failure: $($info.LastTaskResult)" }
}
try {
  $refused=$false
  try { & (Join-Path $repo 'windows/harden.ps1') -Box ci-fixture } catch { $refused=$_.Exception.Message -match 'requires review' }
  if(-not $refused){ throw 'Initial capture accepted without review flag' }
  & (Join-Path $repo 'windows/harden.ps1') -Box ci-fixture -AcceptInitialState
  Wait-Watcher
  $file='C:\tcdc-baseline\integrity.json'
  $before=(Get-FileHash $file).Hash
  & (Join-Path $repo 'windows/harden.ps1') -Box ci-fixture -AcceptInitialState
  Wait-Watcher
  if((Get-FileHash $file).Hash -ne $before){ throw 'Rerun changed accepted baseline' }
  # Change only our installed helper file by appending a harmless comment; verify the scheduled watcher logs it.
  Add-Content 'C:\tcdc-baseline\ad-harden.ps1' '# CI harmless canary'
  Start-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\'
  Wait-Watcher
  if(-not (Select-String -Path 'C:\tcdc-baseline\drift.log' -Pattern 'CHANGED Files : ad-harden.ps1' -Quiet)){ throw 'Watcher missed its own module change' }
  Copy-Item (Join-Path $repo 'windows/ad-harden.ps1') 'C:\tcdc-baseline\ad-harden.ps1' -Force
  . (Join-Path $repo 'windows/common.ps1')
  $changes=@(Compare-TcdcSnapshot (Read-TcdcBaseline $file) (Get-TcdcSnapshot 'C:\tcdc-baseline'))
  if($changes.Count){ throw ('Unexpected post-restore drift: ' + ($changes -join '; ')) }
  & powershell.exe -NoProfile -File (Join-Path $repo 'windows/health.ps1')
  if($LASTEXITCODE -ne 0){ throw 'Independent health check failed' }
  Disable-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\' | Out-Null
  & powershell.exe -NoProfile -File (Join-Path $repo 'windows/health.ps1')
  if($LASTEXITCODE -eq 0){ throw 'Health check missed disabled task' }
  $global:LASTEXITCODE=0
  Enable-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\' | Out-Null
  Write-Host 'PASS: real Windows install, SYSTEM task run, rerun preservation, module tamper detection and restore'
} finally {
  $task=Get-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\' -ErrorAction SilentlyContinue
  if($task){ Stop-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\'; Unregister-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\' -Confirm:$false }
}
