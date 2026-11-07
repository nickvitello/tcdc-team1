# Independent read-only check: run from a trusted checkout, not the installed baseline directory.
$ErrorActionPreference='Stop'
$issues=@()
try {
  $task=Get-ScheduledTask -TaskName 'TCDC-Watch' -TaskPath '\' -ErrorAction Stop
  $info=Get-ScheduledTaskInfo -TaskName 'TCDC-Watch' -TaskPath '\' -ErrorAction Stop
  if($task.State -eq 'Disabled'){ $issues+='watcher task disabled' }
  if($info.LastTaskResult -ne 0){ $issues+='last task result is failed, running, or unverified' }
  $age=((Get-Date)-$info.LastRunTime).TotalSeconds
  if($age -lt 0 -or $age -gt 300 -or $info.LastRunTime.Year -lt 2020){ $issues+='no recent watcher execution' }
  foreach($name in 'common.ps1','watch-agent.ps1','ad-harden.ps1'){
    $installed=Join-Path 'C:\tcdc-baseline' $name
    if((Get-Item $installed -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){ $issues+="module is a reparse point: $name" }
    if((Get-FileHash $installed).Hash -ne (Get-FileHash (Join-Path $PSScriptRoot $name)).Hash){ $issues+="installed module differs from trusted checkout: $name" }
  }
  if(-not (Test-Path 'C:\tcdc-baseline\integrity.json')){ $issues+='accepted baseline missing' }
} catch { $issues+=('health collection failed: '+$_.Exception.Message) }
if($issues.Count){ $issues | ForEach-Object { Write-Host "UNHEALTHY: $_" }; exit 1 }
Write-Host 'HEALTHY: recent successful task run and installed module hashes match this checkout'
Write-Host 'This local observation cannot establish trust in an administrator-compromised OS. Review drift.log separately.'
exit 0
