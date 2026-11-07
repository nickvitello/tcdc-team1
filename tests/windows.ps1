# Offline behavior tests. No host hardening, firewall changes, or external requests.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$count=0
function Assert($Condition,[string]$Message){ if(-not $Condition){ throw $Message }; $script:count++; Write-Host "PASS: $Message" }
Get-ChildItem $repo -Recurse -Filter '*.ps1' | ForEach-Object {
  $tokens=$null; $errors=$null
  [void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
  if($errors.Count){ throw ($errors | Out-String) }
}
Write-Host 'PASS: all PowerShell files parse'
. (Join-Path $repo 'windows/common.ps1')
$root=Join-Path $env:TEMP ('tcdc-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
try {
  foreach($name in 'watch-agent.ps1','common.ps1','ad-harden.ps1'){ Set-Content (Join-Path $root $name) '# fixture' }
  $unsafe=Join-Path $root 'unsafe-child'
  New-Item -ItemType Directory $unsafe | Out-Null
  $acl=Get-Acl $unsafe
  $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Modify','Allow')
  [void]$acl.AddAccessRule($rule)
  Set-Acl $unsafe $acl
  $refused=$false;try { Assert-TcdcPrivateTree $root } catch { $refused=$_.Exception.Message -match 'Untrusted write' }
  Assert $refused 'Pre-existing writable baseline child is rejected'
  Remove-Item $unsafe -Recurse -Force
  $registryFixture='HKCU:\Software\TcdcCi-'+[guid]::NewGuid().ToString('N')
  try {
    New-Item $registryFixture | Out-Null
    New-ItemProperty $registryFixture -Name fixture -PropertyType ExpandString -Value '%USERPROFILE%\fixture' | Out-Null
    Assert ((Get-TcdcRunValue $registryFixture 'fixture') -eq '%USERPROFILE%\fixture') 'Autorun expansion is stable across operator and SYSTEM contexts'
  } finally { Remove-Item $registryFixture -Recurse -Force }
  # Exercise real Windows 5.1 enumeration read-only before replacing host cmdlets with fixtures.
  $live=Get-TcdcSnapshot $root
  Assert (@($live.Services).Count -gt 0) 'Real Windows service enumeration succeeds'
  Assert (@($live.Tasks).Count -gt 0) 'Real Windows task export succeeds'
  $direct=@(Get-TcdcAdmins)
  function Get-LocalGroupMember { throw 'Force orphan-SID fallback path' }
  $fallback=@(Get-TcdcAdmins)
  Remove-Item Function:\Get-LocalGroupMember
  Assert (($direct -join ',') -eq ($fallback -join ',')) 'ADSI fallback matches native administrator SID enumeration'
  # Mock only host enumeration; exercise actual snapshot serialization and comparison.
  function Get-TcdcAdmins { 'S-1-5-21-100' }
  function Get-CimInstance { param($ClassName) if($ClassName -eq 'Win32_Service'){ [pscustomobject]@{Name='fixture';PathName='fixture.exe';StartName='SYSTEM';StartMode='Auto'} } }
  function Get-ScheduledTask { [pscustomobject]@{TaskName='TCDC-Watch';TaskPath='\'} }
  function Export-ScheduledTask { '<Task><RegistrationInfo><Date>fixture</Date></RegistrationInfo><Actions><Exec><Command>fixture.exe</Command></Exec></Actions><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals></Task>' }
  function Get-TcdcRunKeys { [pscustomobject]@{Id='fixture';Value='known'} }
  $before=Get-TcdcSnapshot $root
  $file=Join-Path $root 'integrity.json'
  Write-TcdcJson $before $file
  $accepted=Read-TcdcBaseline $file
  Assert (@(Compare-TcdcSnapshot $accepted (Get-TcdcSnapshot $root)).Count -eq 0) 'Snapshot roundtrip is stable'
  function Export-ScheduledTask { '<Task><RegistrationInfo><Date>changed</Date></RegistrationInfo><Actions><Exec><Command>fixture.exe</Command></Exec><Exec><Command>second.exe</Command></Exec></Actions></Task>' }
  Assert (@(Compare-TcdcSnapshot $accepted (Get-TcdcSnapshot $root)) -match 'CHANGED Tasks') 'Appended task action detected, including own task'
  Set-Content (Join-Path $root 'watch-agent.ps1') '# altered'
  Assert (@(Compare-TcdcSnapshot $accepted (Get-TcdcSnapshot $root)) -match 'CHANGED Files') 'Watcher content tampering detected'
  function Get-TcdcAdmins { throw 'Enumeration failed' }
  $failed=$false;try { Get-TcdcSnapshot $root | Out-Null } catch { $failed=$true }
  Assert $failed 'Enumeration failure does not produce a valid empty snapshot'
  Set-Content (Join-Path $root 'services.base.csv') 'old accepted evidence'
  $archive=Backup-TcdcBaseline $root
  Assert ((Get-Content (Join-Path $archive 'services.base.csv') -Raw).Trim() -eq 'old accepted evidence') 'Old accepted CSV preserved in archive'
  Assert (Test-Path (Join-Path $archive 'integrity.json')) 'JSON baseline archived too'
  Set-Content $file '{"Version":2}'
  $failed=$false;try { Read-TcdcBaseline $file | Out-Null } catch { $failed=$true }
  Assert $failed 'Old schema refused without capture'
  Set-Content $file '{"Version":3}'
  $failed=$false;try { Read-TcdcBaseline $file | Out-Null } catch { $failed=$true }
  Assert $failed 'Incomplete snapshot refused'

  # Bootstrap: downloads stub files only. Execute the real orchestration and cleanup.
  $global:InvocationBox=$null
  function Invoke-WebRequest {
    param($Uri,$OutFile,[switch]$UseBasicParsing,$TimeoutSec)
    if($Uri -like '*/harden.ps1'){ Set-Content $OutFile 'param([string]$Box) $global:InvocationBox=$Box' }
    else { Set-Content $OutFile '# fixture' }
  }
  $Box='ad';$Ref=('a'*40)
  & (Join-Path $repo 'boot.ps1')
  Assert ($global:InvocationBox -eq 'ad') 'AD bootstrap invokes script with typed Box argument'
  $global:InvocationBox=$null
  function Invoke-WebRequest { throw 'Fixture download failure' }
  $failed=$false;try { & (Join-Path $repo 'boot.ps1') } catch { $failed=$true }
  Assert ($failed -and $null -eq $global:InvocationBox) 'Failed download never executes hardener'
  # Legacy enable flags reject before privilege checks or host changes.
  $failed=$false
  try { & (Join-Path $repo 'windows/harden.ps1') -Box fixture -EnableFirewall }
  catch { $failed=$_.Exception.Message -match 'Automatic firewall activation removed' }
  Assert $failed 'Unsafe legacy firewall activation rejected before mutations'
} finally { Remove-Item $root -Recurse -Force }
Write-Host "ALL $count Windows assertions passed."
