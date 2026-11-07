# Shared snapshot and comparison functions. Dot-source only; no host changes here.
$TcdcBaselineVersion = 3
function Get-TcdcAdmins {
  # DCs have domain groups rather than a workgroup local SAM. AD membership is monitored separately.
  if((Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType -eq 2){ return }
  try {
    Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
      ForEach-Object { [string]$_.SID.Value } | Sort-Object -Unique
  } catch {
    # ADSI enumerates orphaned SIDs without localized net.exe output parsing.
    $groupName = (Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop).Name
    $group = [ADSI]("WinNT://./{0},group" -f $groupName)
    @($group.psbase.Invoke('Members')) | ForEach-Object {
      $bytes = $_.GetType().InvokeMember('objectSid','GetProperty',$null,$_,$null)
      ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$bytes,0)).Value
    } | Sort-Object -Unique
  }
}
function Get-TcdcTasks {
  Get-ScheduledTask -ErrorAction Stop | Sort-Object TaskPath,TaskName | ForEach-Object {
    $task=$_
    # Normalize the complete exported definition. Exclude only volatile registration date.
    [xml]$definition = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
    foreach($date in @($definition.SelectNodes("//*[local-name()='RegistrationInfo']/*[local-name()='Date']"))){
      [void]$date.ParentNode.RemoveChild($date)
    }
    [pscustomobject]@{ Id=$task.TaskPath+$task.TaskName; Definition=$definition.OuterXml }
  }
}
function Get-TcdcRunValue([string]$Key,[string]$Name){
  # Preserve REG_EXPAND_SZ text; operator and SYSTEM environments differ.
  (Get-Item $Key -ErrorAction Stop).GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
}
function Get-TcdcRunKeys {
  $keys = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
  Get-ChildItem Registry::HKEY_USERS -ErrorAction Stop | ForEach-Object {
    $keys += "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Run"
    $keys += "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  }
  foreach($key in ($keys | Sort-Object -Unique)){
    if(Test-Path $key){
      foreach($name in ((Get-Item $key -ErrorAction Stop).Property | Sort-Object)){
        [pscustomobject]@{ Id="$key :: $name"; Value=(Get-TcdcRunValue $key $name) }
      }
    }
  }
}
function Get-TcdcSnapshot([string]$Directory){
  $files = foreach($name in 'watch-agent.ps1','common.ps1','ad-harden.ps1'){
    $path=Join-Path $Directory $name
    if(Test-Path $path){ [pscustomobject]@{Id=$name; Hash=(Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash} }
    else { throw "Missing monitor module: $path" }
  }
  [pscustomobject][ordered]@{
    Version=$TcdcBaselineVersion
    Admins=@(Get-TcdcAdmins)
    Services=@(Get-CimInstance Win32_Service -ErrorAction Stop | Sort-Object Name |
      Select-Object @{n='Id';e={$_.Name}},PathName,StartName,StartMode)
    Tasks=@(Get-TcdcTasks)
    RunKeys=@(Get-TcdcRunKeys)
    Files=@($files)
  }
}
function Read-TcdcBaseline([string]$Path){
  $data = Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
  if($data.Version -ne $TcdcBaselineVersion){ throw 'Incompatible baseline version; review before -Rebaseline' }
  foreach($name in 'Admins','Services','Tasks','RunKeys','Files'){
    if($null -eq $data.PSObject.Properties[$name] -or $null -eq $data.$name){ throw "Invalid baseline: missing $name" }
  }
  return $data
}
function Write-TcdcJson($Value,[string]$Path){
  $temporary="$Path.$([guid]::NewGuid().ToString('N')).tmp"
  try {
    $Value | ConvertTo-Json -Depth 20 | Set-Content $temporary -Encoding UTF8 -ErrorAction Stop
    Move-Item $temporary $Path -Force -ErrorAction Stop
  } finally { if(Test-Path $temporary){ Remove-Item $temporary -Force } }
}
function Compare-TcdcSnapshot($Before,$After){
  foreach($sid in @($After.Admins)){ if(@($Before.Admins) -notcontains $sid){ "NEW admin SID: $sid" } }
  foreach($sid in @($Before.Admins)){ if(@($After.Admins) -notcontains $sid){ "REMOVED admin SID: $sid" } }
  foreach($section in 'Services','Tasks','RunKeys','Files'){
    $old=@{}; $new=@{}
    foreach($item in @($Before.$section)){ $old[$item.Id] = $item | ConvertTo-Json -Depth 20 -Compress }
    foreach($item in @($After.$section)){ $new[$item.Id] = $item | ConvertTo-Json -Depth 20 -Compress }
    foreach($id in $new.Keys){
      if(-not $old.ContainsKey($id)){ "NEW $section : $id" }
      elseif($old[$id] -cne $new[$id]){ "CHANGED $section : $id" }
    }
    foreach($id in $old.Keys){ if(-not $new.ContainsKey($id)){ "REMOVED $section : $id" } }
  }
}
function Assert-TcdcPrivateTree([string]$Path){
  # Refuse attacker-owned/writable or redirected pre-existing paths before privileged use.
  $trusted=@('S-1-5-18','S-1-5-32-544')
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  if(([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ $trusted+=$identity.User.Value }
  $writeMask=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $queue=New-Object 'System.Collections.Generic.Queue[string]'
  $queue.Enqueue($Path)
  while($queue.Count){
    $current=$queue.Dequeue()
    $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){ throw "Unsafe reparse point: $current" }
    $acl=Get-Acl -LiteralPath $current -ErrorAction Stop
    if($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value){ throw "Untrusted baseline path owner: $current" }
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
      if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeMask) -and $trusted -notcontains $rule.IdentityReference.Value){ throw "Untrusted write access on baseline path: $current" }
    }
    if($item.PSIsContainer){ Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop | ForEach-Object { $queue.Enqueue($_.FullName) } }
  }
}
function Protect-TcdcDirectory([string]$Path){
  if(Test-Path $Path){
    Assert-TcdcPrivateTree $Path
    if((Get-Item $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){ throw 'Refusing reparse-point baseline directory' }
  }
  New-Item -ItemType Directory -Force -Path $Path -ErrorAction Stop | Out-Null
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  foreach($sid in 'S-1-5-18','S-1-5-32-544'){
    $identity = [System.Security.Principal.SecurityIdentifier]::new($sid)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop

}
function Backup-TcdcBaseline([string]$Directory){
  $archive=Join-Path $Directory ('accepted-'+[guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $archive -ErrorAction Stop | Out-Null
  Get-ChildItem $Directory -File | Where-Object {
    $_.Name -eq 'integrity.json' -or $_.Name -eq 'baseline.fmt' -or $_.Name -like '*.base.*'
  } | Copy-Item -Destination $archive -ErrorAction Stop
  return $archive
}
