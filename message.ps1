<# 
    Stop-RedTeam.ps1
    Purpose: Immediately sever C2 to 167.71.174.87:5555, kill "Windows Font Utility",
             quarantine the binary, and remove common persistence.
    Usage (elevated):
      Set-ExecutionPolicy Bypass -Scope Process -Force
      .\Stop-RedTeam.ps1
#>

[CmdletBinding()]
param(
  [string]$ProcessDisplayName = "Windows Font Utility",
  [string]$AttackIP = "167.71.174.87",
  [int]$AttackPort = 5555
)

Write-Host "=== STOP IT NOW: Starting containment & cleanup ==="

# 0) Prep: logging + quarantine folder
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Log = "$env:PUBLIC\stop_redteam_$TimeStamp.log"
Start-Transcript -Path $Log -Force | Out-Null

$Quarantine = "C:\Quarantine_$TimeStamp"
New-Item -ItemType Directory -Path $Quarantine -ErrorAction SilentlyContinue | Out-Null

function Add-FirewallBlocks {
  Write-Host "[FW] Adding firewall blocks for $AttackIP and port $AttackPort"
  # Block outbound to attacker IP (any protocol/port)
  New-NetFirewallRule -DisplayName "Block C2 IP $AttackIP [$TimeStamp]" `
    -Direction Outbound -RemoteAddress $AttackIP -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

  # Block inbound from attacker IP (defense in depth)
  New-NetFirewallRule -DisplayName "Block C2 IP (Inbound) $AttackIP [$TimeStamp]" `
    -Direction Inbound -RemoteAddress $AttackIP -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

  # Explicitly block outbound TCP 5555 everywhere
  New-NetFirewallRule -DisplayName "Block TCP 5555 [$TimeStamp]" `
    -Direction Outbound -Protocol TCP -RemotePort $AttackPort -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
}

function Get-SuspiciousConns {
  try {
    return Get-NetTCPConnection -State Established -ErrorAction Stop `
      | Where-Object { $_.RemoteAddress -eq $AttackIP -and $_.RemotePort -eq $AttackPort }
  } catch { return @() }
}

function Get-PidsByNameOrConn {
  $pids = New-Object System.Collections.Generic.HashSet[int]

  # 1) Match by friendly display name / exe name (fuzzy contains)
  $procsByName = Get-Process | Where-Object {
    $_.ProcessName -like "*$($ProcessDisplayName -replace '\s','')*" -or
    $_.Name -like "*$($ProcessDisplayName -replace '\s','')*"
  }

  # Also try exact window name match (rare, but helpful)
  $procsByName += Get-Process | Where-Object { $_.MainWindowTitle -like "*$ProcessDisplayName*" }

  foreach ($p in ($procsByName | Select-Object -Unique)) { [void]$pids.Add($p.Id) }

  # 2) Match by active connection to attacker
  $conns = Get-SuspiciousConns
  foreach ($c in $conns) { [void]$pids.Add($c.OwningProcess) }

  return $pids.ToArray()
}

function Get-ExePathFromPid($pid) {
  try {
    $p = Get-Process -Id $pid -ErrorAction Stop
    # Try .Path first; if null, fall back to WMI
    if ($p.Path) { return $p.Path }
    $w = Get-CimInstance Win32_Process -Filter "ProcessId=$pid"
    return $w.ExecutablePath
  } catch { return $null }
}

function Kill-Pids($pids) {
  foreach ($pid in $pids) {
    try {
      $name = (Get-Process -Id $pid -ErrorAction Stop).ProcessName
      Write-Host "[KILL] Stopping PID $pid ($name)"
      Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    } catch {
      Write-Warning "[KILL] Could not stop PID $pid: $($_.Exception.Message)"
    }
  }
}

function Quarantine-File($path) {
  if (-not $path) { return }
  if (-not (Test-Path $path)) { return }

  # Compute hash & move to quarantine
  try {
    $hash = Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction Stop
    $base = Split-Path $path -Leaf
    $qPath = Join-Path $Quarantine ($base + "_$($hash.Hash.Substring(0,12)).quar")
    Write-Host "[QUAR] Moving $path -> $qPath"
    # Clear attributes that might block move
    attrib -r -h -s $path 2>$null
    Move-Item -Path $path -Destination $qPath -Force
    $qPath
  } catch {
    Write-Warning "[QUAR] Failed to move $path: $($_.Exception.Message)"
    $null
  }
}

function Remove-Persistence($suspectPath) {

  # 1) Scheduled Tasks (non-Microsoft and/or pointing at suspectPath)
  Write-Host "[PERSIST] Checking Scheduled Tasks"
  $tasks = schtasks /query /fo LIST /v 2>$null | Out-String
  $taskBlocks = ($tasks -split "(\r?\n){2,}") | Where-Object {$_ -match "TaskName"}
  foreach ($t in $taskBlocks) {
    $name = ($t -split "`r?`n" | Where-Object {$_ -like "TaskName*"}).Replace("TaskName:","").Trim()
    $action = ($t -split "`r?`n" | Where-Object {$_ -like "Actions*"})
    $pathLine = ($t -split "`r?`n" | Where-Object {$_ -like "Task To Run*"} )

    $isMicrosoft = ($name -like "\Microsoft\*")
    $referencesSuspect = $false
    if ($suspectPath -and $pathLine) { $referencesSuspect = ($pathLine -match [Regex]::Escape($suspectPath)) }

    if (-not $isMicrosoft -or $referencesSuspect) {
      try {
        Write-Host "[PERSIST] Deleting task $name"
        schtasks /Delete /TN $name /F | Out-Null
      } catch { Write-Warning "[PERSIST] Could not delete task $name" }
    }
  }

  # 2) Run Keys (HKLM & HKCU) that reference suspectPath or look like the display name
  $runPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  )
  foreach ($rk in $runPaths) {
    try {
      $values = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
      if ($values) {
        foreach ($pn in $values.PSObject.Properties) {
          if ($pn.Name -eq "PSPath" -or $pn.Name -eq "PSParentPath" -or $pn.Name -eq "PSChildName" -or $pn.Name -eq "PSDrive" -or $pn.Name -eq "PSProvider") { continue }
          $val = [string]$pn.Value
          if (($suspectPath -and $val -match [Regex]::Escape($suspectPath)) -or ($val -match "Windows\s*Font\s*Utility")) {
            Write-Host "[PERSIST] Removing Run entry $($pn.Name) in $rk"
            Remove-ItemProperty -Path $rk -Name $pn.Name -Force -ErrorAction SilentlyContinue
          }
        }
      }
    } catch { }
  }

  # 3) Services with suspicious display name or pointing to suspectPath
  Write-Host "[PERSIST] Checking Services"
  $svcs = Get-CimInstance Win32_Service
  foreach ($svc in $svcs) {
    $isMatch = $false
    if ($svc.DisplayName -match "Windows\s*Font\s*Utility") { $isMatch = $true }
    if ($suspectPath -and $svc.PathName -and ($svc.PathName -match [Regex]::Escape($suspectPath))) { $isMatch = $true }

    if ($isMatch) {
      try {
        Write-Host "[PERSIST] Disabling & deleting service: $($svc.Name) ($($svc.DisplayName))"
        sc.exe stop $($svc.Name) | Out-Null
        sc.exe config $($svc.Name) start= disabled | Out-Null
        sc.exe delete $($svc.Name) | Out-Null
      } catch { Write-Warning "[PERSIST] Failed to delete service $($svc.Name)" }
    }
  }
}

# 1) Block C2 immediately
Add-FirewallBlocks

# 2) Identify PIDs by name/connection
$pids = Get-PidsByNameOrConn
if ($pids.Count -eq 0) {
  Write-Warning "[FIND] No process matched by name or active connection. (It may have exited already.)"
} else {
  Write-Host "[FIND] Candidate PIDs: $($pids -join ', ')"
}

# 3) Collect paths for quarantine BEFORE killing (if possible)
$suspectPaths = @()
foreach ($pid in $pids) {
  $p = Get-ExePathFromPid $pid
  if ($p -and -not $suspectPaths.Contains($p)) { $suspectPaths += $p }
}

# 4) Kill processes
if ($pids.Count -gt 0) { Kill-Pids $pids }

# 5) Quarantine binaries (move to C:\Quarantine_* and hash them)
$quarantined = @()
foreach ($sp in $suspectPaths) {
  $q = Quarantine-File $sp
  if ($q) { $quarantined += $q }
}

# 6) Persistence cleanup (tasks, run keys, services)
# Prefer to use ORIGINAL paths when available; also search by display name pattern.
$primaryPath = $suspectPaths | Select-Object -First 1
Remove-Persistence -suspectPath $primaryPath

# 7) Double-check for any still-open connections to the C2
Start-Sleep -Seconds 2
$stillConns = Get-SuspiciousConns
if ($stillConns.Count -gt 0) {
  Write-Warning "[CHECK] There are still connections to $AttackIP:$AttackPort. Consider fully isolating the NIC:"
  Write-Host '  Disable-NetAdapter -Name "Ethernet" -Confirm:$false'
} else {
  Write-Host "[CHECK] No active connections to $AttackIP:$AttackPort detected."
}

Write-Host "`n=== Done. Log: $Log"
if ($quarantined.Count -gt 0) {
  Write-Host "Quarantined files:"
  $quarantined | ForEach-Object { Write-Host " - $_" }
}
Stop-Transcript | Out-Null
