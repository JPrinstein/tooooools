<#
  Stop-RedTeam-NoErrors.ps1
  Purpose: Defensive containment for a named malicious process + C2 IP:Port.
  - Blocks IP/port via Windows Firewall (idempotent)
  - Finds connections (Get-NetTCPConnection or netstat fallback)
  - Finds & stops matching processes (by name or by connection PID)
  - Exports event logs (best-effort)
  - Quarantines discovered binaries (move to C:\Quarantine_<ts>)
  - Attempts to remove common persistence (scheduled tasks, Run keys, services)
  - Optionally disables physical NICs if -IsolateNic
  Notes: MUST run as Administrator. Script is written to avoid unhandled errors.
#>

[CmdletBinding()]
param(
  [string]$ProcessDisplayName   = "Windows Font Utility",
  [string]$AttackIP             = "167.71.174.87",
  [int]   $AttackPort           = 5555,
  [switch]$IsolateNic
)

# ---------------------------
# Helpers & setup
# ---------------------------
function Exit-If-NotAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Exiting." -ForegroundColor Red
    exit 1
  }
}

function SafeLog {
  param([string]$Message)
  $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "$t`t$Message"
  try { Add-Content -Path $Global:Log -Value $line -ErrorAction SilentlyContinue } catch {}
  Write-Host $Message
}

# Ensure admin
Exit-If-NotAdmin

# Timestamped global log & transcript (best-effort)
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$Global:Log = "C:\Users\Public\stop_redteam_log_$ts.txt"
try {
  Start-Transcript -Path $Global:Log -ErrorAction SilentlyContinue | Out-Null
} catch {
  # if Start-Transcript fails (rare), continue with Add-Content logging
}

# Quarantine dir
$QuarantineDir = "C:\Quarantine_$ts"
try { New-Item -ItemType Directory -Path $QuarantineDir -ErrorAction SilentlyContinue | Out-Null } catch {}

SafeLog "=== Stop-RedTeam-NoErrors run started ==="

# ---------------------------
# 0) Export event logs (best-effort)
# ---------------------------
try {
  $evDir = "C:\Users\Public\EventLogs_$ts"
  New-Item -ItemType Directory -Path $evDir -ErrorAction SilentlyContinue | Out-Null
  wevtutil epl System "$evDir\System.evtx" 2>$null
  wevtutil epl Application "$evDir\Application.evtx" 2>$null
  wevtutil epl Security "$evDir\Security.evtx" 2>$null
  SafeLog "Event logs exported (best-effort) to $evDir"
} catch {
  SafeLog "Event log export encountered an error (continuing): $_"
}

# ---------------------------
# 1) Idempotent firewall blocks (inbound + outbound + port)
# ---------------------------
function Add-FirewallBlock-Idempotent {
  param($ip,$port)
  try {
    # Check if a similar rule exists (by DisplayName pattern). If not, create.
    $ruleNameOutIP = "Block_C2_IP_Out_$ip"
    $ruleNameInIP  = "Block_C2_IP_In_$ip"
    $ruleNameOutPort = "Block_TCP_Port_${port}_Out"
    $ruleNameInPort  = "Block_TCP_Port_${port}_In"

    if (-not (Get-NetFirewallRule -DisplayName $ruleNameOutIP -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $ruleNameOutIP -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Get-NetFirewallRule -DisplayName $ruleNameInIP -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $ruleNameInIP  -Direction Inbound  -RemoteAddress $ip -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Get-NetFirewallRule -DisplayName $ruleNameOutPort -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $ruleNameOutPort -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Get-NetFirewallRule -DisplayName $ruleNameInPort -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $ruleNameInPort -Direction Inbound -Protocol TCP -LocalPort $port -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    SafeLog "Firewall: ensured blocks for IP $ip and TCP port $port."
  } catch {
    SafeLog "Firewall block step failed (continuing): $_"
  }
}
Add-FirewallBlock-Idempotent -ip $AttackIP -port $AttackPort

# ---------------------------
# 2) Find established connections (Get-NetTCPConnection with fallback to netstat)
# ---------------------------
function Get-EstablishedConns {
  param($ip,$port)
  $result = @()
  try {
    $c = Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object {
      ($_.RemoteAddress -eq $ip -or $_.RemoteAddress -eq "0.0.0.0") -and ($_.RemotePort -eq $port)
    }
    if ($c) { $result += $c }
  } catch {
    # fallback: parse netstat output
    try {
      $ns = netstat -ano -p tcp 2>$null
      foreach ($line in $ns) {
        if ($line -match "ESTABLISHED") {
          # columns can be: Proto  Local Address  Foreign Address  State  PID
          $parts = ($line -split '\s+') | Where-Object { $_ -ne "" }
          if ($parts.Count -ge 5) {
            $foreign = $parts[2]
            $pid = $parts[-1]
            # foreign format IP:port
            if ($foreign -match "^(.*):(\d+)$") {
              $fip = $matches[1]; $fport = [int]$matches[2]
              if ($fip -eq $ip -and $fport -eq $port) {
                # create a PSCustomObject-like entry similar to Get-NetTCPConnection
                $obj = [PSCustomObject]@{ OwningProcess = [int]$pid; RemoteAddress = $fip; RemotePort = $fport; State = "ESTABLISHED" }
                $result += $obj
              }
            }
          }
        }
      }
    } catch {
      SafeLog "netstat fallback failed: $_"
    }
  }
  return $result
}

try {
  $conns = Get-EstablishedConns -ip $AttackIP -port $AttackPort
  if ($conns.Count -gt 0) {
    SafeLog "Found $($conns.Count) established connection(s) to $AttackIP:$AttackPort"
  } else {
    SafeLog "No established connections to $AttackIP:$AttackPort found."
  }
} catch {
  SafeLog "Connection enumeration failed (continuing): $_"
  $conns = @()
}

# ---------------------------
# 3) Build candidate PID list (from connections & name matching)
# ---------------------------
$pidSet = New-Object System.Collections.Generic.HashSet[int]

# From connections
try {
  foreach ($c in $conns) { if ($c.OwningProcess) { $pidSet.Add([int]$c.OwningProcess) | Out-Null } }
} catch { SafeLog "Error adding PIDs from conns: $_" }

# From name match (fuzzy)
try {
  $pattern = ($ProcessDisplayName -replace '\s+','.*')
  $procCandidates = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    ($_.ProcessName -match $pattern) -or ($_.MainWindowTitle -match [Regex]::Escape($ProcessDisplayName))
  }
  foreach ($p in $procCandidates) { $pidSet.Add($p.Id) | Out-Null }
  SafeLog "Process name lookup added $($procCandidates.Count) candidates (may be zero)."
} catch {
  SafeLog "Process name lookup failed: $_"
}

$pids = @()
try { $pids = $pidSet.ToArray() } catch {}

if ($pids.Count -eq 0) {
  SafeLog "No candidate PIDs collected (by connection or name)."
} else {
  SafeLog "Candidate PIDs: $($pids -join ', ')"
}

# ---------------------------
# 4) For each PID: get exe path & hash (best-effort)
# ---------------------------
$suspectPaths = @()
foreach ($pid in $pids) {
  try {
    $w = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
    $path = $null
    if ($w -and $w.ExecutablePath) { $path = $w.ExecutablePath }
    else {
      try { $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue; if ($proc -and $proc.Path) { $path = $proc.Path } } catch {}
    }
    if ($path) {
      if (-not ($suspectPaths -contains $path)) { $suspectPaths += $path }
      try {
        $h = Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction SilentlyContinue
        $hashStr = if ($h) { $h.Hash } else { "<hash-failed>" }
      } catch { $hashStr = "<hash-failed>" }
      SafeLog "PID $pid -> $path (SHA256: $hashStr)"
    } else {
      SafeLog "PID $pid -> executable path UNKNOWN (process may have exited)"
    }
  } catch {
    SafeLog "Error enumerating PID $pid: $_"
  }
}

# ---------------------------
# 5) Kill candidate processes (safe & best-effort)
# ---------------------------
foreach ($pid in $pids) {
  try {
    # double-check process exists before killing
    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
    if ($proc) {
      SafeLog "Stopping PID $pid ($($proc.ProcessName))"
      Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 500
      $still = Get-Process -Id $pid -ErrorAction SilentlyContinue
      if (-not $still) { SafeLog "PID $pid stopped." } else { SafeLog "PID $pid could not be stopped or restarted rapidly." }
    } else {
      SafeLog "PID $pid not found (may have exited already)."
    }
  } catch {
    SafeLog "Failed to stop PID $pid (continuing): $_"
  }
}

# ---------------------------
# 6) Quarantine discovered binaries (move if possible)
# ---------------------------
function Quarantine-File-Safe {
  param($filePath)
  if (-not $filePath) { return $null }
  try {
    if (-not (Test-Path $filePath)) { SafeLog "Quarantine: file does not exist: $filePath"; return $null }
    try { attrib -r -h -s $filePath 2>$null } catch {}
    $hf = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue
    $hStr = if ($hf) { $hf.Hash.Substring(0,12) } else { "nohash" }
    $leaf = Split-Path -Path $filePath -Leaf
    $dest = Join-Path $QuarantineDir ("$($leaf)_$hStr")
    try {
      Move-Item -LiteralPath $filePath -Destination $dest -Force -ErrorAction Stop
      SafeLog "Quarantined $filePath -> $dest"
      return $dest
    } catch {
      SafeLog "Move-Item failed for $filePath: $_"
      # try copy-and-delete fallback
      try {
        Copy-Item -LiteralPath $filePath -Destination $dest -Force -ErrorAction Stop
        SafeLog "Copied $filePath -> $dest (delete original attempt)"
        Remove-Item -LiteralPath $filePath -Force -ErrorAction SilentlyContinue
        return $dest
      } catch {
        SafeLog "Copy/Delete fallback also failed for $filePath: $_"
        return $null
      }
    }
  } catch {
    SafeLog "Quarantine-File-Safe encountered error for $filePath: $_"
    return $null
  }
}

$quarantined = @()
foreach ($p in $suspectPaths) {
  $q = Quarantine-File-Safe -filePath $p
  if ($q) { $quarantined += $q }
}
if ($quarantined.Count -gt 0) {
  SafeLog "Quarantined files: $($quarantined -join '; ')"
} else {
  SafeLog "No files quarantined (none discovered or move failed)."
}

# ---------------------------
# 7) Remove likely persistence (scheduled tasks, Run keys, services) - best-effort
# ---------------------------
try {
  # Scheduled tasks (skip Microsoft\ tasks)
  try {
    $taskDump = schtasks /query /fo LIST /v 2>$null | Out-String
    $taskBlocks = ($taskDump -split "(\r?\n){2,}") | Where-Object { $_ -match "TaskName:" }
    foreach ($block in $taskBlocks) {
      try {
        $taskNameLine = ($block -split "`r?`n" | Where-Object { $_ -like "TaskName:*" })[0]
        if (-not $taskNameLine) { continue }
        $taskName = $taskNameLine -replace "TaskName:","" -trim
        if ($taskName -match "\\Microsoft\\") { continue }
        $taskAction = ($block -split "`r?`n" | Where-Object { $_ -like "Task To Run:*" }) -join " "
        $shouldDelete = $false
        if ($taskAction -match [Regex]::Escape($ProcessDisplayName)) { $shouldDelete = $true }
        foreach ($s in $suspectPaths) { if ($taskAction -match [Regex]::Escape($s)) { $shouldDelete = $true } }
        if ($shouldDelete) {
          SafeLog "Deleting scheduled task $taskName (action: $taskAction)"
          schtasks /Delete /TN $taskName /F 2>$null | Out-Null
        }
      } catch { SafeLog "Scheduled task sub-step error: $_"; continue }
    }
  } catch { SafeLog "Scheduled tasks enumeration failed: $_" }

  # Run keys
  $runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  )
  foreach ($rk in $runKeys) {
    try {
      $vals = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
      if ($vals) {
        foreach ($prop in $vals.PSObject.Properties) {
          if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
          $v = [string]$prop.Value
          $remove = $false
          if ($v -match [Regex]::Escape($ProcessDisplayName)) { $remove = $true }
          foreach ($s in $suspectPaths) { if ($v -match [Regex]::Escape($s)) { $remove = $true } }
          if ($remove) {
            try {
              Remove-ItemProperty -Path $rk -Name $prop.Name -ErrorAction SilentlyContinue
              SafeLog "Removed Run entry $($prop.Name) from $rk -> $v"
            } catch { SafeLog "Failed to remove Run entry $($prop.Name) from $rk: $_" }
          }
        }
      }
    } catch { SafeLog "Run key read error for $rk: $_" }
  }

  # Services
  try {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
      $match = $false
      try {
        if ($svc.DisplayName -match $ProcessDisplayName) { $match = $true }
        foreach ($s in $suspectPaths) { if ($svc.PathName -and ($svc.PathName -match [Regex]::Escape($s))) { $match = $true } }
      } catch {}
      if ($match) {
        SafeLog "Attempting to disable/delete service: $($svc.Name) ($($svc.DisplayName)) Path: $($svc.PathName)"
        try { sc.exe stop $svc.Name 2>$null | Out-Null } catch {}
        try { sc.exe config $svc.Name start= disabled 2>$null | Out-Null } catch {}
        try { sc.exe delete $svc.Name 2>$null | Out-Null } catch {}
      }
    }
  } catch { SafeLog "Service cleanup step failed: $_" }

} catch {
  SafeLog "Persistence cleanup encountered an error (continuing): $_"
}

# ---------------------------
# 8) Final connection check
# ---------------------------
try {
  $still = Get-EstablishedConns -ip $AttackIP -port $AttackPort
  if ($still.Count -gt 0) {
    SafeLog "WARNING: $($still.Count) connections to $AttackIP:$AttackPort still active. Consider hypervisor-level power-off or NIC isolation."
  } else {
    SafeLog "No active connections to $AttackIP:$AttackPort detected."
  }
} catch { SafeLog "Final connection check error: $_" }

# ---------------------------
# 9) Optional NIC isolation (physical adapters) - safe attempt
# ---------------------------
if ($IsolateNic) {
  try {
    $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    if ($adapters.Count -eq 0) { SafeLog "No physical 'Up' adapters found to disable." }
    foreach ($a in $adapters) {
      try {
        SafeLog "Disabling adapter: $($a.Name)"
        Disable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
      } catch { SafeLog "Failed to disable adapter $($a.Name): $_" }
    }
    SafeLog "NIC isolation attempted (physical adapters)."
  } catch { SafeLog "NIC isolation failed: $_" }
}

# ---------------------------
# 10) Wrap up
# ---------------------------
SafeLog "Manual follow-ups: rotate credentials from a CLEAN machine, rebuild VM from known-good image, submit samples if needed, involve IR if sensitive data involved."
SafeLog "Script finished. Log file: $Global:Log"

try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
