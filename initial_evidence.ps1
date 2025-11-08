$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$evidenceDir = "C:\InitialEvidence_$timestamp"

# Create evidence directory
New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

Write-Host "INITIAL EVIDENCE COLLECTION" -ForegroundColor Cyan
Write-Host "Machine: $hostname" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Evidence will be saved to: $evidenceDir" -ForegroundColor Yellow

function Pause-ForScreenshot {
    param($Message)
    Write-Host "`n[SCREENSHOT] $Message" -ForegroundColor Magenta
    Write-Host "Press Enter when screenshot is taken..." -ForegroundColor Cyan
    Read-Host
}

$allUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires
$allUsers | Format-Table -AutoSize
$allUsers | Out-File "$evidenceDir\01_local_users.txt"

Write-Host "`nEnabled Users:" -ForegroundColor Yellow
$enabledUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
foreach ($user in $enabledUsers) {
    Write-Host "$($user.Name)" -ForegroundColor $(if ($user.Name -like "*admin*") {"Red"} else {"White"})
}

Pause-ForScreenshot "Take screenshot of ALL USERS above"

try {
    $admins = Get-LocalGroupMember -Group "Administrators"
    Write-Host "`nCurrent Administrators:" -ForegroundColor Yellow
    foreach ($admin in $admins) {
        Write-Host "$($admin.Name)" -ForegroundColor Red
    }
    $admins | Out-File "$evidenceDir\02_administrators.txt"
    
    Pause-ForScreenshot "Take screenshot of ADMINISTRATORS"
} catch {
    Write-Host "Could not retrieve administrators: $_" -ForegroundColor Red
}

$groups = Get-LocalGroup
$groups | Format-Table -AutoSize
$groups | Out-File "$evidenceDir\03_local_groups.txt"

# Check important groups
$importantGroups = @("Administrators", "Remote Desktop Users", "Power Users", "Backup Operators")
foreach ($groupName in $importantGroups) {
    try {
        $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
        if ($members) {
            Write-Host "`n$groupName members:" -ForegroundColor Yellow
            foreach ($member in $members) {
                Write-Host "$($member.Name)" -ForegroundColor Cyan
            }
            $members | Out-File "$evidenceDir\03_group_${groupName}_members.txt"
        }
    } catch {
        # Group doesn't exist or no access
    }
}

$processes = Get-Process | Select-Object Name, Id, Path, StartTime | Sort-Object StartTime -Descending
$processes | Out-File "$evidenceDir\04_all_processes.txt"

# Highlight suspicious processes
$suspiciousNames = @("nc", "ncat", "netcat", "powercat", "mimikatz", "psexec", "procdump", "cobalt", "meterpreter", "empire", "powershell", "cmd")
Write-Host "`nPotentially suspicious processes:" -ForegroundColor Yellow

$foundSuspicious = $false
foreach ($proc in $processes) {
    foreach ($suspicious in $suspiciousNames) {
        if ($proc.Name -like "*$suspicious*") {
            Write-Host "$($proc.Name) (PID: $($proc.Id)) - Path: $($proc.Path)" -ForegroundColor Yellow
            $foundSuspicious = $true
        }
    }
}

if ($foundSuspicious) {
    Pause-ForScreenshot "Take screenshot of SUSPICIOUS PROCESSES"
}

$connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
Write-Host "`nEstablished connections:" -ForegroundColor Yellow

$suspiciousConnections = @()
foreach ($conn in $connections) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    $connInfo = "$($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($proc.Name)]"
    
    # Flag external connections
    if ($conn.RemoteAddress -notlike "127.*" -and 
        $conn.RemoteAddress -notlike "::1" -and
        $conn.RemoteAddress -notlike "10.*" -and
        $conn.RemoteAddress -notlike "192.168.*" -and
        $conn.RemoteAddress -notlike "172.16.*" -and
        $conn.RemoteAddress -notlike "172.20.*") {
        Write-Host "EXTERNAL: $connInfo" -ForegroundColor Red
        $suspiciousConnections += $connInfo
    } else {
        Write-Host "$connInfo" -ForegroundColor White
    }
}

$connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
    Out-File "$evidenceDir\05_network_connections.txt"

if ($suspiciousConnections.Count -gt 0) {
    Pause-ForScreenshot "Take screenshot of EXTERNAL CONNECTIONS"
}

$tasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"}
Write-Host "`nCustom scheduled tasks:" -ForegroundColor Yellow

$foundTasks = $false
foreach ($task in $tasks) {
    Write-Host "$($task.TaskName) in $($task.TaskPath)" -ForegroundColor Cyan
    $foundTasks = $true
}

$tasks | Select-Object TaskName, TaskPath, State | Out-File "$evidenceDir\06_scheduled_tasks.txt"

if ($foundTasks) {
    Pause-ForScreenshot "Take screenshot of SCHEDULED TASKS"
}

# Get detailed task info
$taskDetails = Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actions = $task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }
    
    [PSCustomObject]@{
        TaskName = $task.TaskName
        Path = $task.TaskPath
        State = $task.State
        Actions = ($actions -join "; ")
    }
}
$taskDetails | Out-File "$evidenceDir\06_scheduled_tasks_detailed.txt"

$startupItems = Get-CimInstance Win32_StartupCommand
Write-Host "`nStartup programs:" -ForegroundColor Yellow
foreach ($item in $startupItems) {
    Write-Host "$($item.Name): $($item.Command)" -ForegroundColor Cyan
}

$startupItems | Out-File "$evidenceDir\07_startup_programs.txt"

if ($startupItems.Count -gt 0) {
    Pause-ForScreenshot "Take screenshot of STARTUP PROGRAMS"
}

$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\System\CurrentControlSet\Services",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$foundRunKeys = $false
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n$key" -ForegroundColor Yellow
        $entries = Get-ItemProperty -Path $key
        foreach ($prop in $entries.PSObject.Properties) {
            if ($prop.Name -notlike "PS*") {
                Write-Host "$($prop.Name): $($prop.Value)" -ForegroundColor Cyan
                $foundRunKeys = $true
            }
        }
    }
}

"REGISTRY RUN KEYS" | Out-File "$evidenceDir\08_registry_run_keys.txt"
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        "`n $key" | Out-File "$evidenceDir\08_registry_run_keys.txt" -Append
        Get-ItemProperty -Path $key | Out-File "$evidenceDir\08_registry_run_keys.txt" -Append
    }
}

if ($foundRunKeys) {
    Pause-ForScreenshot "Take screenshot of REGISTRY RUN KEYS"
}

$services = Get-Service | Where-Object {
    $_.Status -eq "Running" -and 
    $_.DisplayName -notlike "Windows*" -and
    $_.DisplayName -notlike "Microsoft*"
} | Select-Object Name, DisplayName, Status, StartType

Write-Host "`nCustom running services:" -ForegroundColor Yellow
foreach ($svc in $services) {
    Write-Host "$($svc.DisplayName) [$($svc.Name)]" -ForegroundColor Cyan
}

Get-Service | Out-File "$evidenceDir\09_all_services.txt"
$services | Out-File "$evidenceDir\09_custom_services.txt"

$profiles = Get-NetFirewallProfile
foreach ($profile in $profiles) {
    $status = if ($profile.Enabled) {"ENABLED"} else {"DISABLED"}
    $color = if ($profile.Enabled) {"Green"} else {"Red"}
    Write-Host "$($profile.Name): $status" -ForegroundColor $color
}

$profiles | Out-File "$evidenceDir\10_firewall_profiles.txt"

Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} |
    Select-Object DisplayName, Direction, Action, Enabled |
    Out-File "$evidenceDir\10_firewall_rules_enabled.txt"

Pause-ForScreenshot "Take screenshot of FIREWALL STATUS"

$listening = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
Write-Host "`nListening on ports:" -ForegroundColor Yellow
foreach ($port in ($listening | Select-Object LocalPort -Unique | Sort-Object LocalPort)) {
    Write-Host "Port $($port.LocalPort)" -ForegroundColor Cyan
}

$listening | Select-Object LocalAddress, LocalPort, OwningProcess | 
    Sort-Object LocalPort | Out-File "$evidenceDir\11_listening_ports.txt"

# Recent logons
$logons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($logons) {
    Write-Host "Recent logons: $($logons.Count) events" -ForegroundColor Cyan
    $logons | Select-Object TimeCreated, Message | Out-File "$evidenceDir\12_recent_logons.txt"
}

# Failed logons
$failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($failedLogons) {
    Write-Host "Failed logons: $($failedLogons.Count) events" -ForegroundColor Red
    $failedLogons | Select-Object TimeCreated, Message | Out-File "$evidenceDir\12_failed_logons.txt"
    
    if ($failedLogons.Count -gt 0) {
        Pause-ForScreenshot "Take screenshot showing FAILED LOGON count"
    }
}

# New users
$newUsers = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} -MaxEvents 10 -ErrorAction SilentlyContinue
if ($newUsers) {
    Write-Host "New users created: $($newUsers.Count) events" -ForegroundColor Red
    $newUsers | Select-Object TimeCreated, Message | Out-File "$evidenceDir\12_new_users.txt"
}

if (Test-Path "C:\inetpub\wwwroot") {
    
    $webFiles = Get-ChildItem -Path "C:\inetpub\wwwroot" -Recurse -ErrorAction SilentlyContinue
    Write-Host "`nWeb files found: $($webFiles.Count)" -ForegroundColor Yellow
    
    # Look for suspicious files
    $suspicious = $webFiles | Where-Object {
        $_.Extension -in @(".aspx", ".asp", ".php", ".jsp") -and
        $_.LastWriteTime -gt (Get-Date).AddDays(-1)
    }
    
    if ($suspicious) {
        Write-Host "`nRecent web files (potential webshells):" -ForegroundColor Red
        foreach ($file in $suspicious) {
            Write-Host "$($file.FullName)" -ForegroundColor Red
            Write-Host "Modified: $($file.LastWriteTime)" -ForegroundColor Yellow
        }
    }
    
    $webFiles | Out-File "$evidenceDir\13_web_files.txt"
    
    if ($suspicious) {
        Pause-ForScreenshot "Take screenshot of SUSPICIOUS WEB FILES"
    }
}

$smbService = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
if ($smbService -and $smbService.Status -eq "Running") {
    
    $shares = Get-SmbShare
    Write-Host "`nShared folders:" -ForegroundColor Yellow
    foreach ($share in $shares) {
        Write-Host "$($share.Name): $($share.Path)" -ForegroundColor Cyan
    }
    
    $shares | Out-File "$evidenceDir\14_smb_shares.txt"
    
    # Get share permissions (may fail on some shares, that's okay)
    foreach ($share in $shares) {
        try {
            Get-SmbShareAccess -Name $share.Name | Out-File "$evidenceDir\14_smb_permissions_$($share.Name).txt" -ErrorAction SilentlyContinue
        } catch {
        }
    }
    
    Pause-ForScreenshot "Take screenshot of SMB SHARES"
}

if (Get-Service -Name "NTDS" -ErrorAction SilentlyContinue) {
    
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        Get-ADUser -Filter * -Properties * | Select-Object Name, Enabled, LastLogonDate, PasswordLastSet |
            Out-File "$evidenceDir\15_ad_users.txt"
        
        Get-ADGroup -Filter * | Out-File "$evidenceDir\15_ad_groups.txt"
        
        Get-ADGroupMember -Identity "Domain Admins" | Out-File "$evidenceDir\15_ad_domain_admins.txt"
        
        Write-Host "AD information collected" -ForegroundColor Cyan
    }
    catch {
        "Could not collect AD information: $_" | Out-File "$evidenceDir\15_ad_error.txt"
        Write-Host "Could not collect AD info" -ForegroundColor Yellow
    }
}

Write-Host "EVIDENCE COLLECTION COMPLETE" -ForegroundColor Green

$summary = @"

INITIAL EVIDENCE COLLECTION SUMMARY
Machine: $hostname
Collection Time: $(Get-Date)
Evidence Location: $evidenceDir

FINDINGS:
- Enabled Users: $($enabledUsers.Count)
- Administrators: $(($admins | Measure-Object).Count)
- Running Processes: $((Get-Process).Count)
- Established Connections: $($connections.Count)
- External Connections: $($suspiciousConnections.Count)
- Custom Scheduled Tasks: $(($tasks | Measure-Object).Count)
- Startup Programs: $(($startupItems | Measure-Object).Count)
- Failed Logons: $(($failedLogons | Measure-Object).Count)

RED FLAGS TO INVESTIGATE:
$(if ($suspiciousConnections.Count -gt 0) {"External network connections found!"})
$(if ($failedLogons.Count -gt 5) {"Multiple failed logon attempts!"})
$(if ($newUsers.Count -gt 0) {"New user accounts were created!"})
$(if ($foundSuspicious) {"Suspicious processes detected!"})

"@

$summary | Out-File "$evidenceDir\00_SUMMARY.txt"
Write-Host $summary -ForegroundColor Cyan

Write-Host "`n** Evidence saved to: $evidenceDir **" -ForegroundColor Green
Write-Host "Press Enter to exit..." -ForegroundColor Cyan
Read-Host