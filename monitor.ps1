# Snapshot-Based Security Monitor
# Run this periodically instead of continuously
# Saves state to file, compares on next run

param(
    [string]$StateFile = "C:\SecurityState.json"
)

$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function Send-Alert {
    param($Message, $Severity = "WARNING")
    
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "INFO" { "Green" }
        "CHANGE" { "Cyan" }
        default { "White" }
    }
    
    $output = "[$timestamp] [$Severity] $Message"
    Write-Host $output -ForegroundColor $color
    
    # Also log to file
    Add-Content -Path "C:\SecurityMonitor_Alerts.log" -Value $output
}

function Get-CurrentState {
    Write-Host "`nCollecting current system state" -ForegroundColor Cyan
    
    $state = @{
        Timestamp = $timestamp
        Hostname = $hostname
        Users = @()
        Administrators = @()
        Services = @{}
        FirewallProfiles = @{}
        FirewallRules = @()
        Processes = @()
        Connections = @()
    }
    
    # Collect Users
    $state.Users = Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet | ForEach-Object {
        @{
            Name = $_.Name
            Enabled = $_.Enabled
            PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString() } else { "Never" }
        }
    }
    
    # Collect Administrators
    try {
        $state.Administrators = (Get-LocalGroupMember -Group "Administrators").Name
    } catch {
        $state.Administrators = @()
    }
    
    # Collect Service Status (for monitored services)
    $servicesToCheck = @("DNS", "NTDS", "Netlogon", "WinRM", "LanmanServer", "W3SVC", "WAS", "Spooler")
    foreach ($svcName in $servicesToCheck) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $state.Services[$svcName] = @{
                Status = $svc.Status.ToString()
                StartType = $svc.StartType.ToString()
            }
        }
    }
    
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        $state.FirewallProfiles[$profile.Name] = @{
            Enabled = $profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction.ToString()
            DefaultOutboundAction = $profile.DefaultOutboundAction.ToString()
        }
    }
    
    $state.FirewallRules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | ForEach-Object {
        @{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Direction = $_.Direction.ToString()
            Action = $_.Action.ToString()
        }
    }
    
    $suspiciousNames = @("nc", "ncat", "netcat", "powercat", "mimikatz", "psexec", "procdump", "cobalt", "meterpreter", "empire")
    $processes = Get-Process
    foreach ($proc in $processes) {
        foreach ($suspicious in $suspiciousNames) {
            if ($proc.Name -like "*$suspicious*") {
                $state.Processes += @{
                    Name = $proc.Name
                    Id = $proc.Id
                    Path = if ($proc.Path) { $proc.Path } else { "Unknown" }
                }
            }
        }
    }
    
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    foreach ($conn in $connections) {
        if ($conn.RemoteAddress -notlike "127.*" -and 
            $conn.RemoteAddress -notlike "::1" -and
            $conn.RemoteAddress -notlike "10.*" -and
            $conn.RemoteAddress -notlike "192.168.*" -and
            $conn.RemoteAddress -notlike "172.16.*" -and
            $conn.RemoteAddress -notlike "172.20.*") {
            
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $state.Connections += @{
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                LocalPort = $conn.LocalPort
                Process = if ($proc) { $proc.Name } else { "Unknown" }
            }
        }
    }
    
    return $state
}

function Compare-States {
    param($OldState, $NewState)
    
    Write-Host "`nCOMPARISON" -ForegroundColor Cyan
    Write-Host "Previous: $($OldState.Timestamp)" -ForegroundColor Yellow
    Write-Host "Current:  $($NewState.Timestamp)" -ForegroundColor Yellow
    
    $changesFound = $false
    
    Write-Host "`nUSER CHANGES" -ForegroundColor Green
    
    $oldUserNames = $OldState.Users | ForEach-Object { $_.Name }
    $newUserNames = $NewState.Users | ForEach-Object { $_.Name }
    
    $addedUsers = $newUserNames | Where-Object {$_ -notin $oldUserNames}
    foreach ($user in $addedUsers) {
        $userObj = $NewState.Users | Where-Object {$_.Name -eq $user}
        $status = if ($userObj.Enabled) {"ENABLED"} else {"DISABLED"}
        Send-Alert "NEW USER: $user [$status]" "CRITICAL"
        $changesFound = $true
    }
    
    $deletedUsers = $oldUserNames | Where-Object {$_ -notin $newUserNames}
    foreach ($user in $deletedUsers) {
        Send-Alert "USER DELETED: $user" "WARNING"
        $changesFound = $true
    }
    
    foreach ($newUser in $NewState.Users) {
        $oldUser = $OldState.Users | Where-Object {$_.Name -eq $newUser.Name}
        if ($oldUser) {
            if ($newUser.Enabled -ne $oldUser.Enabled) {
                if ($newUser.Enabled) {
                    Send-Alert "USER ENABLED: $($newUser.Name)" "CRITICAL"
                } else {
                    Send-Alert "USER DISABLED: $($newUser.Name)" "WARNING"
                }
                $changesFound = $true
            }
            
            if ($newUser.PasswordLastSet -ne $oldUser.PasswordLastSet) {
                Send-Alert "PASSWORD CHANGED: $($newUser.Name)" "WARNING"
                $changesFound = $true
            }
        }
    }
    
    if (-not $changesFound) {
        Write-Host "  No user changes detected" -ForegroundColor Gray
    }
    
    Write-Host "`nADMINISTRATOR CHANGES" -ForegroundColor Green
    $changesFound = $false
    
    $addedAdmins = $NewState.Administrators | Where-Object {$_ -notin $OldState.Administrators}
    foreach ($admin in $addedAdmins) {
        Send-Alert "NEW ADMINISTRATOR: $admin" "CRITICAL"
        $changesFound = $true
    }
    
    $removedAdmins = $OldState.Administrators | Where-Object {$_ -notin $NewState.Administrators}
    foreach ($admin in $removedAdmins) {
        Send-Alert "ADMINISTRATOR REMOVED: $admin" "WARNING"
        $changesFound = $true
    }
    
    if (-not $changesFound) {
        Write-Host "  No administrator changes detected" -ForegroundColor Gray
    }
    
    Write-Host "`nSERVICE CHANGES" -ForegroundColor Green
    $changesFound = $false
    
    foreach ($serviceName in $NewState.Services.Keys) {
        if ($OldState.Services.PSObject.Properties.Name -contains $serviceName) {
            $oldSvc = $OldState.Services.$serviceName
            $newSvc = $NewState.Services.$serviceName
            
            if ($newSvc.Status -ne $oldSvc.Status) {
                Send-Alert "SERVICE STATUS CHANGED: $serviceName from $($oldSvc.Status) to $($newSvc.Status)" "WARNING"
                $changesFound = $true
            }
            
            if ($newSvc.StartType -ne $oldSvc.StartType) {
                Send-Alert "SERVICE STARTUP CHANGED: $serviceName from $($oldSvc.StartType) to $($newSvc.StartType)" "WARNING"
                $changesFound = $true
            }
        }
    }
    
    if (-not $changesFound) {
        Write-Host "  No service changes detected" -ForegroundColor Gray
    }
    
    Write-Host "`nFIREWALL PROFILE CHANGES" -ForegroundColor Green
    $changesFound = $false
    
    foreach ($profileName in $NewState.FirewallProfiles.Keys) {
        $oldProfile = $OldState.FirewallProfiles.$profileName
        $newProfile = $NewState.FirewallProfiles.$profileName
        
        if ($newProfile.Enabled -ne $oldProfile.Enabled) {
            $status = if ($newProfile.Enabled) {"ENABLED"} else {"DISABLED"}
            Send-Alert "FIREWALL PROFILE $status`: $profileName" "CRITICAL"
            $changesFound = $true
        }
        
        if ($newProfile.DefaultInboundAction -ne $oldProfile.DefaultInboundAction) {
            Send-Alert "FIREWALL INBOUND CHANGED: $profileName from $($oldProfile.DefaultInboundAction) to $($newProfile.DefaultInboundAction)" "WARNING"
            $changesFound = $true
        }
        
        if ($newProfile.DefaultOutboundAction -ne $oldProfile.DefaultOutboundAction) {
            Send-Alert "FIREWALL OUTBOUND CHANGED: $profileName from $($oldProfile.DefaultOutboundAction) to $($newProfile.DefaultOutboundAction)" "WARNING"
            $changesFound = $true
        }
    }
    
    if (-not $changesFound) {
        Write-Host "  No firewall profile changes detected" -ForegroundColor Gray
    }
    
    Write-Host "`nFIREWALL RULE CHANGES" -ForegroundColor Green
    $changesFound = $false
    
    $oldRuleNames = $OldState.FirewallRules | ForEach-Object { $_.Name }
    $newRuleNames = $NewState.FirewallRules | ForEach-Object { $_.Name }
    
    $addedRules = $newRuleNames | Where-Object {$_ -notin $oldRuleNames}
    foreach ($ruleName in $addedRules) {
        $rule = $NewState.FirewallRules | Where-Object {$_.Name -eq $ruleName}
        Send-Alert "NEW FIREWALL RULE: $($rule.DisplayName) [$($rule.Direction) - $($rule.Action)]" "WARNING"
        $changesFound = $true
    }
    
    $removedRules = $oldRuleNames | Where-Object {$_ -notin $newRuleNames}
    foreach ($ruleName in $removedRules) {
        $rule = $OldState.FirewallRules | Where-Object {$_.Name -eq $ruleName}
        Send-Alert "FIREWALL RULE REMOVED: $($rule.DisplayName)" "WARNING"
        $changesFound = $true
    }
    
    if (-not $changesFound) {
        Write-Host "  No firewall rule changes detected" -ForegroundColor Gray
    }
    
    Write-Host "`nSUSPICIOUS PROCESSES" -ForegroundColor Green
    $changesFound = $false
    
    if ($NewState.Processes.Count -gt 0) {
        foreach ($proc in $NewState.Processes) {
            Send-Alert "SUSPICIOUS PROCESS DETECTED: $($proc.Name) (PID: $($proc.Id)) - $($proc.Path)" "CRITICAL"
            $changesFound = $true
        }
    }
    
    if (-not $changesFound) {
        Write-Host "  No suspicious processes detected" -ForegroundColor Gray
    }
    
    Write-Host "`nEXTERNAL CONNECTIONS" -ForegroundColor Green
    $changesFound = $false
    
    if ($NewState.Connections.Count -gt 0) {
        foreach ($conn in $NewState.Connections) {
            # Check if this connection existed before
            $existed = $OldState.Connections | Where-Object {
                $_.RemoteAddress -eq $conn.RemoteAddress -and 
                $_.RemotePort -eq $conn.RemotePort
            }
            
            if (-not $existed) {
                Send-Alert "NEW EXTERNAL CONNECTION: $($conn.RemoteAddress):$($conn.RemotePort) by $($conn.Process)" "WARNING"
                $changesFound = $true
            } else {
                # Connection still exists, just note it
                Write-Host "  [Existing] $($conn.RemoteAddress):$($conn.RemotePort) by $($conn.Process)" -ForegroundColor Gray
            }
        }
    }
    
    if (-not $changesFound -and $NewState.Connections.Count -eq 0) {
        Write-Host "  No external connections detected" -ForegroundColor Gray
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SNAPSHOT-BASED SECURITY MONITOR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Machine: $hostname" -ForegroundColor Cyan
Write-Host "Time: $timestamp" -ForegroundColor Cyan

# Collect current state
$currentState = Get-CurrentState

# Check if previous state exists
if (Test-Path $StateFile) {
    Write-Host "`nPrevious state file found - comparing changes" -ForegroundColor Yellow
    
    try {
        $previousStateJson = Get-Content $StateFile -Raw | ConvertFrom-Json
        
        # Convert JSON back to proper hashtables
        $oldState = @{
            Timestamp = $previousStateJson.Timestamp
            Hostname = $previousStateJson.Hostname
            Users = @($previousStateJson.Users)
            Administrators = @($previousStateJson.Administrators)
            Services = $previousStateJson.Services
            FirewallProfiles = $previousStateJson.FirewallProfiles
            FirewallRules = @($previousStateJson.FirewallRules)
            Processes = @($previousStateJson.Processes)
            Connections = @($previousStateJson.Connections)
        }
        
        # Compare states
        Compare-States -OldState $oldState -NewState $currentState
        
    } catch {
        Write-Host "Error reading previous state: $_" -ForegroundColor Red
        Write-Host "Creating new baseline" -ForegroundColor Yellow
    }
    
} else {
    Write-Host "`nNo previous state found - creating initial baseline" -ForegroundColor Yellow
    Write-Host "Run this script again to detect changes" -ForegroundColor Green
}

# Save current state
try {
    $currentState | ConvertTo-Json -Depth 10 | Out-File $StateFile -Force
    Write-Host "`nState saved to: $StateFile" -ForegroundColor Green
} catch {
    Write-Host "`nError saving state: $_" -ForegroundColor Red
}

Write-Host "`nAlerts logged to: C:\SecurityMonitor_Alerts.log" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Monitoring complete. Run again to check for new changes." -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan