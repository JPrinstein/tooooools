param(
    [string]$StateFile = "C:\SecurityState.json",
    [switch]$Debug
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
    Write-Host "`nCollecting current system state..." -ForegroundColor Cyan
    
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
    Write-Host "  - Collecting users..." -ForegroundColor DarkGray
    $users = Get-LocalUser
    foreach ($user in $users) {
        $state.Users += @{
            Name = $user.Name
            Enabled = [bool]$user.Enabled
            PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }
        }
    }
    Write-Host "    Found $($state.Users.Count) users" -ForegroundColor DarkGray
    
    # Collect Administrators
    Write-Host "  - Collecting administrators..." -ForegroundColor DarkGray
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $state.Administrators = @($admins | ForEach-Object { $_.Name })
    } catch {
        $state.Administrators = @()
    }
    Write-Host "    Found $($state.Administrators.Count) administrators" -ForegroundColor DarkGray
    
    # Collect Service Status (for monitored services)
    Write-Host "  - Collecting services..." -ForegroundColor DarkGray
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
    Write-Host "    Monitoring $($state.Services.Count) services" -ForegroundColor DarkGray
    
    # Collect Firewall Profiles
    Write-Host "  - Collecting firewall profiles..." -ForegroundColor DarkGray
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        $state.FirewallProfiles[$profile.Name] = @{
            Enabled = [bool]$profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction.ToString()
            DefaultOutboundAction = $profile.DefaultOutboundAction.ToString()
        }
    }
    Write-Host "    Found $($state.FirewallProfiles.Count) profiles" -ForegroundColor DarkGray
    
    # Collect Firewall Rules (only enabled ones)
    Write-Host "  - Collecting firewall rules..." -ForegroundColor DarkGray
    $rules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true}
    foreach ($rule in $rules) {
        $state.FirewallRules += @{
            Name = $rule.Name
            DisplayName = $rule.DisplayName
            Direction = $rule.Direction.ToString()
            Action = $rule.Action.ToString()
        }
    }
    Write-Host "    Found $($state.FirewallRules.Count) enabled rules" -ForegroundColor DarkGray
    
    # Collect Suspicious Processes - FIXED patterns to avoid false positives
    Write-Host "  - Scanning for suspicious processes..." -ForegroundColor DarkGray
    $suspiciousPatterns = @(
        "^nc$", "^nc\.exe$", "ncat", "netcat", "powercat", 
        "mimikatz", "psexec", "procdump", "cobalt", "meterpreter", "empire"
    )
    
    $excludeList = @(
        "svchost", "RuntimeBroker", "ShellExperienceHost", "StartMenuExperienceHost", 
        "PhoneExperienceHost", "SearchHost", "TextInputHost", "SecurityHealthService",
        "OneDrive", "conhost", "fontdrvhost", "sihost", "taskhostw"
    )
    
    $processes = Get-Process
    foreach ($proc in $processes) {
        # Skip excluded processes
        $isExcluded = $false
        foreach ($exclude in $excludeList) {
            if ($proc.Name -eq $exclude -or $proc.Name -like "*$exclude*") {
                $isExcluded = $true
                break
            }
        }
        
        if (-not $isExcluded) {
            foreach ($pattern in $suspiciousPatterns) {
                if ($proc.Name -match $pattern) {
                    $state.Processes += @{
                        Name = $proc.Name
                        Id = $proc.Id
                        Path = if ($proc.Path) { $proc.Path } else { "Unknown" }
                    }
                    break
                }
            }
        }
    }
    Write-Host "    Found $($state.Processes.Count) suspicious processes" -ForegroundColor DarkGray
    
    # Collect External Connections (exclude private ranges)
    Write-Host "  - Collecting external connections..." -ForegroundColor DarkGray
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    foreach ($conn in $connections) {
        $isPrivate = $false
        
        # Check if it's a private/local address
        if ($conn.RemoteAddress -match "^127\." -or 
            $conn.RemoteAddress -match "^::1" -or
            $conn.RemoteAddress -match "^10\." -or
            $conn.RemoteAddress -match "^192\.168\." -or
            $conn.RemoteAddress -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
            $isPrivate = $true
        }
        
        if (-not $isPrivate) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $state.Connections += @{
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                LocalPort = $conn.LocalPort
                Process = if ($proc) { $proc.Name } else { "Unknown" }
                ProcessId = $conn.OwningProcess
            }
        }
    }
    Write-Host "    Found $($state.Connections.Count) external connections" -ForegroundColor DarkGray
    
    return $state
}

function Compare-States {
    param($OldState, $NewState)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "COMPARISON RESULTS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Previous: $($OldState.Timestamp)" -ForegroundColor Yellow
    Write-Host "Current:  $($NewState.Timestamp)" -ForegroundColor Yellow
    
    $totalAlerts = 0
    
    # USER CHANGES
    Write-Host "`n[USER CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $oldUserNames = @($OldState.Users | ForEach-Object { $_.Name })
    $newUserNames = @($NewState.Users | ForEach-Object { $_.Name })
    
    if ($Debug) {
        Write-Host "  DEBUG: Old users: $($oldUserNames -join ', ')" -ForegroundColor DarkYellow
        Write-Host "  DEBUG: New users: $($newUserNames -join ', ')" -ForegroundColor DarkYellow
    }
    
    # Check for new users
    foreach ($userName in $newUserNames) {
        if ($userName -notin $oldUserNames) {
            $userObj = $NewState.Users | Where-Object {$_.Name -eq $userName}
            $status = if ($userObj.Enabled) {"ENABLED"} else {"DISABLED"}
            Send-Alert "NEW USER: $userName [$status]" "CRITICAL"
            $sectionAlerts++
        }
    }
    
    # Check for deleted users
    foreach ($userName in $oldUserNames) {
        if ($userName -notin $newUserNames) {
            Send-Alert "USER DELETED: $userName" "WARNING"
            $sectionAlerts++
        }
    }
    
    # Check for user property changes
    foreach ($newUser in $NewState.Users) {
        $oldUser = $OldState.Users | Where-Object {$_.Name -eq $newUser.Name}
        if ($oldUser) {
            if ($newUser.Enabled -ne $oldUser.Enabled) {
                if ($newUser.Enabled) {
                    Send-Alert "USER ENABLED: $($newUser.Name)" "CRITICAL"
                } else {
                    Send-Alert "USER DISABLED: $($newUser.Name)" "WARNING"
                }
                $sectionAlerts++
            }
            
            if ($newUser.PasswordLastSet -ne $oldUser.PasswordLastSet -and $newUser.PasswordLastSet -ne "Never") {
                Send-Alert "PASSWORD CHANGED: $($newUser.Name)" "WARNING"
                $sectionAlerts++
            }
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "  No user changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # ADMINISTRATOR CHANGES
    Write-Host "`n[ADMINISTRATOR CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $oldAdmins = @($OldState.Administrators)
    $newAdmins = @($NewState.Administrators)
    
    if ($Debug) {
        Write-Host "  DEBUG: Old admins: $($oldAdmins -join ', ')" -ForegroundColor DarkYellow
        Write-Host "  DEBUG: New admins: $($newAdmins -join ', ')" -ForegroundColor DarkYellow
    }
    
    # Check for new admins
    foreach ($admin in $newAdmins) {
        if ($admin -notin $oldAdmins) {
            Send-Alert "NEW ADMINISTRATOR: $admin" "CRITICAL"
            $sectionAlerts++
        }
    }
    
    # Check for removed admins
    foreach ($admin in $oldAdmins) {
        if ($admin -notin $newAdmins) {
            Send-Alert "ADMINISTRATOR REMOVED: $admin" "WARNING"
            $sectionAlerts++
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "  No administrator changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # SERVICE CHANGES
    Write-Host "`n[SERVICE CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $newServiceNames = @($NewState.Services.Keys)
    $oldServiceNames = @($OldState.Services.Keys)
    
    if ($Debug) {
        Write-Host "  DEBUG: Comparing services: $($newServiceNames -join ', ')" -ForegroundColor DarkYellow
    }
    
    foreach ($serviceName in $newServiceNames) {
        if ($serviceName -in $oldServiceNames) {
            $oldSvc = $OldState.Services[$serviceName]
            $newSvc = $NewState.Services[$serviceName]
            
            if ($Debug) {
                Write-Host "  DEBUG: $serviceName - Old: $($oldSvc.Status)/$($oldSvc.StartType) New: $($newSvc.Status)/$($newSvc.StartType)" -ForegroundColor DarkYellow
            }
            
            if ($newSvc.Status -ne $oldSvc.Status) {
                Send-Alert "SERVICE STATUS CHANGED: $serviceName from $($oldSvc.Status) to $($newSvc.Status)" "WARNING"
                $sectionAlerts++
            }
            
            if ($newSvc.StartType -ne $oldSvc.StartType) {
                Send-Alert "SERVICE STARTUP CHANGED: $serviceName from $($oldSvc.StartType) to $($newSvc.StartType)" "WARNING"
                $sectionAlerts++
            }
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "  No service changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # FIREWALL PROFILE CHANGES
    Write-Host "`n[FIREWALL PROFILE CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    foreach ($profileName in $NewState.FirewallProfiles.Keys) {
        if ($OldState.FirewallProfiles.ContainsKey($profileName)) {
            $oldProfile = $OldState.FirewallProfiles[$profileName]
            $newProfile = $NewState.FirewallProfiles[$profileName]
            
            if ($Debug) {
                Write-Host "  DEBUG: $profileName - Old Enabled: $($oldProfile.Enabled), New Enabled: $($newProfile.Enabled)" -ForegroundColor DarkYellow
                Write-Host "  DEBUG: $profileName - Old Inbound: $($oldProfile.DefaultInboundAction), New Inbound: $($newProfile.DefaultInboundAction)" -ForegroundColor DarkYellow
            }
            
            if ($newProfile.Enabled -ne $oldProfile.Enabled) {
                $status = if ($newProfile.Enabled) {"ENABLED"} else {"DISABLED"}
                Send-Alert "FIREWALL PROFILE $status`: $profileName" "CRITICAL"
                $sectionAlerts++
            }
            
            if ($newProfile.DefaultInboundAction -ne $oldProfile.DefaultInboundAction) {
                Send-Alert "FIREWALL INBOUND CHANGED: $profileName from $($oldProfile.DefaultInboundAction) to $($newProfile.DefaultInboundAction)" "CRITICAL"
                $sectionAlerts++
            }
            
            if ($newProfile.DefaultOutboundAction -ne $oldProfile.DefaultOutboundAction) {
                Send-Alert "FIREWALL OUTBOUND CHANGED: $profileName from $($oldProfile.DefaultOutboundAction) to $($newProfile.DefaultOutboundAction)" "WARNING"
                $sectionAlerts++
            }
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "  No firewall profile changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # FIREWALL RULE CHANGES
    Write-Host "`n[FIREWALL RULE CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $oldRuleNames = @($OldState.FirewallRules | ForEach-Object { $_.Name })
    $newRuleNames = @($NewState.FirewallRules | ForEach-Object { $_.Name })
    
    if ($Debug) {
        Write-Host "  DEBUG: Old rule count: $($oldRuleNames.Count)" -ForegroundColor DarkYellow
        Write-Host "  DEBUG: New rule count: $($newRuleNames.Count)" -ForegroundColor DarkYellow
    }
    
    # Check for new rules
    foreach ($ruleName in $newRuleNames) {
        if ($ruleName -notin $oldRuleNames) {
            $rule = $NewState.FirewallRules | Where-Object {$_.Name -eq $ruleName} | Select-Object -First 1
            Send-Alert "NEW FIREWALL RULE: $($rule.DisplayName) [$($rule.Direction) - $($rule.Action)]" "WARNING"
            $sectionAlerts++
        }
    }
    
    # Check for removed rules
    foreach ($ruleName in $oldRuleNames) {
        if ($ruleName -notin $newRuleNames) {
            $rule = $OldState.FirewallRules | Where-Object {$_.Name -eq $ruleName} | Select-Object -First 1
            Send-Alert "FIREWALL RULE REMOVED: $($rule.DisplayName)" "WARNING"
            $sectionAlerts++
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "  No firewall rule changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # SUSPICIOUS PROCESSES
    Write-Host "`n[SUSPICIOUS PROCESSES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    if ($NewState.Processes.Count -gt 0) {
        foreach ($proc in $NewState.Processes) {
            Send-Alert "SUSPICIOUS PROCESS DETECTED: $($proc.Name) (PID: $($proc.Id)) - $($proc.Path)" "CRITICAL"
            $sectionAlerts++
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "  No suspicious processes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # EXTERNAL CONNECTIONS
    Write-Host "`n[EXTERNAL CONNECTIONS]" -ForegroundColor Green
    $sectionAlerts = 0
    
    if ($NewState.Connections.Count -gt 0) {
        foreach ($conn in $NewState.Connections) {
            # Check if this connection existed before
            $existed = $OldState.Connections | Where-Object {
                $_.RemoteAddress -eq $conn.RemoteAddress -and 
                $_.RemotePort -eq $conn.RemotePort -and
                $_.Process -eq $conn.Process
            }
            
            if (-not $existed) {
                Send-Alert "NEW EXTERNAL CONNECTION: $($conn.RemoteAddress):$($conn.RemotePort) by $($conn.Process) (PID: $($conn.ProcessId))" "WARNING"
                $sectionAlerts++
            } else {
                Write-Host "  [Existing] $($conn.RemoteAddress):$($conn.RemotePort) by $($conn.Process)" -ForegroundColor DarkGray
            }
        }
    }
    
    if ($sectionAlerts -eq 0 -and $NewState.Connections.Count -eq 0) {
        Write-Host "  No external connections detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "TOTAL ALERTS: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) {"Red"} else {"Green"})
    Write-Host "========================================" -ForegroundColor Cyan
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SNAPSHOT-BASED SECURITY MONITOR v3" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Machine: $hostname" -ForegroundColor Cyan
Write-Host "Time: $timestamp" -ForegroundColor Cyan
if ($Debug) { Write-Host "DEBUG MODE: ON" -ForegroundColor Yellow }

# Collect current state
$currentState = Get-CurrentState

# Check if previous state exists
if (Test-Path $StateFile) {
    Write-Host "`nPrevious state file found - comparing changes" -ForegroundColor Yellow
    
    try {
        $previousStateJson = Get-Content $StateFile -Raw | ConvertFrom-Json
        
        # Convert JSON back to proper hashtables with proper array handling
        $oldState = @{
            Timestamp = $previousStateJson.Timestamp
            Hostname = $previousStateJson.Hostname
            Users = @($previousStateJson.Users)
            Administrators = @($previousStateJson.Administrators)
            Services = @{}
            FirewallProfiles = @{}
            FirewallRules = @($previousStateJson.FirewallRules)
            Processes = @($previousStateJson.Processes)
            Connections = @($previousStateJson.Connections)
        }
        
        # Rebuild Services hashtable
        if ($previousStateJson.Services) {
            foreach ($prop in $previousStateJson.Services.PSObject.Properties) {
                $oldState.Services[$prop.Name] = @{
                    Status = $prop.Value.Status
                    StartType = $prop.Value.StartType
                }
            }
        }
        
        # Rebuild FirewallProfiles hashtable
        if ($previousStateJson.FirewallProfiles) {
            foreach ($prop in $previousStateJson.FirewallProfiles.PSObject.Properties) {
                $oldState.FirewallProfiles[$prop.Name] = @{
                    Enabled = $prop.Value.Enabled
                    DefaultInboundAction = $prop.Value.DefaultInboundAction
                    DefaultOutboundAction = $prop.Value.DefaultOutboundAction
                }
            }
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

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Alerts logged to: C:\SecurityMonitor_Alerts.log" -ForegroundColor Cyan
Write-Host "Monitoring complete. Run again to check for new changes." -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan