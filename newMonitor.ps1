param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Prompt","AutoRemove","ReportOnly")]
    [string]$Action = "Prompt",

    [string[]]$NotifyMethods = @("Console"), # "Console","Toast","SMTP"
    [string]$StateFile = "C:\DefenderState.json",
    [switch]$Debug,

    # SMTP configuration (EDIT THESE PLACEHOLDERS)
    [string]$SmtpServer = "smtp.example.com",
    [int]$SmtpPort = 587,
    [string]$SmtpFrom = "alerts@yourdomain.com",
    [string]$SmtpTo = "admin@yourdomain.com",
    [string]$SmtpUser = "your-smtp-user",
    [string]$SmtpPassword = "your-smtp-pass"
)

# -----------------------
# Ensure elevated
# -----------------------
function Assert-Elevated {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERROR: Must run as Administrator!" -ForegroundColor Red
        exit 1
    }
}

Assert-Elevated

# -----------------------
# Setup Logging
# -----------------------
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = "$PSScriptRoot\defender_logs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$logFile = Join-Path $logDir "defender_$timestamp.log"
$alertLogFile = "C:\Defender_Alerts.log"
$hostname = $env:COMPUTERNAME
$scriptProcessName = "powershell"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DEFENDER - UNIFIED SECURITY MONITOR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Machine: $hostname" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Mode: $Action" -ForegroundColor Cyan
if ($Debug) { Write-Host "DEBUG: ON" -ForegroundColor Yellow }
Write-Host "========================================`n" -ForegroundColor Cyan

function Log {
    param($msg, $color = "Yellow")
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$hostname] $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Add-Content -Path $alertLogFile -Value $line -Encoding UTF8
    if ($NotifyMethods -contains "Console") { Write-Host $line -ForegroundColor $color }
}

function Send-Toast {
    param($title, $body)
    if (-not (Get-Module -ListAvailable -Name BurntToast)) {
        Log "BurntToast not installed. Install with: Install-Module BurntToast -Scope CurrentUser"
        return
    }
    try {
        Import-Module BurntToast -ErrorAction SilentlyContinue
        New-BurntToastNotification -Text $title, $body
        Log "Toast sent: $title"
    } catch {
        Log "Toast failed: $_"
    }
}

function Send-SMTP {
    param($subject, $body)
    if (-not $SmtpServer -or -not $SmtpTo) {
        Log "SMTP not configured (SmtpServer/SmtpTo empty)."
        return
    }
    try {
        $securePass = ConvertTo-SecureString $SmtpPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($SmtpUser, $securePass)
        Send-MailMessage -SmtpServer $SmtpServer -Port $SmtpPort -From $SmtpFrom -To $SmtpTo -Subject "[$hostname] $subject" -Body $body -Credential $cred -UseSsl -BodyAsHtml
        Log "SMTP sent to $SmtpTo"
    } catch {
        Log "SMTP failed: $_"
    }
}

# -----------------------
# Dynamic Whitelist
# -----------------------
function Get-Whitelist {
    $commonProcesses = @(
        "system", "smss", "csrss", "wininit", "services", "lsass", "lsm", "explorer", "dwm", "spoolsv",  
        "svchost", "taskhostw", "taskhostex", "runtimebroker", "searchindexer", "wmiaprvse", "wmiprvse",  
        "sihost", "conhost", "cmd", "powershell", "powershell_ise", "mmc", "msmpeng", "wuauclt",
        "AggregatorHost", "ctfmon", "dllhost", "fontdrvhost", "Idle", "MicrosoftEdgeUpdate",
        "MpDefenderCoreService", "MoUsoCoreWorker", "musnotifyicon", "notepad", "msiexec", "LogonUI",
        "SecurityHealthService", "SearchProtocolHost", "SearchFilterHost", "audiodg", "dasHost", "OneDrive",
        "ShellExperienceHost", "StartMenuExperienceHost", "PhoneExperienceHost", "SearchHost", "TextInputHost"
    )

    $commonServices = @(
        "Appinfo", "AudioEndpointBuilder", "AudioSrv", "BITS", "BrokerInfrastructure", "CryptSvc", "DcomLaunch",  
        "Dhcp", "Dnscache", "EventLog", "EventSystem", "FontCache", "TimeBrokerSvc", "WdiServiceHost",  
        "WdiSystemHost", "WpnService", "BFE", "MpsSvc", "ProfSvc", "RpcEptMapper", "RpcSs", "Schedule",  
        "SecurityHealthService", "SysMain", "TermService", "UserManager", "Themes", "ShellHWDetection",
        "DoSvc", "iphlpsvc", "WerSvc", "wuauserv", "WSService", "DiagTrack", "PcaSvc", "TokenBroker", 
        "PushToInstall", "InstallService", "AppXSvc", "UsoSvc"
    )

    $hostSpecificServices = @{}
    switch ($hostname) {
        "Wright Brothers" { 
            $hostSpecificServices["LanmanServer"] = $true
            $hostSpecificServices["Netlogon"] = $true
        } 
        "Moon Landing" { 
            $hostSpecificServices["W3SVC"] = $true
            $hostSpecificServices["MSFTPSVC"] = $true
        }
        "Pyramids" {  
            $hostSpecificServices["NTDS"] = $true
            $hostSpecificServices["DNS"] = $true
            $hostSpecificServices["DFSR"] = $true
            $hostSpecificServices["Dfs"] = $true
            $hostSpecificServices["ADWS"] = $true
            $hostSpecificServices["IsmServ"] = $true
            $hostSpecificServices["Netlogon"] = $true
        }
        "First Olympics" { $hostSpecificServices["WinRM"] = $true }
        "Silk Road" { $hostSpecificServices["iphlpsvc"] = $true }
        default { 
            if ($hostname -like "*DC*") {
                Log "INFO: Hostname '$hostname' suggests DC. Adding DC services." "Cyan"
                $hostSpecificServices["NTDS"] = $true
                $hostSpecificServices["DNS"] = $true
                $hostSpecificServices["DFSR"] = $true
                $hostSpecificServices["Dfs"] = $true
                $hostSpecificServices["ADWS"] = $true
                $hostSpecificServices["IsmServ"] = $true
                $hostSpecificServices["Netlogon"] = $true
            } else {
                Log "WARNING: Unknown hostname '$hostname'. Using common allowlist." "Yellow"
            }
        }
    }

    $allowedProcesses = @{}
    foreach ($proc in $commonProcesses) {  
        $allowedProcesses["$($proc).exe".ToLower()] = $true
        $allowedProcesses[$proc.ToLower()] = $true 
    }
    
    $serverProcesses = @("DFSRs.exe", "dns.exe", "dfssvc.exe", "ismserv.exe", "Microsoft.ActiveDirectory.WebServices.exe")
    foreach ($proc in $serverProcesses) { $allowedProcesses[$proc.ToLower()] = $true }

    $allowedServices = @{}
    foreach ($svc in $commonServices) { $allowedServices[$svc.ToLower()] = $true }
    foreach ($svc in $hostSpecificServices.Keys) { $allowedServices[$svc.ToLower()] = $true }

    return @{
        Processes = $allowedProcesses
        Services = $allowedServices
    }
}

# -----------------------
# Collect Current State
# -----------------------
function Get-CurrentState {
    Write-Host "Collecting current system state..." -ForegroundColor Cyan
    
    $state = @{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Hostname = $hostname
        Users = @()
        Administrators = @()
        Services = @{}
        FirewallProfiles = @{}
        FirewallRules = @()
        AnomalousProcesses = @()
        AnomalousServices = @()
        ExternalConnections = @()
    }
    
    # Collect Users
    Write-Host "- Collecting users" -ForegroundColor DarkGray
    $users = Get-LocalUser
    foreach ($user in $users) {
        $state.Users += @{
            Name = $user.Name
            Enabled = [bool]$user.Enabled
            PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss') } else { "Never" }
        }
    }
    
    # Collect Administrators
    Write-Host "- Collecting administrators" -ForegroundColor DarkGray
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $state.Administrators = @($admins | ForEach-Object { $_.Name })
    } catch {
        $state.Administrators = @()
    }
    
    # Collect Services
    Write-Host "- Collecting services" -ForegroundColor DarkGray
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
    
    # Collect Firewall Profiles
    Write-Host "- Collecting firewall profiles" -ForegroundColor DarkGray
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        $state.FirewallProfiles[$profile.Name] = @{
            Enabled = [bool]$profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction.ToString()
            DefaultOutboundAction = $profile.DefaultOutboundAction.ToString()
        }
    }
    
    # Collect Firewall Rules (enabled only)
    Write-Host "- Collecting firewall rules" -ForegroundColor DarkGray
    $rules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true}
    foreach ($rule in $rules) {
        $state.FirewallRules += @{
            Name = $rule.Name
            DisplayName = $rule.DisplayName
            Direction = $rule.Direction.ToString()
            Action = $rule.Action.ToString()
        }
    }
    
    # Whitelist-based anomaly detection
    Write-Host "- Scanning for anomalous processes/services" -ForegroundColor DarkGray
    $allow = Get-Whitelist
    
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -and $_.ProcessName -ne $scriptProcessName } | Select-Object Id, ProcessName, Path
    $anomalousProcs = $procs | Where-Object {  
        $name = $_.ProcessName.ToLower()
        $nameExe = "$($name).exe"
        -not $allow.Processes.ContainsKey($name) -and -not $allow.Processes.ContainsKey($nameExe)
    }
    
    foreach ($proc in $anomalousProcs) {
        $state.AnomalousProcesses += @{
            Name = $proc.ProcessName
            Id = $proc.Id
            Path = if ($proc.Path) { $proc.Path } else { "Unknown" }
        }
    }
    
    $svcs = Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName, Status
    $anomalousServices = $svcs | Where-Object {  
        $sName = $_.Name.ToLower()
        -not $allow.Services.ContainsKey($sName)
    }
    
    foreach ($svc in $anomalousServices) {
        $state.AnomalousServices += @{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Status = $svc.Status.ToString()
        }
    }
    
    # Collect External Connections
    Write-Host "- Collecting external connections" -ForegroundColor DarkGray
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    foreach ($conn in $connections) {
        $isPrivate = $false
        
        if ($conn.RemoteAddress -match "^127\." -or 
            $conn.RemoteAddress -match "^::1" -or
            $conn.RemoteAddress -match "^10\." -or
            $conn.RemoteAddress -match "^192\.168\." -or
            $conn.RemoteAddress -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
            $isPrivate = $true
        }
        
        if (-not $isPrivate) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $state.ExternalConnections += @{
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                LocalPort = $conn.LocalPort
                Process = if ($proc) { $proc.Name } else { "Unknown" }
                ProcessId = $conn.OwningProcess
            }
        }
    }
    
    Write-Host "State collection complete" -ForegroundColor Green
    return $state
}

# -----------------------
# Compare States
# -----------------------
function Compare-States {
    param($OldState, $NewState)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "BASELINE COMPARISON RESULTS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Previous: $($OldState.Timestamp)" -ForegroundColor Yellow
    Write-Host "Current:  $($NewState.Timestamp)" -ForegroundColor Yellow
    
    $totalAlerts = 0
    
    # USER CHANGES
    Write-Host "`n[USER CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $oldUserNames = @($OldState.Users | ForEach-Object { $_.Name })
    $newUserNames = @($NewState.Users | ForEach-Object { $_.Name })
    
    foreach ($userName in $newUserNames) {
        if ($userName -notin $oldUserNames) {
            $userObj = $NewState.Users | Where-Object {$_.Name -eq $userName}
            $status = if ($userObj.Enabled) {"ENABLED"} else {"DISABLED"}
            Log "CRITICAL: NEW USER: $userName [$status]" "Red"
            $sectionAlerts++
        }
    }
    
    foreach ($userName in $oldUserNames) {
        if ($userName -notin $newUserNames) {
            Log "WARNING: USER DELETED: $userName" "Yellow"
            $sectionAlerts++
        }
    }
    
    foreach ($newUser in $NewState.Users) {
        $oldUser = $OldState.Users | Where-Object {$_.Name -eq $newUser.Name}
        if ($oldUser) {
            if ($newUser.Enabled -ne $oldUser.Enabled) {
                if ($newUser.Enabled) {
                    Log "CRITICAL: USER ENABLED: $($newUser.Name)" "Red"
                } else {
                    Log "WARNING: USER DISABLED: $($newUser.Name)" "Yellow"
                }
                $sectionAlerts++
            }
            
            if ($newUser.PasswordLastSet -ne $oldUser.PasswordLastSet -and $newUser.PasswordLastSet -ne "Never") {
                Log "INFO: PASSWORD CHANGED: $($newUser.Name)" "Cyan"
                $sectionAlerts++
            }
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "No user changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # ADMINISTRATOR CHANGES
    Write-Host "`n[ADMINISTRATOR CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $oldAdmins = @($OldState.Administrators)
    $newAdmins = @($NewState.Administrators)
    
    foreach ($admin in $newAdmins) {
        if ($admin -notin $oldAdmins) {
            Log "CRITICAL: NEW ADMINISTRATOR: $admin" "Red"
            $sectionAlerts++
        }
    }
    
    foreach ($admin in $oldAdmins) {
        if ($admin -notin $newAdmins) {
            Log "WARNING: ADMINISTRATOR REMOVED: $admin" "Yellow"
            $sectionAlerts++
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "No administrator changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # SERVICE CHANGES
    Write-Host "`n[SERVICE CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $newServiceNames = @($NewState.Services.Keys)
    $oldServiceNames = @($OldState.Services.Keys)
    
    foreach ($serviceName in $newServiceNames) {
        if ($serviceName -in $oldServiceNames) {
            $oldSvc = $OldState.Services[$serviceName]
            $newSvc = $NewState.Services[$serviceName]
            
            if ($newSvc.Status -ne $oldSvc.Status) {
                Log "WARNING: SERVICE STATUS CHANGED: $serviceName from $($oldSvc.Status) to $($newSvc.Status)" "Yellow"
                $sectionAlerts++
            }
            
            if ($newSvc.StartType -ne $oldSvc.StartType) {
                Log "WARNING: SERVICE STARTUP CHANGED: $serviceName from $($oldSvc.StartType) to $($newSvc.StartType)" "Yellow"
                $sectionAlerts++
            }
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "No service changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # FIREWALL PROFILE CHANGES
    Write-Host "`n[FIREWALL PROFILE CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    foreach ($profileName in $NewState.FirewallProfiles.Keys) {
        if ($OldState.FirewallProfiles.ContainsKey($profileName)) {
            $oldProfile = $OldState.FirewallProfiles[$profileName]
            $newProfile = $NewState.FirewallProfiles[$profileName]
            
            if ($newProfile.Enabled -ne $oldProfile.Enabled) {
                $status = if ($newProfile.Enabled) {"ENABLED"} else {"DISABLED"}
                Log "CRITICAL: FIREWALL PROFILE $status`: $profileName" "Red"
                $sectionAlerts++
            }
            
            if ($newProfile.DefaultInboundAction -ne $oldProfile.DefaultInboundAction) {
                Log "CRITICAL: FIREWALL INBOUND CHANGED: $profileName from $($oldProfile.DefaultInboundAction) to $($newProfile.DefaultInboundAction)" "Red"
                $sectionAlerts++
            }
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "No firewall profile changes detected" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    # FIREWALL RULE CHANGES
    Write-Host "`n[FIREWALL RULE CHANGES]" -ForegroundColor Green
    $sectionAlerts = 0
    
    $oldRuleNames = @($OldState.FirewallRules | ForEach-Object { $_.Name })
    $newRuleNames = @($NewState.FirewallRules | ForEach-Object { $_.Name })
    
    $ruleChangeCount = 0
    foreach ($ruleName in $newRuleNames) {
        if ($ruleName -notin $oldRuleNames) {
            $ruleChangeCount++
        }
    }
    
    foreach ($ruleName in $oldRuleNames) {
        if ($ruleName -notin $newRuleNames) {
            $ruleChangeCount++
        }
    }
    
    if ($ruleChangeCount -gt 0) {
        Log "WARNING: $ruleChangeCount firewall rule changes detected" "Yellow"
        $sectionAlerts += $ruleChangeCount
    } else {
        Write-Host "No firewall rule changes detected" -ForegroundColor Gray
    }
    
    $totalAlerts += $sectionAlerts
    
    # EXTERNAL CONNECTIONS
    Write-Host "`n[NEW EXTERNAL CONNECTIONS]" -ForegroundColor Green
    $sectionAlerts = 0
    
    foreach ($conn in $NewState.ExternalConnections) {
        $existed = $OldState.ExternalConnections | Where-Object {
            $_.RemoteAddress -eq $conn.RemoteAddress -and 
            $_.RemotePort -eq $conn.RemotePort -and
            $_.Process -eq $conn.Process
        }
        
        if (-not $existed) {
            Log "WARNING: NEW EXTERNAL CONNECTION: $($conn.RemoteAddress):$($conn.RemotePort) by $($conn.Process)" "Yellow"
            $sectionAlerts++
        }
    }
    
    if ($sectionAlerts -eq 0) {
        Write-Host "No new external connections" -ForegroundColor Gray
    }
    $totalAlerts += $sectionAlerts
    
    return $totalAlerts
}

# -----------------------
# Handle Anomalies
# -----------------------
function Handle-Process {
    param($proc)
    $info = "PROC: $($proc.Name) (PID: $($proc.Id)) Path: $($proc.Path)"
    Log "ANOMALY $info" "Red"

    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Anomalous Process [$hostname]" -body "$($proc.Name) (PID $($proc.Id))" }
    if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Anomalous Process" -body "$info<br>Host: $hostname" }

    switch ($Action) {
        "ReportOnly" { Log "[ReportOnly] Skipped action on $($proc.Name)" "Cyan"; break }
        "AutoRemove" {
            try { 
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Log "[Auto] Killed $($proc.Name) (PID $($proc.Id))" "Green"
            } 
            catch { Log "[Auto] Failed to kill $($proc.Name): $_" "Red" }
            break
        }
        "Prompt" {
            $response = Read-Host "Kill '$($proc.Name)' (PID $($proc.Id))? [y/N]"
            if ($response -match '^[Yy]') {
                try { 
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Log "[User] Killed $($proc.Name) (PID $($proc.Id))" "Green"
                } 
                catch { Log "[User] Failed to kill $($proc.Name): $_" "Red" }
            } else { Log "[User] Skipped $($proc.Name)" "Cyan" }
        }
    }
}

function Handle-Service {
    param($svc)
    $info = "SERVICE: $($svc.Name) '$($svc.DisplayName)' (Status: $($svc.Status))"
    Log "ANOMALY $info" "Red"

    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Anomalous Service [$hostname]" -body "$($svc.DisplayName) ($($svc.Name))" }
    if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Anomalous Service" -body "$info<br>Host: $hostname" }

    switch ($Action) {
        "ReportOnly" { Log "[ReportOnly] Skipped action on $($svc.Name)" "Cyan"; break }
        "AutoRemove" {
            try { 
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                Log "[Auto] Stopped $($svc.Name)" "Green"
            } 
            catch { Log "[Auto] Failed to stop $($svc.Name): $_" "Red" }
            break
        }
        "Prompt" {
            $response = Read-Host "Stop '$($svc.DisplayName)' ($($svc.Name))? [y/N]"
            if ($response -match '^[Yy]') {
                try { 
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Log "[User] Stopped $($svc.Name)" "Green"
                } 
                catch { Log "[User] Failed to stop $($svc.Name): $_" "Red" }
            } else { Log "[User] Skipped $($svc.Name)" "Cyan" }
        }
    }
}

# -----------------------
# MAIN EXECUTION
# -----------------------
Log "=== Defender Started on $hostname (Action: $Action) ===" "Cyan"

# Collect current state
$currentState = Get-CurrentState

# Check if previous state exists for comparison
$comparisonAlerts = 0
if (Test-Path $StateFile) {
    Write-Host "`nPrevious state found - running baseline comparison" -ForegroundColor Yellow
    
    try {
        $previousStateJson = Get-Content $StateFile -Raw | ConvertFrom-Json
        
        # Convert JSON back to proper hashtables
        $oldState = @{
            Timestamp = $previousStateJson.Timestamp
            Hostname = $previousStateJson.Hostname
            Users = @($previousStateJson.Users)
            Administrators = @($previousStateJson.Administrators)
            Services = @{}
            FirewallProfiles = @{}
            FirewallRules = @($previousStateJson.FirewallRules)
            AnomalousProcesses = @($previousStateJson.AnomalousProcesses)
            AnomalousServices = @($previousStateJson.AnomalousServices)
            ExternalConnections = @($previousStateJson.ExternalConnections)
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
        $comparisonAlerts = Compare-States -OldState $oldState -NewState $currentState
        
    } catch {
        Write-Host "Error reading previous state: $_" -ForegroundColor Red
        Write-Host "Creating new baseline" -ForegroundColor Yellow
    }
    
} else {
    Write-Host "`nNo previous state found - creating initial baseline" -ForegroundColor Yellow
    Write-Host "Run this script again to detect changes" -ForegroundColor Green
}

# Whitelist-based Detection
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "WHITELIST-BASED ANOMALY DETECTION" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$anomalousProcs = $currentState.AnomalousProcesses
$anomalousServices = $currentState.AnomalousServices

$whitelistAlerts = $anomalousProcs.Count + $anomalousServices.Count

if ($whitelistAlerts -eq 0) {
    $msg = "No whitelist anomalies detected on $hostname."
    Log $msg "Green"
    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Clean Host" -body $msg }
} else {
    $summary = "Anomalous: $($anomalousProcs.Count) processes, $($anomalousServices.Count) services on $hostname."
    Log $summary "Red"
    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Anomalies Detected!" -body $summary }
    if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Anomalies Alert" -body "$summary<br>See log: $logFile" }
    
    # Handle anomalous processes
    if ($anomalousProcs.Count -gt 0) {
        Log "Handling $($anomalousProcs.Count) anomalous processes..." "Yellow"
        foreach ($proc in $anomalousProcs) {
            Handle-Process -proc $proc
        }
    }
    
    # Handle anomalous services
    if ($anomalousServices.Count -gt 0) {
        Log "Handling $($anomalousServices.Count) anomalous services..." "Yellow"
        foreach ($svc in $anomalousServices) {
            Handle-Service -svc $svc
        }
    }
}

# Save current state
try {
    $currentState | ConvertTo-Json -Depth 10 | Out-File $StateFile -Force
    Write-Host "`nState saved to: $StateFile" -ForegroundColor Green
} catch {
    Write-Host "`nError saving state: $_" -ForegroundColor Red
}

# Final Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DEFENDER SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalAlerts = $comparisonAlerts + $whitelistAlerts
Write-Host "Baseline Comparison Alerts: $comparisonAlerts" -ForegroundColor $(if ($comparisonAlerts -gt 0) {"Red"} else {"Green"})
Write-Host "Whitelist Anomaly Alerts: $whitelistAlerts" -ForegroundColor $(if ($whitelistAlerts -gt 0) {"Red"} else {"Green"})
Write-Host "TOTAL ALERTS: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) {"Red"} else {"Green"})
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Logs saved to:" -ForegroundColor Cyan
Write-Host "  - $logFile" -ForegroundColor White
Write-Host "  - $alertLogFile" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

if ($totalAlerts -gt 0) {
    if ($NotifyMethods -contains "Toast") { Send-Toast -title "Defender Complete" -body "Total Alerts: $totalAlerts on $hostname" }
    if ($NotifyMethods -contains "SMTP") { Send-SMTP -subject "Defender Scan Complete" -body "Total Alerts: $totalAlerts<br>Logs: $logFile" }
}

Write-Host "Run again in 10-15 minutes to continue monitoring" -ForegroundColor Green