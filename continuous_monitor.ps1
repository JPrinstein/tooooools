# Continuous Service and Security Monitor
# Run this in a separate PowerShell window during competition
# It will continuously check your services and alert you to problems

param(
    [int]$CheckInterval = 30  # Check every 30 seconds
)

$hostname = $env:COMPUTERNAME

# Define services to monitor based on machine
$servicesToMonitor = @{}

# Configure based on hostname
if ($hostname -like "*Pyramids*") {
    $servicesToMonitor = @{
        "DNS" = "DNS Server"
        "NTDS" = "Active Directory"
        "Netlogon" = "Netlogon"
    }
    $requiredPorts = @(53, 88, 389, 636)
}
elseif ($hostname -like "*Olympics*") {
    $servicesToMonitor = @{
        "WinRM" = "Windows Remote Management"
    }
    $requiredPorts = @(5985, 5986)
}
elseif ($hostname -like "*Wright*") {
    $servicesToMonitor = @{
        "LanmanServer" = "SMB Server"
    }
    $requiredPorts = @(445, 139)
}
elseif ($hostname -like "*Moon*") {
    $servicesToMonitor = @{
        "W3SVC" = "IIS"
        "WAS" = "Windows Process Activation"
    }
    $requiredPorts = @(80, 443)
}

function Send-Alert {
    param($Message, $Severity = "WARNING")
    
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "INFO" { "Green" }
        default { "White" }
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] [$Severity] $Message" -ForegroundColor $color
    
    # Optional: Play a beep for critical alerts
    if ($Severity -eq "CRITICAL") {
        [Console]::Beep(1000, 500)
    }
}

function Check-Services {
    foreach ($service in $servicesToMonitor.Keys) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        
        if (-not $svc) {
            Send-Alert "Service $($servicesToMonitor[$service]) NOT FOUND!" "CRITICAL"
        }
        elseif ($svc.Status -ne "Running") {
            Send-Alert "Service $($servicesToMonitor[$service]) is $($svc.Status) - ATTEMPTING RESTART" "CRITICAL"
            try {
                Start-Service -Name $service
                Send-Alert "Successfully restarted $($servicesToMonitor[$service])" "INFO"
            }
            catch {
                Send-Alert "FAILED to restart $($servicesToMonitor[$service]): $_" "CRITICAL"
            }
        }
    }
}

function Check-FirewallStatus {
    $profiles = Get-NetFirewallProfile
    
    foreach ($profile in $profiles) {
        if ($profile.Enabled -eq $false) {
            Send-Alert "Firewall profile $($profile.Name) is DISABLED!" "CRITICAL"
            try {
                Set-NetFirewallProfile -Name $profile.Name -Enabled True
                Send-Alert "Re-enabled firewall profile $($profile.Name)" "INFO"
            }
            catch {
                Send-Alert "Failed to enable firewall: $_" "CRITICAL"
            }
        }
    }
}

function Check-NewUsers {
    $currentUsers = (Get-LocalUser | Where-Object {$_.Enabled -eq $true}).Name
    
    if ($script:lastUserList) {
        $newUsers = Compare-Object -ReferenceObject $script:lastUserList -DifferenceObject $currentUsers | Where-Object {$_.SideIndicator -eq "=>"}
        
        if ($newUsers) {
            foreach ($user in $newUsers) {
                Send-Alert "NEW USER DETECTED: $($user.InputObject)" "CRITICAL"
            }
        }
    }
    
    $script:lastUserList = $currentUsers
}

function Check-AdminGroup {
    $currentAdmins = (Get-LocalGroupMember -Group "Administrators").Name
    
    if ($script:lastAdminList) {
        $newAdmins = Compare-Object -ReferenceObject $script:lastAdminList -DifferenceObject $currentAdmins | Where-Object {$_.SideIndicator -eq "=>"}
        
        if ($newAdmins) {
            foreach ($admin in $newAdmins) {
                Send-Alert "NEW ADMINISTRATOR DETECTED: $($admin.InputObject)" "CRITICAL"
            }
        }
    }
    
    $script:lastAdminList = $currentAdmins
}

function Check-SuspiciousProcesses {
    # List of suspicious process names (actual hacking tools)
    $suspiciousNames = @("nc", "ncat", "netcat", "powercat", "mimikatz", "psexec", "procdump", "cobalt", "meterpreter", "empire", "crackmapexec", "bloodhound", "sharpup")
    
    # Whitelist of legitimate Windows processes that might match patterns
    $whitelist = @("PhoneExperienceHost", "ShellExperienceHost", "StartMenuExperienceHost", "SearchHost", "RuntimeBroker", "ApplicationFrameHost")
    
    $processes = Get-Process
    
    foreach ($proc in $processes) {
        # Skip if it's a whitelisted legitimate process
        if ($whitelist -contains $proc.Name) {
            continue
        }
        
        foreach ($suspicious in $suspiciousNames) {
            if ($proc.Name -like "*$suspicious*") {
                Send-Alert "SUSPICIOUS PROCESS: $($proc.Name) (PID: $($proc.Id))" "CRITICAL"
            }
        }
    }
}

function Check-NewConnections {
    $connections = Get-NetTCPConnection | Where-Object {
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notlike "127.*" -and 
        $_.RemoteAddress -notlike "::1" -and
        $_.RemoteAddress -notlike "10.*" -and
        $_.RemoteAddress -notlike "192.168.*" -and
        $_.RemoteAddress -notlike "172.16.*" -and
        $_.RemoteAddress -notlike "172.20.*"
    }
    
    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($conn.RemotePort -notin @(80, 443, 53)) {  # Ignore common legitimate ports
            Send-Alert "External connection: $($conn.RemoteAddress):$($conn.RemotePort) by $($proc.Name)" "WARNING"
        }
    }
}

# Initialize tracking variables
$script:lastUserList = $null
$script:lastAdminList = $null

Send-Alert "CONTINUOUS MONITOR STARTED ON $hostname" "INFO"

# Initial baseline
Check-NewUsers
Check-AdminGroup

# Main monitoring loop
while ($true) {
    try {
        Check-Services
        Check-FirewallStatus
        Check-NewUsers
        Check-AdminGroup
        Check-SuspiciousProcesses
        Check-NewConnections
        
        Write-Host "." -NoNewline  # Progress indicator
        
    }
    catch {
        Send-Alert "Monitor error: $_" "WARNING"
    }
    
    Start-Sleep -Seconds $CheckInterval
}