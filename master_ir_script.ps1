# Require Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run as Administrator!"
    Exit
}

# Detect which machine we're on
$hostname = $env:COMPUTERNAME
$logFile = "C:\IR_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Log-Action {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

Log-Action "STARTING IR SCRIPT ON $hostname"

function Secure-Service {
    param($ServiceName, $DisplayName)
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($service) {
        if ($service.Status -ne "Running") {
            Start-Service -Name $ServiceName
            Log-Action "Started $DisplayName service"
        }
        Set-Service -Name $ServiceName -StartupType Automatic
        Log-Action "Set $DisplayName to Automatic startup"
    } else {
        Log-Action "$DisplayName service not found!"
    }
}

function Configure-Firewall {
    param($AllowedPorts, $MachinePurpose)
    
    Log-Action "FIREWALL CONFIGURATION"
    
    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled "True"
    Log-Action "Enabled Windows Firewall on all profiles"
    
    # Set default deny
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Log-Action "Set default inbound to BLOCK"
    
    # Allow SSH from management (for your access)
    New-NetFirewallRule -DisplayName "Allow SSH Inbound" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Enabled True -ErrorAction SilentlyContinue
    Log-Action "Allowed SSH (port 22)"
    
    # Verify SSH service is configured for port 22 (Windows OpenSSH)
    $sshService = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if ($sshService) {
        if ($sshService.Status -ne "Running") {
            Start-Service -Name "sshd"
            Log-Action "Started SSH service"
        }
        Set-Service -Name "sshd" -StartupType Automatic
        Log-Action "SSH service set to Automatic"
        
        # Check SSH config for port
        $sshConfig = "C:\ProgramData\ssh\sshd_config"
        if (Test-Path $sshConfig) {
            $portLine = Select-String -Path $sshConfig -Pattern "^Port " -ErrorAction SilentlyContinue
            if ($portLine) {
                Log-Action "SSH configured on: $($portLine.Line)"
            } else {
                Log-Action "SSH using default port 22"
            }
        }
    } else {
        Log-Action "SSH service not found - may need manual installation"
    }
    
    # Allow RDP for emergency access
    New-NetFirewallRule -DisplayName "Allow RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Enabled True -ErrorAction SilentlyContinue
    Log-Action "Allowed RDP (port 3389)"
    
    # Allow scored service ports
    foreach ($port in $AllowedPorts) {
        New-NetFirewallRule -DisplayName "Allow $MachinePurpose Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Enabled True -ErrorAction SilentlyContinue
        Log-Action "Allowed $MachinePurpose on port $port"
    }
    
    # Allow ICMP (ping) if this is Silk Road or for general connectivity
    New-NetFirewallRule -DisplayName "Allow ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Enabled True -ErrorAction SilentlyContinue
    Log-Action "Allowed ICMP (ping)"
    
    # Block common attack ports
    $blockPorts = @(23, 21, 20, 69, 135, 137, 138, 139, 4444, 4445, 5555, 8888, 9999)
    foreach ($port in $blockPorts) {
        New-NetFirewallRule -DisplayName "Block Attack Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Block -Enabled True -ErrorAction SilentlyContinue
    }
    Log-Action "Blocked common attack ports"
}

function Check-Persistence {
    Log-Action "CHECKING FOR PERSISTENCE"
    
    # Check scheduled tasks
    Log-Action "Suspicious Scheduled Tasks:"
    $tasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}
    foreach ($task in $tasks) {
        Log-Action "    - $($task.TaskName) in $($task.TaskPath)"
    }
    
    # Check startup programs
    Log-Action "Startup Programs:"
    $startupItems = Get-CimInstance Win32_StartupCommand
    foreach ($item in $startupItems) {
        Log-Action "    - $($item.Name): $($item.Command)"
    }
    
    # Check run keys
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    Log-Action "Registry Run Keys:"
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty -Path $key
            foreach ($prop in $entries.PSObject.Properties) {
                if ($prop.Name -notlike "PS*") {
                    Log-Action "    - $key\$($prop.Name): $($prop.Value)"
                }
            }
        }
    }
}

function Check-Network {
    Log-Action "NETWORK CONNECTIONS"
    
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        Log-Action "$($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($process.Name)]"
    }
}

switch -Wildcard ($hostname) {
    "*Pyramids*" {
        Log-Action "Detected: PYRAMIDS (AD/DNS Server)"
        
        $authorizedLocal = @("drwho", "martymcFly", "arthurdent", "sambeckett", "loki", "riphunter", "theflash", "tonystark", "drstrange", "bartallen")
        Secure-Users -AuthorizedLocalUsers $authorizedLocal -AuthorizedDomainUsers @()
        
        # Secure AD/DNS services
        Secure-Service -ServiceName "DNS" -DisplayName "DNS Server"
        Secure-Service -ServiceName "NTDS" -DisplayName "Active Directory Domain Services"
        Secure-Service -ServiceName "Netlogon" -DisplayName "Netlogon"
        Secure-Service -ServiceName "W32Time" -DisplayName "Windows Time"
        
        # DNS/AD ports: 53, 88, 389, 636, 3268, 3269, 135, 445
        Configure-Firewall -AllowedPorts @(53, 88, 389, 636, 3268, 3269, 135, 445, 464, 9389) -MachinePurpose "AD/DNS"
    }
    
    "*Olympics*" {
        Log-Action "Detected: FIRST OLYMPICS (WinRM Server)"
        
        $authorizedLocal = @("drwho", "martymcFly", "arthurdent", "sambeckett", "loki", "riphunter", "theflash", "tonystark", "drstrange", "bartallen")
        Secure-Users -AuthorizedLocalUsers $authorizedLocal -AuthorizedDomainUsers @()
        
        # Secure WinRM
        Secure-Service -ServiceName "WinRM" -DisplayName "Windows Remote Management"
        
        # Enable WinRM if not configured
        try {
            Enable-PSRemoting -Force
            Log-Action "Enabled PSRemoting/WinRM"
        } catch {
            Log-Action "Failed to enable WinRM: $_"
        }
        
        # WinRM ports: 5985 (HTTP), 5986 (HTTPS)
        Configure-Firewall -AllowedPorts @(5985, 5986) -MachinePurpose "WinRM"
    }
    
    "*Silk*" {
        Log-Action "Detected: SILK ROAD (ICMP/Ping Server)"
        
        $authorizedLocal = @("drwho", "martymcFly", "arthurdent", "sambeckett", "loki", "riphunter", "theflash", "tonystark", "drstrange", "bartallen")
        Secure-Users -AuthorizedLocalUsers $authorizedLocal -AuthorizedDomainUsers @()
        
        # Just needs to respond to ping - firewall handles this
        Configure-Firewall -AllowedPorts @() -MachinePurpose "ICMP"
    }
    
    "*Wright*" {
        Log-Action "Detected: WRIGHT BROTHERS (SMB Server)"
        
        $authorizedLocal = @("drwho", "martymcFly", "arthurdent", "sambeckett", "loki", "riphunter", "theflash", "tonystark", "drstrange", "bartallen")
        Secure-Users -AuthorizedLocalUsers $authorizedLocal -AuthorizedDomainUsers @()
        
        # Secure SMB
        Secure-Service -ServiceName "LanmanServer" -DisplayName "Server (SMB)"
        
        # Enable SMB signing
        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
        Log-Action "Enabled SMB signing"
        
        # Check SMB shares
        Log-Action "Current SMB Shares:"
        $shares = Get-SmbShare
        foreach ($share in $shares) {
            Log-Action "    - $($share.Name): $($share.Path)"
        }
        
        # SMB ports: 445, 139
        Configure-Firewall -AllowedPorts @(445, 139) -MachinePurpose "SMB"
    }
    
    "*Moon*" {
        Log-Action "Detected: MOON LANDING (IIS Web Server)"
        
        $authorizedLocal = @("drwho", "martymcFly", "arthurdent", "sambeckett", "loki", "riphunter", "theflash", "tonystark", "drstrange", "bartallen")
        Secure-Users -AuthorizedLocalUsers $authorizedLocal -AuthorizedDomainUsers @()
        
        # Secure IIS
        Secure-Service -ServiceName "W3SVC" -DisplayName "World Wide Web Publishing Service"
        Secure-Service -ServiceName "WAS" -DisplayName "Windows Process Activation Service"
        
        # Check for webshells in common locations
        Log-Action "Checking for suspicious web files..."
        $webPaths = @("C:\inetpub\wwwroot", "C:\inetpub\wwwroot\aspnet_client")
        
        foreach ($path in $webPaths) {
            if (Test-Path $path) {
                $suspiciousFiles = Get-ChildItem -Path $path -Recurse -Include *.aspx,*.asp,*.php,*.jsp -ErrorAction SilentlyContinue
                foreach ($file in $suspiciousFiles) {
                    Log-Action "    Found web file: $($file.FullName)"
                }
            }
        }
        
        # IIS ports: 80, 443
        Configure-Firewall -AllowedPorts @(80, 443) -MachinePurpose "IIS"
    }
    
    default {
        Log-Action "Unknown hostname: $hostname - Running generic hardening"
        
        $authorizedLocal = @("drwho", "martymcFly", "arthurdent", "sambeckett", "loki", "riphunter", "theflash", "tonystark", "drstrange", "bartallen")
        Secure-Users -AuthorizedLocalUsers $authorizedLocal -AuthorizedDomainUsers @()
        Configure-Firewall -AllowedPorts @() -MachinePurpose "Generic"
    }
}

Check-Persistence
Check-Network

Log-Action "IR SCRIPT COMPLETED!"
Log-Action "Log file saved to: $logFile"
Write-Host "`nLog file saved to: $logFile" -ForegroundColor Green