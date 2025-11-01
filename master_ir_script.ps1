# Master Incident Response Script for IRSeC 2025
# Auto-detects machine and runs appropriate hardening

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

Log-Action "===== STARTING IR SCRIPT ON $hostname ====="

# ==================== USER MANAGEMENT ====================
function Secure-Users {
    param($AuthorizedLocalUsers, $AuthorizedDomainUsers)
    
    Log-Action "=== USER SECURITY PHASE ==="
    
    # NOTE: Password changes are handled by separate Password Manager script
    Log-Action "[*] Run Password_Manager.ps1 separately to change passwords"
    
    # Get all local users
    $allLocalUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
    
    # Find unauthorized users
    $unauthorizedUsers = @()
    foreach ($user in $allLocalUsers) {
        if ($AuthorizedLocalUsers -notcontains $user.Name -and $user.Name -ne "Administrator" -and $user.Name -ne "Guest") {
            $unauthorizedUsers += $user.Name
        }
    }
    
    # Find unauthorized users
    $unauthorizedUsers = @()
    foreach ($user in $allLocalUsers) {
        if ($AuthorizedLocalUsers -notcontains $user.Name -and $user.Name -ne "Administrator" -and $user.Name -ne "Guest") {
            $unauthorizedUsers += $user.Name
        }
    }
    
    # ALWAYS review each user individually
    if ($unauthorizedUsers.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "UNAUTHORIZED USERS DETECTED:" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Yellow
        foreach ($user in $unauthorizedUsers) {
            Write-Host "  - $user" -ForegroundColor Red
        }
        Write-Host "`nAuthorized users are:" -ForegroundColor Cyan
        foreach ($user in $AuthorizedLocalUsers) {
            Write-Host "  - $user" -ForegroundColor Green
        }
        Write-Host "`n** REVIEWING EACH USER INDIVIDUALLY **" -ForegroundColor Magenta
        
        foreach ($user in $unauthorizedUsers) {
            Write-Host "`n----------------------------------------" -ForegroundColor Cyan
            Write-Host "User: $user" -ForegroundColor Yellow
            Write-Host "  1 = Disable (RECOMMENDED - can undo later)" -ForegroundColor Green
            Write-Host "  2 = Delete (PERMANENT removal)" -ForegroundColor Red
            Write-Host "  3 = Keep (might be White/Black team)" -ForegroundColor Cyan
            $userChoice = Read-Host "Action for $user (1-3)"
            
            switch ($userChoice) {
                "1" {
                    try {
                        Disable-LocalUser -Name $user
                        Log-Action "[+] Disabled user: $user"
                        Write-Host "[+] Disabled: $user" -ForegroundColor Green
                    } catch {
                        Log-Action "[-] Failed to disable $user $_"
                        Write-Host "[-] Failed to disable: $user" -ForegroundColor Red
                    }
                }
                "2" {
                    Write-Host "    Confirm DELETE $user? (yes/no)" -ForegroundColor Red
                    $confirm = Read-Host
                    if ($confirm -eq "yes") {
                        try {
                            Remove-LocalUser -Name $user
                            Log-Action "[+] DELETED user: $user"
                            Write-Host "[+] DELETED: $user" -ForegroundColor Green
                        } catch {
                            Log-Action "[-] Failed to delete $user $_"
                            Write-Host "[-] Failed to delete: $user" -ForegroundColor Red
                        }
                    } else {
                        Log-Action "[*] Skipped deletion of: $user"
                        Write-Host "[*] Skipped deletion" -ForegroundColor Yellow
                    }
                }
                "3" {
                    Log-Action "[*] Kept user: $user (may be White/Black team)"
                    Write-Host "[*] Keeping: $user" -ForegroundColor Cyan
                }
                default {
                    Log-Action "[*] Invalid choice for $user - keeping user"
                    Write-Host "[*] Invalid choice - keeping user" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Log-Action "[+] No unauthorized users detected"
        Write-Host "[+] No unauthorized users found!" -ForegroundColor Green
    }
    
    # Check Admin group membership
    $adminGroup = Get-LocalGroupMember -Group "Administrators"
    Log-Action "[*] Current Administrators:"
    
    $unauthorizedAdmins = @()
    foreach ($admin in $adminGroup) {
        Log-Action "    - $($admin.Name)"
        $adminUsername = $admin.Name.Split('\')[-1]
        if ($AuthorizedLocalUsers -notcontains $adminUsername -and $admin.Name -notlike "*Administrator" -and $adminUsername -ne "Administrator") {
            $unauthorizedAdmins += $admin.Name
        }
    }
    
    if ($unauthorizedAdmins.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "UNAUTHORIZED ADMINISTRATORS DETECTED:" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Yellow
        foreach ($admin in $unauthorizedAdmins) {
            Write-Host "  - $admin" -ForegroundColor Red
        }
        Write-Host "`n** TAKE SCREENSHOTS FOR EVIDENCE **" -ForegroundColor Magenta
        Write-Host "`nRemove all unauthorized admins? (yes/no)" -ForegroundColor Yellow
        $removeChoice = Read-Host
        
        if ($removeChoice -eq "yes") {
            foreach ($admin in $unauthorizedAdmins) {
                try {
                    Remove-LocalGroupMember -Group "Administrators" -Member $admin
                    Log-Action "[+] Removed unauthorized admin: $admin"
                    Write-Host "[+] Removed admin: $admin" -ForegroundColor Green
                } catch {
                    Log-Action "[-] Failed to remove admin $admin $_"
                    Write-Host "[-] Failed to remove: $admin" -ForegroundColor Red
                }
            }
        } else {
            Log-Action "[*] User chose not to remove unauthorized admins"
            Write-Host "Skipping admin removal..." -ForegroundColor Yellow
        }
    } else {
        Log-Action "[+] No unauthorized administrators detected"
        Write-Host "[+] No unauthorized admins found!" -ForegroundColor Green
    }
}

# ==================== SERVICE MANAGEMENT ====================
function Secure-Service {
    param($ServiceName, $DisplayName)
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($service) {
        if ($service.Status -ne "Running") {
            Start-Service -Name $ServiceName
            Log-Action "[+] Started $DisplayName service"
        }
        Set-Service -Name $ServiceName -StartupType Automatic
        Log-Action "[+] Set $DisplayName to Automatic startup"
    } else {
        Log-Action "[-] $DisplayName service not found!"
    }
}

# ==================== FIREWALL CONFIGURATION ====================
function Configure-Firewall {
    param($AllowedPorts, $MachinePurpose)
    
    Log-Action "=== FIREWALL CONFIGURATION ==="
    
    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Log-Action "[+] Enabled Windows Firewall on all profiles"
    
    # Set default deny
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Log-Action "[+] Set default inbound to BLOCK"
    
    # Remove all existing rules (nuclear option - be careful!)
    # Uncomment if you want to start fresh
    # Get-NetFirewallRule | Remove-NetFirewallRule
    
    # Allow SSH from management (for your access)
    New-NetFirewallRule -DisplayName "Allow SSH Inbound" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Enabled True -ErrorAction SilentlyContinue
    Log-Action "[+] Allowed SSH (port 22)"
    
    # Verify SSH service is configured for port 22 (Windows OpenSSH)
    $sshService = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if ($sshService) {
        if ($sshService.Status -ne "Running") {
            Start-Service -Name "sshd"
            Log-Action "[+] Started SSH service"
        }
        Set-Service -Name "sshd" -StartupType Automatic
        Log-Action "[+] SSH service set to Automatic"
        
        # Check SSH config for port
        $sshConfig = "C:\ProgramData\ssh\sshd_config"
        if (Test-Path $sshConfig) {
            $portLine = Select-String -Path $sshConfig -Pattern "^Port " -ErrorAction SilentlyContinue
            if ($portLine) {
                Log-Action "[*] SSH configured on: $($portLine.Line)"
            } else {
                Log-Action "[+] SSH using default port 22"
            }
        }
    } else {
        Log-Action "[!] SSH service not found - may need manual installation"
    }
    
    # Allow RDP for emergency access
    New-NetFirewallRule -DisplayName "Allow RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Enabled True -ErrorAction SilentlyContinue
    Log-Action "[+] Allowed RDP (port 3389)"
    
    # Allow scored service ports
    foreach ($port in $AllowedPorts) {
        New-NetFirewallRule -DisplayName "Allow $MachinePurpose Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Enabled True -ErrorAction SilentlyContinue
        Log-Action "[+] Allowed $MachinePurpose on port $port"
    }
    
    # Allow ICMP (ping) if this is Silk Road or for general connectivity
    New-NetFirewallRule -DisplayName "Allow ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Enabled True -ErrorAction SilentlyContinue
    Log-Action "[+] Allowed ICMP (ping)"
    
    # Block common attack ports
    $blockPorts = @(23, 21, 20, 69, 135, 137, 138, 139, 4444, 4445, 5555, 8888, 9999)
    foreach ($port in $blockPorts) {
        New-NetFirewallRule -DisplayName "Block Attack Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Block -Enabled True -ErrorAction SilentlyContinue
    }
    Log-Action "[+] Blocked common attack ports"
}

# ==================== PERSISTENCE CHECK ====================
function Check-Persistence {
    Log-Action "=== CHECKING FOR PERSISTENCE ==="
    
    # Check scheduled tasks
    Log-Action "[*] Suspicious Scheduled Tasks:"
    $tasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}
    foreach ($task in $tasks) {
        Log-Action "    - $($task.TaskName) in $($task.TaskPath)"
    }
    
    # Check startup programs
    Log-Action "[*] Startup Programs:"
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
    
    Log-Action "[*] Registry Run Keys:"
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

# ==================== NETWORK MONITORING ====================
function Check-Network {
    Log-Action "=== NETWORK CONNECTIONS ==="
    
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        Log-Action "[*] $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($process.Name)]"
    }
}

# ==================== HANDLE DOMAIN USERS (if DC) ====================
$isDC = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
if ($isDC -and $isDC.Status -eq "Running") {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "DOMAIN CONTROLLER DETECTED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "Do you want to check DOMAIN users? (yes/no)" -ForegroundColor Yellow
    $checkDomain = Read-Host
    
    if ($checkDomain -eq "yes") {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # Define authorized domain users
            $authorizedDomainAdmins = @("fathertime", "chronos", "aion", "kairos")
            $authorizedDomainUsers = @("merlin", "terminator", "mrpeabody", "jamescole", "docbrown", "professorparadox")
            $allAuthorizedDomain = $authorizedDomainAdmins + $authorizedDomainUsers
            
            # Get all domain users
            $allDomainUsers = Get-ADUser -Filter {Enabled -eq $true} | Select-Object -ExpandProperty SamAccountName
            
            # Find unauthorized domain users
            $unauthorizedDomainUsers = @()
            foreach ($user in $allDomainUsers) {
                if ($allAuthorizedDomain -notcontains $user -and $user -ne "Administrator" -and $user -ne "Guest" -and $user -notlike "krbtgt") {
                    $unauthorizedDomainUsers += $user
                }
            }
            
            # Review each unauthorized domain user individually
            if ($unauthorizedDomainUsers.Count -gt 0) {
                Write-Host "`n========================================" -ForegroundColor Yellow
                Write-Host "UNAUTHORIZED DOMAIN USERS DETECTED:" -ForegroundColor Red
                Write-Host "========================================" -ForegroundColor Yellow
                foreach ($user in $unauthorizedDomainUsers) {
                    Write-Host "  - $user" -ForegroundColor Red
                }
                Write-Host "`nAuthorized domain users are:" -ForegroundColor Cyan
                foreach ($user in $allAuthorizedDomain) {
                    Write-Host "  - $user" -ForegroundColor Green
                }
                Write-Host "`n** REVIEWING EACH DOMAIN USER INDIVIDUALLY **" -ForegroundColor Magenta
                
                foreach ($user in $unauthorizedDomainUsers) {
                    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
                    Write-Host "Domain User: $user" -ForegroundColor Yellow
                    Write-Host "  1 = Disable (RECOMMENDED - can undo later)" -ForegroundColor Green
                    Write-Host "  2 = Delete (PERMANENT removal)" -ForegroundColor Red
                    Write-Host "  3 = Keep (might be White/Black team)" -ForegroundColor Cyan
                    $userChoice = Read-Host "Action for $user (1-3)"
                    
                    switch ($userChoice) {
                        "1" {
                            try {
                                Disable-ADAccount -Identity $user
                                Log-Action "[+] Disabled domain user: $user"
                                Write-Host "[+] Disabled: $user" -ForegroundColor Green
                            } catch {
                                Log-Action "[-] Failed to disable domain user $user $_"
                                Write-Host "[-] Failed to disable: $user" -ForegroundColor Red
                            }
                        }
                        "2" {
                            Write-Host "    Confirm DELETE domain user $user? (yes/no)" -ForegroundColor Red
                            $confirm = Read-Host
                            if ($confirm -eq "yes") {
                                try {
                                    Remove-ADUser -Identity $user -Confirm:$false
                                    Log-Action "[+] DELETED domain user: $user"
                                    Write-Host "[+] DELETED: $user" -ForegroundColor Green
                                } catch {
                                    Log-Action "[-] Failed to delete domain user $user $_"
                                    Write-Host "[-] Failed to delete: $user" -ForegroundColor Red
                                }
                            } else {
                                Log-Action "[*] Skipped deletion of domain user: $user"
                                Write-Host "[*] Skipped deletion" -ForegroundColor Yellow
                            }
                        }
                        "3" {
                            Log-Action "[*] Kept domain user: $user (may be White/Black team)"
                            Write-Host "[*] Keeping: $user" -ForegroundColor Cyan
                        }
                        default {
                            Log-Action "[*] Invalid choice for domain user $user - keeping user"
                            Write-Host "[*] Invalid choice - keeping user" -ForegroundColor Yellow
                        }
                    }
                }
            } else {
                Log-Action "[+] No unauthorized domain users detected"
                Write-Host "[+] No unauthorized domain users found!" -ForegroundColor Green
            }
            
            # Check Domain Admins group
            Write-Host "`n========================================" -ForegroundColor Yellow
            Write-Host "Checking Domain Admins group..." -ForegroundColor Cyan
            
            try {
                $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty SamAccountName
                
                Log-Action "[*] Current Domain Admins:"
                foreach ($admin in $domainAdmins) {
                    Log-Action "    - $admin"
                }
                
                $unauthorizedDomainAdmins = @()
                foreach ($admin in $domainAdmins) {
                    if ($authorizedDomainAdmins -notcontains $admin -and $admin -ne "Administrator") {
                        $unauthorizedDomainAdmins += $admin
                    }
                }
                
                if ($unauthorizedDomainAdmins.Count -gt 0) {
                    Write-Host "`nUNAUTHORIZED DOMAIN ADMINS DETECTED:" -ForegroundColor Red
                    foreach ($admin in $unauthorizedDomainAdmins) {
                        Write-Host "  - $admin" -ForegroundColor Red
                    }
                    Write-Host "`n** REVIEWING EACH DOMAIN ADMIN INDIVIDUALLY **" -ForegroundColor Magenta
                    
                    foreach ($admin in $unauthorizedDomainAdmins) {
                        Write-Host "`n----------------------------------------" -ForegroundColor Cyan
                        Write-Host "Domain Admin: $admin" -ForegroundColor Yellow
                        Write-Host "  1 = Remove from Domain Admins (RECOMMENDED)" -ForegroundColor Green
                        Write-Host "  2 = Keep in Domain Admins (might be White/Black team)" -ForegroundColor Cyan
                        $adminChoice = Read-Host "Action for $admin (1-2)"
                        
                        switch ($adminChoice) {
                            "1" {
                                try {
                                    Remove-ADGroupMember -Identity "Domain Admins" -Members $admin -Confirm:$false
                                    Log-Action "[+] Removed $admin from Domain Admins"
                                    Write-Host "[+] Removed from Domain Admins: $admin" -ForegroundColor Green
                                } catch {
                                    Log-Action "[-] Failed to remove $admin from Domain Admins: $_"
                                    Write-Host "[-] Failed to remove: $admin" -ForegroundColor Red
                                }
                            }
                            "2" {
                                Log-Action "[*] Kept $admin in Domain Admins (may be White/Black team)"
                                Write-Host "[*] Keeping in Domain Admins: $admin" -ForegroundColor Cyan
                            }
                            default {
                                Log-Action "[*] Invalid choice for $admin - keeping in Domain Admins"
                                Write-Host "[*] Invalid choice - keeping" -ForegroundColor Yellow
                            }
                        }
                    }
                } else {
                    Log-Action "[+] No unauthorized Domain Admins detected"
                    Write-Host "[+] No unauthorized Domain Admins found!" -ForegroundColor Green
                }
            } catch {
                Log-Action "[-] Failed to check Domain Admins group: $_"
                Write-Host "[-] Could not check Domain Admins group" -ForegroundColor Red
            }
            
        } catch {
            Write-Host "[-] Could not manage domain users: $_" -ForegroundColor Red
            Log-Action "[ERROR] Domain user management failed: $_"
        }
    } else {
        Log-Action "[*] User chose to skip domain user checking"
        Write-Host "Skipping domain user checking..." -ForegroundColor Yellow
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
            Log-Action "[+] Enabled PSRemoting/WinRM"
        } catch {
            Log-Action "[-] Failed to enable WinRM: $_"
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
        Log-Action "[+] Enabled SMB signing"
        
        # Check SMB shares
        Log-Action "[*] Current SMB Shares:"
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
        Log-Action "[*] Checking for suspicious web files..."
        $webPaths = @("C:\inetpub\wwwroot", "C:\inetpub\wwwroot\aspnet_client")
        
        foreach ($path in $webPaths) {
            if (Test-Path $path) {
                $suspiciousFiles = Get-ChildItem -Path $path -Recurse -Include *.aspx,*.asp,*.php,*.jsp -ErrorAction SilentlyContinue
                foreach ($file in $suspiciousFiles) {
                    Log-Action "    [!] Found web file: $($file.FullName)"
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

# Run common checks on all machines
Check-Persistence
Check-Network

Log-Action "===== IR SCRIPT COMPLETED ====="
Log-Action "Log file saved to: $logFile"
Write-Host "`nLog file saved to: $logFile" -ForegroundColor Green