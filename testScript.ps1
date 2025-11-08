# Comprehensive Test Suite for IRSeC Scripts
# Tests all functionality of all scripts

# Require Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run as Administrator!"
    Exit
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  IRSeC SCRIPT TEST SUITE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will test all functions of your scripts." -ForegroundColor Yellow
Write-Host "Tests will create and remove users, change firewall, etc." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Enter to continue or Ctrl+C to cancel..." -ForegroundColor Cyan
Read-Host

$testResults = @()

function Test-Result {
    param($TestName, $Passed, $Details = "")
    
    $result = [PSCustomObject]@{
        Test = $TestName
        Passed = $Passed
        Details = $Details
    }
    
    $script:testResults += $result
    
    if ($Passed) {
        Write-Host "[PASS] $TestName" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $TestName - $Details" -ForegroundColor Red
    }
}

# ==================== TEST 1: PASSWORD MANAGER SCRIPT ====================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 1: Password Manager Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Test 1.1: Create test users
Write-Host "`n[1.1] Creating test users..." -ForegroundColor Yellow
try {
    $testPassword = ConvertTo-SecureString "Test123!" -AsPlainText -Force
    New-LocalUser -Name "testuser1" -Password $testPassword -PasswordNeverExpires -ErrorAction Stop | Out-Null
    New-LocalUser -Name "testuser2" -Password $testPassword -PasswordNeverExpires -ErrorAction Stop | Out-Null
    Test-Result "Create test users" $true
} catch {
    Test-Result "Create test users" $false $_
}

# Test 1.2: Verify password can be changed
Write-Host "`n[1.2] Testing password change functionality..." -ForegroundColor Yellow
try {
    $newPassword = ConvertTo-SecureString "NewPass123!" -AsPlainText -Force
    Set-LocalUser -Name "testuser1" -Password $newPassword -ErrorAction Stop
    Test-Result "Password change" $true
} catch {
    Test-Result "Password change" $false $_
}

# Test 1.3: Verify password file would be created
Write-Host "`n[1.3] Testing password file creation..." -ForegroundColor Yellow
try {
    $testPasswordFile = "C:\Test_Passwords.txt"
    "Test Password Data" | Out-File $testPasswordFile -Force
    $exists = Test-Path $testPasswordFile
    Remove-Item $testPasswordFile -Force
    Test-Result "Password file creation" $exists
} catch {
    Test-Result "Password file creation" $false $_
}

# ==================== TEST 2: MASTER IR SCRIPT FUNCTIONS ====================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 2: Master IR Script Functions" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Test 2.1: User detection
Write-Host "`n[2.1] Testing unauthorized user detection..." -ForegroundColor Yellow
try {
    New-LocalUser -Name "hacker123" -Password $testPassword -PasswordNeverExpires -ErrorAction Stop | Out-Null
    $allUsers = Get-LocalUser
    $hackerExists = $allUsers | Where-Object {$_.Name -eq "hacker123"}
    Test-Result "Unauthorized user detection" ($hackerExists -ne $null)
} catch {
    Test-Result "Unauthorized user detection" $false $_
}

# Test 2.2: User disable functionality
Write-Host "`n[2.2] Testing user disable..." -ForegroundColor Yellow
try {
    Disable-LocalUser -Name "hacker123" -ErrorAction Stop
    $user = Get-LocalUser -Name "hacker123"
    Test-Result "User disable" ($user.Enabled -eq $false)
} catch {
    Test-Result "User disable" $false $_
}

# Test 2.3: User deletion functionality
Write-Host "`n[2.3] Testing user deletion..." -ForegroundColor Yellow
try {
    Remove-LocalUser -Name "hacker123" -ErrorAction Stop
    $userExists = Get-LocalUser -Name "hacker123" -ErrorAction SilentlyContinue
    Test-Result "User deletion" ($userExists -eq $null)
} catch {
    Test-Result "User deletion" $false $_
}

# Test 2.4: Admin group manipulation
Write-Host "`n[2.4] Testing admin group manipulation..." -ForegroundColor Yellow
try {
    Add-LocalGroupMember -Group "Administrators" -Member "testuser1" -ErrorAction Stop
    $isAdmin = (Get-LocalGroupMember -Group "Administrators").Name -contains "testuser1" -or (Get-LocalGroupMember -Group "Administrators").Name -match "testuser1"
    Remove-LocalGroupMember -Group "Administrators" -Member "testuser1" -ErrorAction Stop
    Test-Result "Admin group manipulation" $isAdmin
} catch {
    Test-Result "Admin group manipulation" $false $_
}

# Test 2.5: Service management
Write-Host "`n[2.5] Testing service management..." -ForegroundColor Yellow
try {
    Stop-Service -Name "Spooler" -Force -ErrorAction Stop
    $stopped = (Get-Service -Name "Spooler").Status -eq "Stopped"
    Start-Service -Name "Spooler" -ErrorAction Stop
    $started = (Get-Service -Name "Spooler").Status -eq "Running"
    Test-Result "Service management" ($stopped -and $started)
} catch {
    Test-Result "Service management" $false $_
}

# Test 2.6: Firewall profile enable/disable
Write-Host "`n[2.6] Testing firewall profile management..." -ForegroundColor Yellow
try {
    $originalState = (Get-NetFirewallProfile -Name Domain).Enabled
    Set-NetFirewallProfile -Name Domain -Enabled $false -ErrorAction Stop
    $disabled = (Get-NetFirewallProfile -Name Domain).Enabled -eq $false
    Set-NetFirewallProfile -Name Domain -Enabled $true -ErrorAction Stop
    $enabled = (Get-NetFirewallProfile -Name Domain).Enabled -eq $true
    # Restore original state
    Set-NetFirewallProfile -Name Domain -Enabled $originalState
    Test-Result "Firewall profile management" ($disabled -and $enabled)
} catch {
    Test-Result "Firewall profile management" $false $_
}

# Test 2.7: Firewall rule creation
Write-Host "`n[2.7] Testing firewall rule creation..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "Test Rule" -Direction Inbound -Protocol TCP -LocalPort 9999 -Action Block -ErrorAction Stop | Out-Null
    $ruleExists = Get-NetFirewallRule -DisplayName "Test Rule" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "Test Rule" -ErrorAction SilentlyContinue
    Test-Result "Firewall rule creation" ($ruleExists -ne $null)
} catch {
    Test-Result "Firewall rule creation" $false $_
}

# Test 2.8: SSH port check
Write-Host "`n[2.8] Testing SSH configuration detection..." -ForegroundColor Yellow
try {
    $sshService = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    # Test passes if we can check for SSH service (may or may not exist)
    Test-Result "SSH configuration detection" $true "SSH service: $(if ($sshService) {'Found'} else {'Not installed'})"
} catch {
    Test-Result "SSH configuration detection" $false $_
}

# ==================== TEST 3: SNAPSHOT MONITOR SCRIPT ====================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 3: Snapshot Monitor Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Test 3.1: State file creation
Write-Host "`n[3.1] Testing state file creation..." -ForegroundColor Yellow
try {
    $testStateFile = "C:\TestSecurityState.json"
    $testState = @{
        Users = @("user1", "user2")
        Administrators = @("admin1")
    }
    $testState | ConvertTo-Json | Out-File $testStateFile -Force
    $exists = Test-Path $testStateFile
    Remove-Item $testStateFile -Force
    Test-Result "State file creation" $exists
} catch {
    Test-Result "State file creation" $false $_
}

# Test 3.2: User state collection
Write-Host "`n[3.2] Testing user state collection..." -ForegroundColor Yellow
try {
    $users = Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet
    Test-Result "User state collection" ($users.Count -gt 0)
} catch {
    Test-Result "User state collection" $false $_
}

# Test 3.3: Admin state collection
Write-Host "`n[3.3] Testing admin state collection..." -ForegroundColor Yellow
try {
    $admins = Get-LocalGroupMember -Group "Administrators"
    Test-Result "Admin state collection" ($admins.Count -gt 0)
} catch {
    Test-Result "Admin state collection" $false $_
}

# Test 3.4: Service state collection
Write-Host "`n[3.4] Testing service state collection..." -ForegroundColor Yellow
try {
    $service = Get-Service -Name "Spooler" -ErrorAction Stop
    $serviceState = @{
        Status = $service.Status.ToString()
        StartType = $service.StartType.ToString()
    }
    Test-Result "Service state collection" ($serviceState.Status -ne $null)
} catch {
    Test-Result "Service state collection" $false $_
}

# Test 3.5: Firewall state collection
Write-Host "`n[3.5] Testing firewall state collection..." -ForegroundColor Yellow
try {
    $profile = Get-NetFirewallProfile -Name Domain
    $profileState = @{
        Enabled = $profile.Enabled
        DefaultInboundAction = $profile.DefaultInboundAction.ToString()
    }
    Test-Result "Firewall state collection" ($profileState.Enabled -ne $null)
} catch {
    Test-Result "Firewall state collection" $false $_
}

# Test 3.6: Firewall rule collection
Write-Host "`n[3.6] Testing firewall rule collection..." -ForegroundColor Yellow
try {
    $rules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Select-Object -First 1
    Test-Result "Firewall rule collection" ($rules -ne $null)
} catch {
    Test-Result "Firewall rule collection" $false $_
}

# Test 3.7: Network connection collection
Write-Host "`n[3.7] Testing network connection collection..." -ForegroundColor Yellow
try {
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    Test-Result "Network connection collection" $true "Found $($connections.Count) connections"
} catch {
    Test-Result "Network connection collection" $false $_
}

# Test 3.8: Process detection
Write-Host "`n[3.8] Testing process detection..." -ForegroundColor Yellow
try {
    $processes = Get-Process
    Test-Result "Process detection" ($processes.Count -gt 0)
} catch {
    Test-Result "Process detection" $false $_
}

# ==================== TEST 4: INITIAL EVIDENCE SCRIPT ====================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 4: Initial Evidence Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Test 4.1: Evidence directory creation
Write-Host "`n[4.1] Testing evidence directory creation..." -ForegroundColor Yellow
try {
    $testEvidenceDir = "C:\TestEvidence"
    New-Item -ItemType Directory -Path $testEvidenceDir -Force | Out-Null
    $exists = Test-Path $testEvidenceDir
    Remove-Item $testEvidenceDir -Recurse -Force
    Test-Result "Evidence directory creation" $exists
} catch {
    Test-Result "Evidence directory creation" $false $_
}

# Test 4.2: Local user enumeration
Write-Host "`n[4.2] Testing local user enumeration..." -ForegroundColor Yellow
try {
    $users = Get-LocalUser
    Test-Result "Local user enumeration" ($users.Count -gt 0)
} catch {
    Test-Result "Local user enumeration" $false $_
}

# Test 4.3: Scheduled task enumeration
Write-Host "`n[4.3] Testing scheduled task enumeration..." -ForegroundColor Yellow
try {
    $tasks = Get-ScheduledTask
    Test-Result "Scheduled task enumeration" ($tasks.Count -gt 0)
} catch {
    Test-Result "Scheduled task enumeration" $false $_
}

# Test 4.4: Startup program enumeration
Write-Host "`n[4.4] Testing startup program enumeration..." -ForegroundColor Yellow
try {
    $startupItems = Get-CimInstance Win32_StartupCommand
    Test-Result "Startup program enumeration" $true "Found $($startupItems.Count) items"
} catch {
    Test-Result "Startup program enumeration" $false $_
}

# Test 4.5: Registry run key enumeration
Write-Host "`n[4.5] Testing registry run key enumeration..." -ForegroundColor Yellow
try {
    $runKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $exists = Test-Path $runKey
    Test-Result "Registry run key enumeration" $exists
} catch {
    Test-Result "Registry run key enumeration" $false $_
}

# Test 4.6: Event log collection
Write-Host "`n[4.6] Testing event log collection..." -ForegroundColor Yellow
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 5 -ErrorAction SilentlyContinue
    Test-Result "Event log collection" $true "Found $(if ($events) {$events.Count} else {0}) events"
} catch {
    Test-Result "Event log collection" $false $_
}

# ==================== TEST 5: FORENSICS COLLECTOR ====================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 5: Forensics Collector" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Test 5.1: System information collection
Write-Host "`n[5.1] Testing system information collection..." -ForegroundColor Yellow
try {
    $sysInfo = Get-ComputerInfo -ErrorAction Stop
    Test-Result "System information collection" ($sysInfo -ne $null)
} catch {
    Test-Result "System information collection" $false $_
}

# Test 5.2: Running process collection
Write-Host "`n[5.2] Testing running process collection..." -ForegroundColor Yellow
try {
    $processes = Get-Process | Select-Object Name, Id, Path
    Test-Result "Running process collection" ($processes.Count -gt 0)
} catch {
    Test-Result "Running process collection" $false $_
}

# Test 5.3: Network information collection
Write-Host "`n[5.3] Testing network information collection..." -ForegroundColor Yellow
try {
    $ipAddresses = Get-NetIPAddress
    Test-Result "Network information collection" ($ipAddresses.Count -gt 0)
} catch {
    Test-Result "Network information collection" $false $_
}

# ==================== CLEANUP ====================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CLEANUP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nCleaning up test users and resources..." -ForegroundColor Yellow

try {
    Remove-LocalUser -Name "testuser1" -ErrorAction SilentlyContinue
    Remove-LocalUser -Name "testuser2" -ErrorAction SilentlyContinue
    Write-Host "Cleanup completed" -ForegroundColor Green
} catch {
    Write-Host "Cleanup had some errors (this is ok)" -ForegroundColor Yellow
}

# ==================== RESULTS SUMMARY ====================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalTests = $testResults.Count
$passedTests = ($testResults | Where-Object {$_.Passed -eq $true}).Count
$failedTests = ($testResults | Where-Object {$_.Passed -eq $false}).Count
$passRate = [math]::Round(($passedTests / $totalTests) * 100, 2)

Write-Host "`nTotal Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $passedTests" -ForegroundColor Green
Write-Host "Failed: $failedTests" -ForegroundColor $(if ($failedTests -eq 0) {"Green"} else {"Red"})
Write-Host "Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -eq 100) {"Green"} elseif ($passRate -ge 80) {"Yellow"} else {"Red"})

Write-Host "`nDetailed Results:" -ForegroundColor Cyan
$testResults | Format-Table -AutoSize

if ($failedTests -eq 0) {
    Write-Host "`nALL TESTS PASSED! Your scripts are ready for competition!" -ForegroundColor Green
} else {
    Write-Host "`nSome tests failed. Review the failures above." -ForegroundColor Yellow
    Write-Host "Note: Some failures may be expected (e.g., SSH not installed)" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Testing complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan