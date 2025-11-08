# Test Harness for defender.ps1
# This script creates controlled threats and verifies detection

param(
    [switch]$SkipCleanup,
    [switch]$Verbose
)

# Require Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run as Administrator!"
    Exit
}

$ErrorActionPreference = "SilentlyContinue"
$testResults = @()
$hostname = $env:COMPUTERNAME

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DEFENDER.PS1 TEST HARNESS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "This script will create controlled threats" -ForegroundColor Yellow
Write-Host "and verify defender.ps1 detects them." -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

function Test-Result {
    param($TestName, $Expected, $Actual, $Pass)
    
    $result = [PSCustomObject]@{
        Test = $TestName
        Expected = $Expected
        Actual = $Actual
        Pass = $Pass
        Timestamp = Get-Date -Format 'HH:mm:ss'
    }
    
    $script:testResults += $result
    
    $color = if ($Pass) { "Green" } else { "Red" }
    $status = if ($Pass) { "✓ PASS" } else { "✗ FAIL" }
    
    Write-Host "[$status] $TestName" -ForegroundColor $color
    if ($Verbose) {
        Write-Host "  Expected: $Expected" -ForegroundColor Gray
        Write-Host "  Actual: $Actual" -ForegroundColor Gray
    }
}

function Wait-ForUser {
    param($Message)
    Write-Host "`n$Message" -ForegroundColor Yellow
    Write-Host "Press Enter to continue..." -ForegroundColor Cyan
    Read-Host
}

# ======================
# PRE-TEST SETUP
# ======================
Write-Host "[SETUP] Preparing test environment..." -ForegroundColor Cyan

# Check if defender.ps1 exists
$defenderPath = ".\defender.ps1"
if (-not (Test-Path $defenderPath)) {
    Write-Host "ERROR: defender.ps1 not found in current directory!" -ForegroundColor Red
    Write-Host "Please run this test script from the same directory as defender.ps1" -ForegroundColor Red
    exit 1
}

# Store original state for cleanup
$originalUsers = Get-LocalUser | Select-Object -ExpandProperty Name
$originalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$originalTasks = Get-ScheduledTask | Select-Object -ExpandProperty TaskName
$originalFirewallState = Get-NetFirewallProfile -Name Domain | Select-Object -ExpandProperty Enabled

Write-Host "[SETUP] Baseline captured" -ForegroundColor Green

# ======================
# TEST 1: BASELINE CREATION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 1: Baseline Creation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Delete existing baseline if present
if (Test-Path "C:\DefenderState.json") {
    Remove-Item "C:\DefenderState.json" -Force
    Write-Host "[SETUP] Removed existing baseline" -ForegroundColor Yellow
}

Write-Host "[ACTION] Running defender.ps1 to create baseline..." -ForegroundColor Yellow
& $defenderPath -Action ReportOnly | Out-Null

Start-Sleep -Seconds 3

# Verify baseline was created
$baselineExists = Test-Path "C:\DefenderState.json"
Test-Result -TestName "Baseline File Created" -Expected "File exists" -Actual $(if($baselineExists){"Exists"}else{"Missing"}) -Pass $baselineExists

if ($baselineExists) {
    $baseline = Get-Content "C:\DefenderState.json" -Raw | ConvertFrom-Json
    $hasTimestamp = $null -ne $baseline.Timestamp
    $hasHostname = $baseline.Hostname -eq $hostname
    
    Test-Result -TestName "Baseline Has Timestamp" -Expected "Timestamp present" -Actual $(if($hasTimestamp){"Present"}else{"Missing"}) -Pass $hasTimestamp
    Test-Result -TestName "Baseline Has Correct Hostname" -Expected $hostname -Actual $baseline.Hostname -Pass $hasHostname
}

Write-Host "[INFO] Baseline established. Now testing detection capabilities..." -ForegroundColor Green

# ======================
# TEST 2: USER DETECTION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 2: New User Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$testUserName = "TestThreatUser_$(Get-Random -Maximum 9999)"
Write-Host "[ACTION] Creating test user: $testUserName" -ForegroundColor Yellow

try {
    New-LocalUser -Name $testUserName -Password (ConvertTo-SecureString "TestPass123!@#" -AsPlainText -Force) -Description "Test threat user" -ErrorAction Stop | Out-Null
    Write-Host "[SUCCESS] Test user created" -ForegroundColor Green
    
    # Run defender
    Write-Host "[ACTION] Running defender.ps1..." -ForegroundColor Yellow
    $defenderOutput = & $defenderPath -Action ReportOnly 2>&1 | Out-String
    
    # Check if defender detected the new user
    $detectedNewUser = $defenderOutput -match "NEW USER.*$testUserName"
    Test-Result -TestName "New User Detection" -Expected "Detected new user" -Actual $(if($detectedNewUser){"Detected"}else{"Not detected"}) -Pass $detectedNewUser
    
    # Verify user still exists (ReportOnly shouldn't remove it)
    $userStillExists = Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
    Test-Result -TestName "User Not Removed (ReportOnly)" -Expected "User still exists" -Actual $(if($userStillExists){"Exists"}else{"Removed"}) -Pass ($null -ne $userStillExists)
    
} catch {
    Test-Result -TestName "New User Detection" -Expected "Test executed" -Actual "Error: $_" -Pass $false
}

# ======================
# TEST 3: ADMINISTRATOR DETECTION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 3: Administrator Change Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue) {
    Write-Host "[ACTION] Adding $testUserName to Administrators group" -ForegroundColor Yellow
    
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $testUserName -ErrorAction Stop
        Write-Host "[SUCCESS] User added to Administrators" -ForegroundColor Green
        
        # Run defender
        Write-Host "[ACTION] Running defender.ps1..." -ForegroundColor Yellow
        $defenderOutput = & $defenderPath -Action ReportOnly 2>&1 | Out-String
        
        # Check if defender detected the new admin
        $detectedNewAdmin = $defenderOutput -match "NEW ADMINISTRATOR.*$testUserName"
        Test-Result -TestName "New Administrator Detection" -Expected "Detected new admin" -Actual $(if($detectedNewAdmin){"Detected"}else{"Not detected"}) -Pass $detectedNewAdmin
        
    } catch {
        Test-Result -TestName "New Administrator Detection" -Expected "Test executed" -Actual "Error: $_" -Pass $false
    }
} else {
    Test-Result -TestName "New Administrator Detection" -Expected "Test executed" -Actual "Previous test failed" -Pass $false
}

# ======================
# TEST 4: SCHEDULED TASK DETECTION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 4: Scheduled Task Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$testTaskName = "SuspiciousTask_$(Get-Random -Maximum 9999)"
Write-Host "[ACTION] Creating test scheduled task: $testTaskName" -ForegroundColor Yellow

try {
    $action = New-ScheduledTaskAction -Execute "notepad.exe"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $testTaskName -Action $action -Trigger $trigger -ErrorAction Stop | Out-Null
    Write-Host "[SUCCESS] Test task created" -ForegroundColor Green
    
    # Note: Defender doesn't directly track individual tasks, but we can verify the state is captured
    $taskExists = Get-ScheduledTask -TaskName $testTaskName -ErrorAction SilentlyContinue
    Test-Result -TestName "Scheduled Task Created" -Expected "Task exists" -Actual $(if($taskExists){"Exists"}else{"Missing"}) -Pass ($null -ne $taskExists)
    
} catch {
    Test-Result -TestName "Scheduled Task Created" -Expected "Task created" -Actual "Error: $_" -Pass $false
}

# ======================
# TEST 5: FIREWALL CHANGE DETECTION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 5: Firewall Change Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "[ACTION] Temporarily disabling Domain firewall profile" -ForegroundColor Yellow

try {
    Set-NetFirewallProfile -Profile Domain -Enabled False -ErrorAction Stop
    Write-Host "[SUCCESS] Firewall profile disabled" -ForegroundColor Green
    
    Start-Sleep -Seconds 2
    
    # Run defender
    Write-Host "[ACTION] Running defender.ps1..." -ForegroundColor Yellow
    $defenderOutput = & $defenderPath -Action ReportOnly 2>&1 | Out-String
    
    # Check if defender detected the firewall change
    $detectedFirewallChange = $defenderOutput -match "FIREWALL.*DISABLED.*Domain"
    Test-Result -TestName "Firewall Disable Detection" -Expected "Detected firewall change" -Actual $(if($detectedFirewallChange){"Detected"}else{"Not detected"}) -Pass $detectedFirewallChange
    
    # Re-enable immediately
    Write-Host "[SAFETY] Re-enabling firewall..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain -Enabled True -ErrorAction Stop
    Write-Host "[SUCCESS] Firewall re-enabled" -ForegroundColor Green
    
} catch {
    # Make sure to re-enable even if test fails
    Set-NetFirewallProfile -Profile Domain -Enabled True -ErrorAction SilentlyContinue
    Test-Result -TestName "Firewall Disable Detection" -Expected "Test executed" -Actual "Error: $_" -Pass $false
}

# ======================
# TEST 6: SERVICE CHANGE DETECTION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 6: Service Change Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Use Windows Update service as it's safe to stop temporarily
$testService = "wuauserv"
Write-Host "[ACTION] Stopping Windows Update service temporarily" -ForegroundColor Yellow

try {
    $originalServiceState = (Get-Service $testService).Status
    
    if ($originalServiceState -eq "Running") {
        Stop-Service $testService -Force -ErrorAction Stop
        Write-Host "[SUCCESS] Service stopped" -ForegroundColor Green
        
        Start-Sleep -Seconds 2
        
        # Run defender
        Write-Host "[ACTION] Running defender.ps1..." -ForegroundColor Yellow
        $defenderOutput = & $defenderPath -Action ReportOnly 2>&1 | Out-String
        
        # Check if defender detected the service change
        $detectedServiceChange = $defenderOutput -match "SERVICE.*CHANGED.*wuauserv"
        Test-Result -TestName "Service Status Change Detection" -Expected "Detected service change" -Actual $(if($detectedServiceChange){"Detected"}else{"Not detected"}) -Pass $detectedServiceChange
        
        # Restart the service
        Write-Host "[SAFETY] Restarting Windows Update service..." -ForegroundColor Yellow
        Start-Service $testService -ErrorAction SilentlyContinue
    } else {
        Write-Host "[SKIP] Windows Update service not running, skipping test" -ForegroundColor Yellow
        Test-Result -TestName "Service Status Change Detection" -Expected "Test executed" -Actual "Service not running" -Pass $null
    }
    
} catch {
    # Make sure to restart service
    Start-Service $testService -ErrorAction SilentlyContinue
    Test-Result -TestName "Service Status Change Detection" -Expected "Test executed" -Actual "Error: $_" -Pass $false
}

# ======================
# TEST 7: ANOMALOUS PROCESS DETECTION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 7: Anomalous Process Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "[ACTION] Starting notepad.exe (will be flagged as anomalous)" -ForegroundColor Yellow

try {
    $notepad = Start-Process notepad.exe -PassThru
    Write-Host "[SUCCESS] Notepad started (PID: $($notepad.Id))" -ForegroundColor Green
    
    Start-Sleep -Seconds 2
    
    # Run defender
    Write-Host "[ACTION] Running defender.ps1..." -ForegroundColor Yellow
    $defenderOutput = & $defenderPath -Action ReportOnly 2>&1 | Out-String
    
    # Check if defender detected notepad as anomalous
    $detectedAnomalousProcess = $defenderOutput -match "ANOMALY.*notepad"
    Test-Result -TestName "Anomalous Process Detection" -Expected "Detected notepad" -Actual $(if($detectedAnomalousProcess){"Detected"}else{"Not detected"}) -Pass $detectedAnomalousProcess
    
    # Verify notepad still running (ReportOnly mode)
    $notepadStillRunning = Get-Process -Id $notepad.Id -ErrorAction SilentlyContinue
    Test-Result -TestName "Process Not Killed (ReportOnly)" -Expected "Notepad still running" -Actual $(if($notepadStillRunning){"Running"}else{"Killed"}) -Pass ($null -ne $notepadStillRunning)
    
    # Kill notepad
    Stop-Process -Id $notepad.Id -Force -ErrorAction SilentlyContinue
    
} catch {
    Test-Result -TestName "Anomalous Process Detection" -Expected "Test executed" -Actual "Error: $_" -Pass $false
}

# ======================
# TEST 8: EXTERNAL CONNECTION DETECTION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 8: External Connection Detection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "[ACTION] Creating external connection to google.com" -ForegroundColor Yellow

try {
    # Start a background job that creates an external connection
    $job = Start-Job -ScriptBlock {
        try {
            Invoke-WebRequest -Uri "http://www.google.com" -UseBasicParsing -TimeoutSec 30
        } catch {
            # Doesn't matter if it fails, we just need the connection attempt
        }
    }
    
    Start-Sleep -Seconds 3
    
    # Run defender while connection might still be active
    Write-Host "[ACTION] Running defender.ps1..." -ForegroundColor Yellow
    $defenderOutput = & $defenderPath -Action ReportOnly 2>&1 | Out-String
    
    # Check if defender detected external connections
    $detectedExternal = $defenderOutput -match "EXTERNAL CONNECTION|NEW EXTERNAL CONNECTION"
    Test-Result -TestName "External Connection Detection" -Expected "Detected external connection" -Actual $(if($detectedExternal){"Detected"}else{"Not detected or timed out"}) -Pass $detectedExternal
    
    # Clean up job
    Get-Job | Stop-Job
    Get-Job | Remove-Job
    
} catch {
    Get-Job | Stop-Job -ErrorAction SilentlyContinue
    Get-Job | Remove-Job -ErrorAction SilentlyContinue
    Test-Result -TestName "External Connection Detection" -Expected "Test executed" -Actual "Error: $_" -Pass $false
}

# ======================
# TEST 9: LOG FILE CREATION
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 9: Log File Creation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "[ACTION] Checking for log files..." -ForegroundColor Yellow

$logDir = ".\defender_logs"
$logDirExists = Test-Path $logDir
Test-Result -TestName "Log Directory Created" -Expected "Directory exists" -Actual $(if($logDirExists){"Exists"}else{"Missing"}) -Pass $logDirExists

if ($logDirExists) {
    $logFiles = Get-ChildItem $logDir -Filter "defender_*.log" | Sort-Object LastWriteTime -Descending
    $hasLogFiles = $logFiles.Count -gt 0
    Test-Result -TestName "Log Files Generated" -Expected "At least one log file" -Actual "$($logFiles.Count) files" -Pass $hasLogFiles
    
    if ($hasLogFiles) {
        $latestLog = $logFiles[0]
        $logContent = Get-Content $latestLog.FullName -Raw
        $hasContent = $logContent.Length -gt 100
        Test-Result -TestName "Log File Has Content" -Expected "Substantial content" -Actual "$($logContent.Length) bytes" -Pass $hasContent
    }
}

$alertLogExists = Test-Path "C:\Defender_Alerts.log"
Test-Result -TestName "Alert Log Created" -Expected "C:\Defender_Alerts.log exists" -Actual $(if($alertLogExists){"Exists"}else{"Missing"}) -Pass $alertLogExists

# ======================
# TEST 10: STATE PERSISTENCE
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST 10: State Persistence" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "[ACTION] Verifying state file updates..." -ForegroundColor Yellow

if (Test-Path "C:\DefenderState.json") {
    $state1 = Get-Content "C:\DefenderState.json" -Raw
    $timestamp1 = (Get-Content "C:\DefenderState.json" | ConvertFrom-Json).Timestamp
    
    Start-Sleep -Seconds 2
    
    # Run defender again
    & $defenderPath -Action ReportOnly | Out-Null
    
    Start-Sleep -Seconds 2
    
    $state2 = Get-Content "C:\DefenderState.json" -Raw
    $timestamp2 = (Get-Content "C:\DefenderState.json" | ConvertFrom-Json).Timestamp
    
    $timestampUpdated = $timestamp1 -ne $timestamp2
    Test-Result -TestName "State File Updates" -Expected "Timestamp changes" -Actual $(if($timestampUpdated){"Updated"}else{"Unchanged"}) -Pass $timestampUpdated
} else {
    Test-Result -TestName "State File Updates" -Expected "File exists" -Actual "No baseline file" -Pass $false
}

# ======================
# CLEANUP
# ======================
if (-not $SkipCleanup) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "CLEANUP" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "[CLEANUP] Removing test artifacts..." -ForegroundColor Yellow
    
    # Remove test user
    if (Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue) {
        # Remove from Administrators first
        Remove-LocalGroupMember -Group "Administrators" -Member $testUserName -ErrorAction SilentlyContinue
        Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
        Write-Host "[CLEANUP] Removed test user: $testUserName" -ForegroundColor Green
    }
    
    # Remove test scheduled task
    if (Get-ScheduledTask -TaskName $testTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[CLEANUP] Removed test task: $testTaskName" -ForegroundColor Green
    }
    
    # Ensure firewall is back to original state
    if ($originalFirewallState -ne (Get-NetFirewallProfile -Name Domain).Enabled) {
        Set-NetFirewallProfile -Profile Domain -Enabled $originalFirewallState -ErrorAction SilentlyContinue
        Write-Host "[CLEANUP] Restored firewall state" -ForegroundColor Green
    }
    
    # Kill any remaining notepad processes started by test
    Get-Process notepad -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Write-Host "[CLEANUP] Cleanup complete" -ForegroundColor Green
} else {
    Write-Host "`n[INFO] Cleanup skipped (-SkipCleanup flag)" -ForegroundColor Yellow
    Write-Host "[INFO] Manual cleanup required:" -ForegroundColor Yellow
    Write-Host "  - Remove user: $testUserName" -ForegroundColor Gray
    Write-Host "  - Remove task: $testTaskName" -ForegroundColor Gray
}

# ======================
# FINAL REPORT
# ======================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$totalTests = $testResults.Count
$passedTests = ($testResults | Where-Object {$_.Pass -eq $true}).Count
$failedTests = ($testResults | Where-Object {$_.Pass -eq $false}).Count
$skippedTests = ($testResults | Where-Object {$_.Pass -eq $null}).Count

Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $passedTests" -ForegroundColor Green
Write-Host "Failed: $failedTests" -ForegroundColor Red
if ($skippedTests -gt 0) {
    Write-Host "Skipped: $skippedTests" -ForegroundColor Yellow
}

$passRate = [math]::Round(($passedTests / $totalTests) * 100, 1)
Write-Host "`nPass Rate: $passRate%" -ForegroundColor $(if($passRate -ge 80){"Green"}elseif($passRate -ge 60){"Yellow"}else{"Red"})

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DETAILED RESULTS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

foreach ($result in $testResults) {
    $symbol = switch ($result.Pass) {
        $true { "✓" }
        $false { "✗" }
        $null { "⊘" }
    }
    $color = switch ($result.Pass) {
        $true { "Green" }
        $false { "Red" }
        $null { "Yellow" }
    }
    
    Write-Host "[$symbol] $($result.Test)" -ForegroundColor $color
    if ($Verbose -or -not $result.Pass) {
        Write-Host "    Expected: $($result.Expected)" -ForegroundColor Gray
        Write-Host "    Actual: $($result.Actual)" -ForegroundColor Gray
        Write-Host "    Time: $($result.Timestamp)" -ForegroundColor Gray
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($failedTests -eq 0) {
    Write-Host "✓ All tests passed! defender.ps1 is working correctly." -ForegroundColor Green
    Write-Host "  You're ready for competition!" -ForegroundColor Green
} elseif ($passRate -ge 80) {
    Write-Host "⚠ Most tests passed, but some issues detected." -ForegroundColor Yellow
    Write-Host "  Review failed tests and fix before competition." -ForegroundColor Yellow
} else {
    Write-Host "✗ Multiple test failures detected." -ForegroundColor Red
    Write-Host "  defender.ps1 needs troubleshooting before use." -ForegroundColor Red
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

# Export results to file
$reportFile = ".\defender_test_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$testResults | Format-Table -AutoSize | Out-File $reportFile
Write-Host "Full report saved to: $reportFile" -ForegroundColor Cyan