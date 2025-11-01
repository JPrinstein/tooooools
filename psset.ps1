# Prompt once for new password
$newPassword = Read-Host "Enter the new password for all users" -AsSecureString

# Get all local users except Administrator and Guest
$users = Get-LocalUser | Where-Object {
    $_.Name -ne "Administrator" -and $_.Name -ne "Guest"
}

Write-Host "`nChanging password for all local users..." -ForegroundColor Cyan

foreach ($user in $users) {
    try {
        Set-LocalUser -Name $user.Name -Password $newPassword
        Write-Host ("{0,-20} Password changed successfully" -f $user.Name) -ForegroundColor Green
    } catch {
        Write-Host ("{0,-20} FAILED - {1}" -f $user.Name, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host "`nDone! Password updated for all users." -ForegroundColor Cyan
