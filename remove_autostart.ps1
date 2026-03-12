# PowerShell script to remove automatic lab startup task
# Requires Administrator privileges

# Check for admin privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as administrator'" -ForegroundColor Yellow
    exit 1
}

try {
    $taskName = "Start CML Lab"

    # Check if task exists
    if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Write-Host "Task '$taskName' not found. Nothing to remove." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Removing automatic lab startup task..." -ForegroundColor Cyan

    # Remove the task
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

    Write-Host "✓ Task removed successfully" -ForegroundColor Green
    Write-Host "The lab will no longer start automatically on boot." -ForegroundColor Cyan

} catch {
    Write-Host "✗ Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
