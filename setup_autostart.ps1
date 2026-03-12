# PowerShell script to configure automatic lab startup via Windows Task Scheduler
# Runs the lab startup script 5 minutes after Windows boots, completely silently
# Requires Administrator privileges

# Check for admin privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as administrator'" -ForegroundColor Yellow
    exit 1
}

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$startLabScript = Join-Path $scriptPath "start_lab.ps1"

# Verify the script exists
if (-not (Test-Path $startLabScript)) {
    Write-Host "Error: start_lab.ps1 not found in $scriptPath" -ForegroundColor Red
    exit 1
}

try {
    Write-Host "Setting up automatic lab startup..." -ForegroundColor Cyan

    # Get the full path (resolve any relative paths)
    $startLabScript = Resolve-Path $startLabScript

    # Task name and description
    $taskName = "Start CML Lab"
    $taskDescription = "Automatically start CML lab 5 minutes after system boot"

    # Remove existing task if it exists
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Host "Removing existing task..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    # Create trigger: At startup, wait 5 minutes
    $trigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 5)

    # Create action: Run PowerShell silently with the script
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startLabScript`""

    # Create principal: Run as SYSTEM with highest privileges
    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    # Create settings: Run with high priority, allow task to run on battery, etc.
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -Priority 7

    # Register the task
    Register-ScheduledTask `
        -TaskName $taskName `
        -Trigger $trigger `
        -Action $action `
        -Principal $principal `
        -Settings $settings `
        -Description $taskDescription

    Write-Host "Task created successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "Task Details:" -ForegroundColor Cyan
    Write-Host "  Name: $taskName"
    Write-Host "  Trigger: At system startup (5 minute delay)"
    Write-Host "  Action: Run start_lab.ps1 silently"
    Write-Host "  User: SYSTEM (runs automatically)"
    Write-Host ""
    Write-Host "The lab will now start automatically 5 minutes after Windows boots."
    Write-Host "Monitor the CML console to confirm the lab is starting." -ForegroundColor Yellow

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
