# PowerShell script to run validator and open results in Chrome
# This script runs silently and automatically opens the attendee report

# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configDir = Join-Path $scriptPath "config\network1"
$venvPath = Join-Path $scriptPath ".venv\Scripts\python.exe"

# Change to the script directory
Push-Location $scriptPath

try {
    # Run the validator (Python will execute silently if there are no errors)
    Write-Host "Running validator..." -ForegroundColor Green
    & $venvPath validator.py $configDir

    # Get the attendee report path
    $reportPath = Join-Path $scriptPath "network1_attendee_report.html"

    # Check if the report was generated
    if (Test-Path $reportPath) {
        Write-Host "Opening report in Chrome..." -ForegroundColor Green

        # Open in Chrome (will use default browser if Chrome not found)
        $chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        if (Test-Path $chromePath) {
            Start-Process $chromePath $reportPath
        } else {
            # Fallback to default browser
            Start-Process $reportPath
        }

        Write-Host "Done! Report opened successfully." -ForegroundColor Green
    } else {
        Write-Host "Error: Report file not found." -ForegroundColor Red
        Write-Host "Check that validator ran successfully." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error running validator: $_" -ForegroundColor Red
} finally {
    Pop-Location
}
