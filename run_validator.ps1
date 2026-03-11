# PowerShell script to run validator and open results in Chrome
# This script runs silently and automatically opens the attendee report

# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configDir = Join-Path $scriptPath "config\network1"
$venvPath = Join-Path $scriptPath ".venv\Scripts\python.exe"

# Change to the script directory
Push-Location $scriptPath

try {
    # Verify Python exists
    if (-not (Test-Path $venvPath)) {
        Write-Host "Error: Python executable not found at: $venvPath" -ForegroundColor Red
        Write-Host "Please ensure .venv is properly initialized." -ForegroundColor Yellow
        Write-Host "Run: python -m venv .venv" -ForegroundColor Yellow
        exit 1
    }

    # Run the validator (Python will execute silently if there are no errors)
    Write-Host "Running validator..." -ForegroundColor Green
    & "$venvPath" validator.py $configDir

    # Get the attendee report path
    $reportPath = Join-Path $scriptPath "network1_attendee_report.html"

    # Check if the report was generated
    if (Test-Path $reportPath) {
        Write-Host "Opening report in Chrome..." -ForegroundColor Green

        # Open in Chrome (check both 64-bit and 32-bit installations)
        $chromePath64 = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        $chromePath32 = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

        if (Test-Path $chromePath64) {
            Start-Process $chromePath64 $reportPath
        } elseif (Test-Path $chromePath32) {
            Start-Process $chromePath32 $reportPath
        } else {
            # Fallback to default browser if Chrome not found
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
