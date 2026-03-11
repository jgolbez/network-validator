# PowerShell script to run validator and open results in Chrome
# This script runs silently and automatically opens the attendee report

# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configDir = Join-Path $scriptPath "config\network1"

# Try to find venv - check for both .venv and venv folders
$venvDir = $null
if (Test-Path (Join-Path $scriptPath ".venv")) {
    $venvDir = Join-Path $scriptPath ".venv"
} elseif (Test-Path (Join-Path $scriptPath "venv")) {
    $venvDir = Join-Path $scriptPath "venv"
}

$venvActivate = Join-Path $venvDir "Scripts\Activate.ps1"
$pythonPath = Join-Path $venvDir "Scripts\python.exe"

# Change to the script directory
Push-Location $scriptPath

try {
    # Verify virtual environment exists (silently fail if not found)
    if ($null -eq $venvDir) {
        exit 1
    }

    # Activate the virtual environment silently
    & "$venvActivate" 2>$null

    # Show validation in progress message (spawns in separate process, doesn't block)
    $msgScriptPath = Join-Path $scriptPath "show_validation_message.vbs"
    if (Test-Path $msgScriptPath) {
        Start-Process cscript.exe -ArgumentList $msgScriptPath -WindowStyle Hidden 2>$null
        Start-Sleep -Milliseconds 300
    }

    # Run the validator silently
    python validator.py $configDir 2>$null

    # Get the attendee report path
    $reportPath = Join-Path $scriptPath "network1_attendee_report.html"

    # Check if the report was generated and open in browser
    if (Test-Path $reportPath) {
        # Open in Chrome (check both 64-bit and 32-bit installations)
        $chromePath64 = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        $chromePath32 = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

        if (Test-Path $chromePath64) {
            Start-Process $chromePath64 $reportPath -WindowStyle Hidden
        } elseif (Test-Path $chromePath32) {
            Start-Process $chromePath32 $reportPath -WindowStyle Hidden
        } else {
            # Fallback to default browser if Chrome not found
            Start-Process $reportPath -WindowStyle Hidden
        }
    }
} catch {
    # Silently fail - no output
} finally {
    Pop-Location
}
