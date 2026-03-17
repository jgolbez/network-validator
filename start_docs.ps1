# PowerShell script to start MkDocs documentation server and open in Chrome
# Serves the site at http://localhost:8000

# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Try to find venv - check for both .venv and venv folders
$venvDir = $null
if (Test-Path (Join-Path $scriptPath ".venv")) {
    $venvDir = Join-Path $scriptPath ".venv"
} elseif (Test-Path (Join-Path $scriptPath "venv")) {
    $venvDir = Join-Path $scriptPath "venv"
}

$venvActivate = Join-Path $venvDir "Scripts\Activate.ps1"

Push-Location $scriptPath

try {
    # Verify virtual environment exists (silently fail if not found)
    if ($null -eq $venvDir) {
        exit 1
    }

    # Activate the virtual environment silently
    & "$venvActivate" 2>$null

    # Start MkDocs server in background
    $docsProcess = Start-Process powershell.exe `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"mkdocs serve`"" `
        -PassThru 2>$null

    # Wait for server to start
    Start-Sleep -Seconds 2

    # Open in Chrome
    $chromePath64 = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    $chromePath32 = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

    if (Test-Path $chromePath64) {
        Start-Process $chromePath64 "http://localhost:8000" -WindowStyle Hidden
    } elseif (Test-Path $chromePath32) {
        Start-Process $chromePath32 "http://localhost:8000" -WindowStyle Hidden
    } else {
        Start-Process "http://localhost:8000" -WindowStyle Hidden
    }

} catch {
    # Silently fail
} finally {
    Pop-Location
}
