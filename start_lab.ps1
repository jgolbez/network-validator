# PowerShell wrapper to start CML lab from desktop shortcut
# Reads config from cml_config.yaml and starts the lab

param(
    [string]$ConfigPath = "config/cml_config.yaml"
)

# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFilePath = Join-Path $scriptPath $ConfigPath
$logFile = Join-Path $scriptPath "start_lab.log"

# Function to log messages
function Log-Message {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Add-Content $logFile
}

Log-Message "Script started"
Log-Message "Script path: $scriptPath"
Log-Message "Config path: $configFilePath"

Push-Location $scriptPath

try {
    # Check if config file exists
    if (-not (Test-Path $configFilePath)) {
        Log-Message "ERROR: Config file not found at $configFilePath"
        exit 1
    }

    Log-Message "Config file found"

    # Install and import yaml parsing if needed (simple inline YAML parser)
    # For now, we'll use a simple regex-based approach to extract values
    $configContent = Get-Content $configFilePath -Raw

    # Extract values from YAML
    $cmlUrl = [regex]::Match($configContent, 'url:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()
    $username = [regex]::Match($configContent, 'username:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()
    $password = [regex]::Match($configContent, 'password:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()
    $labId = [regex]::Match($configContent, 'lab_id:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()

    Log-Message "Config values extracted: URL=$cmlUrl, Username=$username, LabId=$labId"

    # Validate config values
    if (-not $cmlUrl -or -not $username -or -not $password -or -not $labId) {
        Log-Message "ERROR: Missing required configuration values"
        exit 1
    }

    Log-Message "Calling start_cml_lab.ps1"

    # Call the start_cml_lab script
    & ".\start_cml_lab.ps1" -CMLUrl $cmlUrl -Username $username -Password $password -LabId $labId

    Log-Message "Script completed successfully"

} catch {
    Log-Message "ERROR: $($_.Exception.Message)"
    exit 1
} finally {
    Pop-Location
}
