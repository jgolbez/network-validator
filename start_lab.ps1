# PowerShell wrapper to start CML lab from desktop shortcut
# Reads config from cml_config.yaml and starts the lab

param(
    [string]$ConfigPath = "config/cml_config.yaml"
)

# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFilePath = Join-Path $scriptPath $ConfigPath

Push-Location $scriptPath

try {
    # Check if config file exists
    if (-not (Test-Path $configFilePath)) {
        Write-Host "Error: Config file not found at $configFilePath" -ForegroundColor Red
        exit 1
    }

    # Install and import yaml parsing if needed (simple inline YAML parser)
    # For now, we'll use a simple regex-based approach to extract values
    $configContent = Get-Content $configFilePath -Raw

    # Extract values from YAML
    $cmlUrl = [regex]::Match($configContent, 'url:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()
    $username = [regex]::Match($configContent, 'username:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()
    $password = [regex]::Match($configContent, 'password:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()
    $labId = [regex]::Match($configContent, 'lab_id:\s*[''"]?([^''"]+)[''"]?').Groups[1].Value.Trim()

    # Validate config values
    if (-not $cmlUrl -or -not $username -or -not $password -or -not $labId) {
        Write-Host "Error: Missing required configuration values in $ConfigPath" -ForegroundColor Red
        exit 1
    }

    # Call the start_cml_lab script
    & ".\start_cml_lab.ps1" -CMLUrl $cmlUrl -Username $username -Password $password -LabId $labId

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}
