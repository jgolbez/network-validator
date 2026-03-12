# PowerShell script to authenticate with CML and start a lab
# Usage: .\start_cml_lab.ps1 -CMLUrl <url> -Username <user> -Password <pass> -LabId <id>

param(
    [Parameter(Mandatory=$true)]
    [string]$CMLUrl,

    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$Password,

    [Parameter(Mandatory=$true)]
    [string]$LabId,

    [string]$LogFile = "start_lab.log"
)

# Function to log messages
function Log-Message {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - [CML] $Message" | Add-Content $LogFile
}

# Disable SSL certificate validation (for demo/test environments)
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class ServerCertificateValidationCallback
{
    public static void Ignore()
    {
        if(ServicePointManager.ServerCertificateValidationCallback == null)
        {
            ServicePointManager.ServerCertificateValidationCallback +=
                delegate (
                    Object obj,
                    X509Certificate certificate,
                    X509Chain chain,
                    SslPolicyErrors errors
                ) {
                    return true;
                };
        }
    }
}
"@
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Ignore()

try {
    Write-Host "Authenticating with CML..." -ForegroundColor Cyan
    Log-Message "Starting authentication to $CMLUrl"

    # Authenticate and get token
    $authUrl = "$CMLUrl/api/v0/authenticate"
    Log-Message "Auth URL: $authUrl"

    $authBody = @{
        username = $Username
        password = $Password
    } | ConvertTo-Json

    Log-Message "Sending authentication request"
    $authResponse = Invoke-RestMethod -Uri $authUrl `
        -Method POST `
        -Headers @{
            "Content-Type" = "application/json"
            "X-CML-CLIENT" = "PowerShell"
        } `
        -Body $authBody

    $token = $authResponse
    Log-Message "Authentication successful, token received (length: $($token.Length))"
    Write-Host "Authentication successful" -ForegroundColor Green

    # Start the lab
    Write-Host "Starting lab $LabId..." -ForegroundColor Cyan
    Log-Message "Starting lab $LabId"

    $startUrl = "$CMLUrl/api/v0/labs/$LabId/start"
    Log-Message "Start URL: $startUrl"

    Log-Message "Sending PUT request to start lab"
    $startResponse = Invoke-RestMethod -Uri $startUrl `
        -Method PUT `
        -Headers @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $token"
            "X-CML-CLIENT" = "PowerShell"
            "accept" = "application/json"
        }

    Log-Message "Lab start request completed: $($startResponse | ConvertTo-Json)"
    Write-Host "Lab started successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "Lab is starting up. Devices will be available shortly." -ForegroundColor Cyan

} catch {
    $errorMsg = $_.Exception.Message
    Log-Message "ERROR: $errorMsg"
    Log-Message "Exception details: $($_ | ConvertTo-Json)"
    Write-Host "Error: $errorMsg" -ForegroundColor Red
    exit 1
}
