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
    [string]$LabId
)

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

    # Authenticate and get token
    $authUrl = "$CMLUrl/api/v0/authenticate"
    $authBody = @{
        username = $Username
        password = $Password
    } | ConvertTo-Json

    $authResponse = Invoke-RestMethod -Uri $authUrl `
        -Method POST `
        -Headers @{
            "Content-Type" = "application/json"
            "X-CML-CLIENT" = "PowerShell"
        } `
        -Body $authBody

    $token = $authResponse
    Write-Host "✓ Authentication successful" -ForegroundColor Green

    # Start the lab
    Write-Host "Starting lab $LabId..." -ForegroundColor Cyan

    $startUrl = "$CMLUrl/api/v0/labs/$LabId/start"

    $startResponse = Invoke-RestMethod -Uri $startUrl `
        -Method PUT `
        -Headers @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $token"
            "X-CML-CLIENT" = "PowerShell"
            "accept" = "application/json"
        }

    Write-Host "✓ Lab started successfully" -ForegroundColor Green
    Write-Host "`nLab is starting up. Devices will be available shortly." -ForegroundColor Cyan

} catch {
    Write-Host "✗ Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
