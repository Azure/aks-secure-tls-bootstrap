# PowerShell script to install aks-secure-tls-bootstrap-client on AKS Windows nodes
# This script can be used to install an arbitrary version of aks-secure-tls-bootstrap-client
# on a running AKS Windows node for development/testing.

# download and usage:
# 1. Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/aks-secure-tls-bootstrap/refs/heads/main/client/hack/windows/install.ps1" -OutFile "install-aks-secure-tls-bootstrap-client.ps1"
# 2. Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
# 3. .\install-aks-secure-tls-bootstrap-client.ps1 -Version <version> -StorageAccountName <storage-account-name>

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName
)

Write-Host "Downloading aks-secure-tls-bootstrap-client version $Version from storage account $StorageAccountName"

$downloadUrl = "https://$StorageAccountName.z22.web.core.windows.net/client/windows/amd64/$Version"
$archivePath = "windows-amd64.zip"

Write-Host "Downloading from: $downloadUrl"
Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing

$tempDir = "client"
if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

Write-Host "Extracting archive to $tempDir"
Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force

$installPath = "C:\k"
$binaryPath = "$installPath\aks-secure-tls-bootstrap-client.exe"

if (Test-Path $binaryPath) {
    Write-Host "Removing existing binary: $binaryPath"
    Remove-Item $binaryPath -Force
}

$sourceBinary = Get-ChildItem -Path $tempDir -Filter "aks-secure-tls-bootstrap-client.exe" -Recurse | Select-Object -First 1

Write-Host "Installing binary to: $binaryPath"
Move-Item $sourceBinary.FullName $binaryPath -Force

Write-Host "Cleaning up temporary files"
Remove-Item $tempDir -Recurse -Force
Remove-Item $archivePath -Force

Get-Item $binaryPath
