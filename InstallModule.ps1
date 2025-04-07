# InstallModule.ps1
# Installation script for Conditional Access Analyzer
# For use with Azure Cloud Shell

Write-Host "Installing Conditional Access Analyzer..." -ForegroundColor Cyan

# Set temporary directory for download
$tempDir = "$env:TEMP\CAAnalyzer"
$moduleDir = "$HOME\CAAnalyzer"

# Create directories if they don't exist
if (-not (Test-Path -Path $tempDir)) {
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -Path $moduleDir)) {
    New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
}

# GitHub repository information
$repoOwner = "DataGuys"
$repoName = "ConditionalAccessAnalyzer"  # Updated the repository name
$branch = "refs/heads/main"  # Updated the branch reference format
$baseUrl = "https://raw.githubusercontent.com/$repoOwner/$repoName/$branch"

# Check if running in Azure Cloud Shell
$isCloudShell = $env:ACC_CLOUD -eq 'Azure'
Write-Host "Detected environment: $(if ($isCloudShell) { "Azure Cloud Shell" } else { "PowerShell" })"

# Check for required modules
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.DeviceManagement"
)

$missingModules = @()
foreach ($module in $requiredModules) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "Installing required modules: $($missingModules -join ', ')" -ForegroundColor Yellow
    foreach ($module in $missingModules) {
        try {
            Install-Module -Name $module -Force -Scope CurrentUser -AllowClobber
            Write-Host "  ✓ $module installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install $module. Error: $_"
            Write-Host "  × $module installation failed" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "All required modules are already installed." -ForegroundColor Green
}

# Function to download files
function Download-RepoFile {
    param (
        [string]$RelativePath,
        [string]$TargetPath
    )
    
    $fileUrl = "$baseUrl/$RelativePath"
    $savePath = Join-Path -Path $moduleDir -ChildPath $TargetPath
    
    # Create directory if it doesn't exist
    $saveDir = Split-Path -Path $savePath -Parent
    if (-not (Test-Path -Path $saveDir)) {
        New-Item -Path $saveDir -ItemType Directory -Force | Out-Null
    }
    
    try {
        Invoke-WebRequest -Uri $fileUrl -OutFile $savePath -UseBasicParsing
        return $true
    }
    catch {
        Write-Error "Failed to download $fileUrl. Error: $_"
        return $false
    }
}

# List of essential files to download
$essentialFiles = @(
    @{ Path = "ConditionalAccessAnalyzer.psd1"; Target = "ConditionalAccessAnalyzer.psd1" },
    @{ Path = "ConditionalAccessAnalyzer.psm1"; Target = "ConditionalAccessAnalyzer.psm1" },
    @{ Path = "Classes/ComplianceScore.ps1"; Target = "Classes/ComplianceScore.ps1" },
    @{ Path = "Classes/PolicyResult.ps1"; Target = "Classes/PolicyResult.ps1" },
    @{ Path = "Classes/ReportData.ps1"; Target = "Classes/ReportData.ps1" },
    @{ Path = "Private/DataProcessing.ps1"; Target = "Private/DataProcessing.ps1" },
    @{ Path = "Private/GraphHelpers.ps1"; Target = "Private/GraphHelpers.ps1" },
    @{ Path = "Private/Logging.ps1"; Target = "Private/Logging.ps1" },
    @{ Path = "Private/PolicyEvaluation.ps1"; Target = "Private/PolicyEvaluation.ps1" },
    @{ Path = "Public/Analysis.ps1"; Target = "Public/Analysis.ps1" },
    @{ Path = "Public/Connect.ps1"; Target = "Public/Connect.ps1" },
    @{ Path = "Public/Remediation.ps1"; Target = "Public/Remediation.ps1" },
    @{ Path = "Public/Reporting.ps1"; Target = "Public/Reporting.ps1" },
    @{ Path = "Templates/BenchmarkAnalyzer.ps1"; Target = "Templates/BenchmarkAnalyzer.ps1" },
    @{ Path = "Templates/CABestPracticePolicy.ps1"; Target = "Templates/CABestPracticePolicy.ps1" },
    @{ Path = "Templates/CIS.ps1"; Target = "Templates/CIS.ps1" },
    @{ Path = "Templates/NIST.ps1"; Target = "Templates/NIST.ps1" },
    @{ Path = "Templates/ZeroTrust.ps1"; Target = "Templates/ZeroTrust.ps1" }
)

# Download files
$downloadSuccess = $true
Write-Host "Downloading module files..." -ForegroundColor Yellow
foreach ($file in $essentialFiles) {
    $success = Download-RepoFile -RelativePath $file.Path -TargetPath $file.Target
    if (-not $success) {
        $downloadSuccess = $false
    }
}

if (-not $downloadSuccess) {
    Write-Error "Failed to download some module files. The module might not work correctly."
}
else {
    Write-Host "All module files downloaded successfully." -ForegroundColor Green
}

# Import the module
try {
    Import-Module "$moduleDir\ConditionalAccessAnalyzer.psd1" -Force
    Write-Host "Conditional Access Analyzer module imported successfully." -ForegroundColor Green
    
    # Display help information
    Write-Host "`nQuick Start Guide:" -ForegroundColor Cyan
    Write-Host "1. Connect to Microsoft Graph with required permissions:"
    Write-Host "   Connect-CAAnalyzer" -ForegroundColor Yellow
    Write-Host "2. Run comprehensive compliance check:"
    Write-Host "   Invoke-CAComplianceCheck" -ForegroundColor Yellow
    Write-Host "3. Generate interactive dashboard:"
    Write-Host "   Export-CAComplianceDashboard -IncludeBenchmarks -OpenDashboard" -ForegroundColor Yellow
    Write-Host "`nFor more information, use: Get-Command -Module ConditionalAccessAnalyzer | Get-Help" -ForegroundColor Cyan
    
    # Connect to Microsoft Graph (optional)
    $connectNow = Read-Host "Do you want to connect to Microsoft Graph now? (Y/N)"
    if ($connectNow.ToUpper() -eq "Y") {
        Connect-CAAnalyzer
    }
    
    # Return success
    return $true
}
catch {
    Write-Error "Failed to import Conditional Access Analyzer module. Error: $_"
    # Return failure
    return $false
}
