# InstallModule.ps1
# Installation script for Conditional Access Analyzer
# For use with Azure Cloud Shell and PowerShell 7+ on any platform

Write-Host "Installing Conditional Access Analyzer..." -ForegroundColor Cyan

# Detect if we're running in Linux/macOS or Windows
$lookWindows = $PSVersionTable.Platform -eq 'Win32NT' -or (-not (Get-Command -Name 'uname' -ErrorAction SilentlyContinue))
$pathSeparator = if ($lookWindows) { '\' } else { '/' }

# Set temporary directory for download - Use user's home directory in Cloud Shell
$tempDir = Join-Path -Path $HOME -ChildPath "temp/CAAnalyzer" -ErrorAction Stop
$moduleDir = Join-Path -Path $HOME -ChildPath "CAAnalyzer" -ErrorAction Stop

# Create directories if they don't exist
if (-not (Test-Path -Path $tempDir)) {
    try {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        Write-Host "Created temporary directory: $tempDir" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not create temp directory. Using module directory directly."
        $tempDir = $moduleDir
    }
}

if (-not (Test-Path -Path $moduleDir)) {
    try {
        New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
        Write-Host "Created module directory: $moduleDir" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create module directory: $_"
        return $false
    }
}

# GitHub repository information
$repoOwner = "DataGuys"
$repoName = "ConditionalAccessAnalyzer" # Correct repository name
$branch = "refs/heads/main"
$baseUrl = "https://raw.githubusercontent.com/$repoOwner/$repoName/$branch"

# Check if running in Azure Cloud Shell or Linux
$isCloudShell = $env:ACC_CLOUD -eq 'Azure' -or (Test-Path -Path "/home")
$envType = if ($isCloudShell) { 
    if ($lookWindows) { "Cloud Shell (Windows)" } else { "Cloud Shell (Linux)" } 
} else { 
    if ($lookWindows) { "PowerShell (Windows)" } else { "PowerShell (Linux/macOS)" }
}
Write-Host "Detected environment: $envType" -ForegroundColor Yellow

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
    $savePath = Join-Path -Path $moduleDir -ChildPath $TargetPath -ErrorAction Stop
    
    # Normalize path to use correct separators
    $savePath = $savePath.Replace('\', $pathSeparator)
    
    # Create directory if it doesn't exist
    $saveDir = Split-Path -Path $savePath -Parent
    if (-not (Test-Path -Path $saveDir)) {
        try {
            New-Item -Path $saveDir -ItemType Directory -Force | Out-Null
        }
        catch {
            Write-Error "Failed to create directory $saveDir. Error: $_"
            return $false
        }
    }
    
    try {
        Write-Verbose "Downloading $fileUrl to $savePath"
        Invoke-WebRequest -Uri $fileUrl -OutFile $savePath -UseBasicParsing
        if (Test-Path -Path $savePath) {
            Write-Verbose "Downloaded successfully: $RelativePath"
            
            # Fix Windows-style path separators in PS1 files if we're on Linux
            if (-not $lookWindows -and $savePath.EndsWith('.ps1')) {
                $content = Get-Content -Path $savePath -Raw
                if ($content -like '*\*') {
                    $content = $content.Replace('\', '/')
                    Set-Content -Path $savePath -Value $content -Force
                    Write-Verbose "Fixed path separators in $savePath"
                }
                
                # Fix other common issues in PowerShell files for Linux
                $content = Get-Content -Path $savePath -Raw
                
                # Fix variable references with colons (common in error messages)
                if ($content -like '*$_*') {
                    $content = $content.Replace('$_', '${_}')
                    Set-Content -Path $savePath -Value $content -Force
                    Write-Verbose "Fixed variable references in $savePath"
                }
            }
            
            return $true
        } else {
            Write-Error "File downloaded but not found on disk: $savePath"
            return $false
        }
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
$downloadedFiles = 0
$totalFiles = $essentialFiles.Count

Write-Host "Downloading module files..." -ForegroundColor Yellow
foreach ($file in $essentialFiles) {
    $success = Download-RepoFile -RelativePath $file.Path -TargetPath $file.Target
    if ($success) {
        $downloadedFiles++
        Write-Progress -Activity "Downloading Module Files" -Status "$downloadedFiles of $totalFiles complete" -PercentComplete (($downloadedFiles / $totalFiles) * 100)
    } else {
        $downloadSuccess = $false
    }
}
Write-Progress -Activity "Downloading Module Files" -Completed

# Fix common PowerShell syntax issues in all module files
Write-Host "Applying PowerShell compatibility fixes..." -ForegroundColor Yellow

# Fix hashtable syntax issues in BenchmarkAnalyzer.ps1
$benchmarkFile = Join-Path -Path $moduleDir -ChildPath "Templates/BenchmarkAnalyzer.ps1"
if (Test-Path $benchmarkFile) {
    $content = Get-Content -Path $benchmarkFile -Raw
    
    # Fix hashtable syntax (issue with assignment operators in hashtables)
    $content = $content -replace "'NIST' = @\(", "'NIST' = @("
    $content = $content -replace "'CIS' = @\(", "'CIS' = @("
    $content = $content -replace "'MCRA' = @\(", "'MCRA' = @("
    $content = $content -replace "'ISO27001' = @\(", "'ISO27001' = @("
    $content = $content -replace "'PCI' = @\(", "'PCI' = @("
    $content = $content -replace "'HIPAA' = @\(", "'HIPAA' = @("
    
    # Write the fixed content back
    Set-Content -Path $benchmarkFile -Value $content -Force
    Write-Host "  ✓ Fixed BenchmarkAnalyzer.ps1 hashtable syntax" -ForegroundColor Green
}

# Fix ComplianceScore.ps1 issues
$scoreFile = Join-Path -Path $moduleDir -ChildPath "Classes/ComplianceScore.ps1"
if (Test-Path $scoreFile) {
    $content = Get-Content -Path $scoreFile -Raw
    
    # Fix method return issues
    $content = $content -replace "\[string\] GetColor\(\) \{", "[string] GetColor() { return "
    $content = $content -replace "\[string\] GetTextColor\(\) \{", "[string] GetTextColor() { return "
    
    # Write the fixed content back
    Set-Content -Path $scoreFile -Value $content -Force
    Write-Host "  ✓ Fixed ComplianceScore.ps1 method return issues" -ForegroundColor Green
}

# Fix Analysis.ps1 issues
$analysisFile = Join-Path -Path $moduleDir -ChildPath "Public/Analysis.ps1"
if (Test-Path $analysisFile) {
    $content = Get-Content -Path $analysisFile -Raw
    
    # Fix variable expansion in string issues
    $content = $content -replace "with ID \$Id \$_", "with ID `${Id}: `${_}"
    
    # Write the fixed content back
    Set-Content -Path $analysisFile -Value $content -Force
    Write-Host "  ✓ Fixed Analysis.ps1 variable expansion issues" -ForegroundColor Green
}

# Fix Remediation.ps1 issues
$remediationFile = Join-Path -Path $moduleDir -ChildPath "Public/Remediation.ps1"
if (Test-Path $remediationFile) {
    $content = Get-Content -Path $remediationFile -Raw
    
    # Fix variable expansion in string issues
    $content = $content -replace "\$policyBaseName", "`${policyBaseName}:"
    
    # Write the fixed content back
    Set-Content -Path $remediationFile -Value $content -Force
    Write-Host "  ✓ Fixed Remediation.ps1 variable expansion issues" -ForegroundColor Green
}

if (-not $downloadSuccess) {
    Write-Error "Failed to download some module files. The module might not work correctly."
}
else {
    Write-Host "All module files downloaded successfully." -ForegroundColor Green
}

# Import the module
try {
    $modulePath = Join-Path -Path $moduleDir -ChildPath "ConditionalAccessAnalyzer.psd1"
    Write-Host "Importing module from: $modulePath" -ForegroundColor Yellow
    Import-Module $modulePath -Force -ErrorAction Stop
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
    
    return $true
}
catch {
    Write-Error "Failed to import Conditional Access Analyzer module. Error: $_"
    Write-Host "More details:"
    Write-Host $_.ScriptStackTrace
    return $false
}
