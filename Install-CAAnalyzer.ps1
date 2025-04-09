# Install-CAAnalyzer.ps1
# One-line installation script for Conditional Access Analyzer
# For use with Azure Cloud Shell or any PowerShell 5.1+ environment

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory = $false)]
    [switch]$PreRelease,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Write-Host "Installing Conditional Access Analyzer..." -ForegroundColor Cyan

# Check for supported PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)"
    return $false
}

# Detect if we're running in Linux/macOS or Windows
$isWindows = $PSVersionTable.Platform -eq 'Win32NT' -or (-not (Get-Command -Name 'uname' -ErrorAction SilentlyContinue))
$pathSeparator = if ($isWindows) { '\' } else { '/' }

# Check if we're in Azure Cloud Shell
$isCloudShell = $env:ACC_CLOUD -eq 'Azure' -or (Test-Path -Path "/home/azureuser" -ErrorAction SilentlyContinue)

# Set module directories for installation
$moduleDir = if ($isCloudShell) {
    Join-Path -Path $HOME -ChildPath ".local/share/powershell/Modules/ConditionalAccessAnalyzer"
} else {
    if ($isWindows) {
        Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath "WindowsPowerShell/Modules/ConditionalAccessAnalyzer"
    } else {
        Join-Path -Path $HOME -ChildPath ".local/share/powershell/Modules/ConditionalAccessAnalyzer"
    }
}

# Create temporary directory for downloads
$tempDir = Join-Path -Path $env:TEMP -ChildPath "CAAnalyzer_$(Get-Random)"
New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

# GitHub repository information
$repoOwner = "DataGuys"
$repoName = "ConditionalAccessAnalyzer"
$branch = if ($PreRelease) { "refs/heads/dev" } else { "refs/heads/main" }
$baseUrl = "https://raw.githubusercontent.com/$repoOwner/$repoName/$branch"

# Display environment information
$envType = if ($isCloudShell) { 
    if ($isWindows) { "Azure Cloud Shell (Windows)" } else { "Azure Cloud Shell (Linux)" }
} else { 
    if ($isWindows) { "PowerShell (Windows)" } else { "PowerShell (Linux/macOS)" }
}
Write-Host "Detected environment: $envType" -ForegroundColor Yellow

# Required module structure
$moduleStructure = @{
    "ConditionalAccessAnalyzer.psd1" = $null
    "ConditionalAccessAnalyzer.psm1" = $null
    "Classes" = @(
        "ComplianceScore.ps1",
        "PolicyResult.ps1",
        "ReportData.ps1"
    )
    "Private" = @(
        "DataProcessing.ps1",
        "GraphHelpers.ps1",
        "Logging.ps1",
        "PolicyEvaluation.ps1"
    )
    "Public" = @(
        "Analysis.ps1",
        "Connect.ps1",
        "Remediation.ps1",
        "Reporting.ps1"
    )
    "Templates" = @(
        "BenchmarkAnalyzer.ps1",
        "CABestPracticePolicy.ps1", 
        "CIS.ps1",
        "NIST.ps1",
        "ZeroTrust.ps1"
    )
}

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

# Function to download file from GitHub
function Get-RepoFile {
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
        Write-Verbose "Downloading $fileUrl to $savePath"
        Invoke-WebRequest -Uri $fileUrl -OutFile $savePath -UseBasicParsing
        
        # Fix path separators in PS1 files for Linux
        if (-not $isWindows -and $savePath.EndsWith('.ps1')) {
            $content = Get-Content -Path $savePath -Raw
            if ($content -like '*\*') {
                $content = $content.Replace('\', '/')
                Set-Content -Path $savePath -Value $content -Force
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to download $fileUrl. Error: $_"
        return $false
    }
}

# Create module directory
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

# Download module files
$downloadSuccess = $true
$filesDownloaded = 0
$totalFiles = 0

# Count total files
foreach ($file in $moduleStructure.Keys) {
    if ($moduleStructure[$file] -eq $null) {
        $totalFiles++
    }
    else {
        $totalFiles += $moduleStructure[$file].Count
    }
}

Write-Host "Downloading module files..." -ForegroundColor Yellow

# Download root files
foreach ($file in $moduleStructure.Keys | Where-Object { $moduleStructure[$_] -eq $null }) {
    if (Get-RepoFile -RelativePath $file -TargetPath $file) {
        $filesDownloaded++
        Write-Progress -Activity "Downloading Module Files" -Status "$filesDownloaded of $totalFiles complete" -PercentComplete (($filesDownloaded / $totalFiles) * 100)
    }
    else {
        $downloadSuccess = $false
    }
}

# Download subdirectory files
foreach ($dir in $moduleStructure.Keys | Where-Object { $moduleStructure[$_] -ne $null }) {
    foreach ($file in $moduleStructure[$dir]) {
        $relativePath = "$dir/$file"
        $targetPath = $relativePath.Replace('/', $pathSeparator)
        
        if (Get-RepoFile -RelativePath $relativePath -TargetPath $targetPath) {
            $filesDownloaded++
            Write-Progress -Activity "Downloading Module Files" -Status "$filesDownloaded of $totalFiles complete" -PercentComplete (($filesDownloaded / $totalFiles) * 100)
        }
        else {
            $downloadSuccess = $false
        }
    }
}

Write-Progress -Activity "Downloading Module Files" -Completed

# Create utility scripts
$utilityScripts = @{
    "Run-CAAnalyzer.ps1" = @"
# Run-CAAnalyzer.ps1
# Helper script to connect and run Conditional Access Analyzer

# Import the module
Import-Module ConditionalAccessAnalyzer

# Connect to Microsoft Graph
Connect-CAAnalyzer

# Run compliance check
Write-Host "Running Conditional Access compliance check..." -ForegroundColor Cyan
`$results = Invoke-CAComplianceCheck

# Display results
Write-Host "`nCompliance Score: `$(`$results.ComplianceScore)%" -ForegroundColor $(
    if (`$results.ComplianceScore -ge 90) { "Green" }
    elseif (`$results.ComplianceScore -ge 70) { "Yellow" }
    else { "Red" }
)

# Ask if user wants to generate report
`$generateReport = Read-Host "Do you want to generate a compliance report? (Y/N)"
if (`$generateReport -eq "Y") {
    `$reportPath = Join-Path -Path `$HOME -ChildPath "CA-Report-`$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-CAComplianceReport -Results `$results -ReportType HTML -Path `$reportPath
    Write-Host "Report saved to: `$reportPath" -ForegroundColor Green
}

# Ask if user wants to view benchmark comparisons
`$viewBenchmarks = Read-Host "Do you want to check compliance against security benchmarks? (Y/N)"
if (`$viewBenchmarks -eq "Y") {
    Test-CASecurityBenchmark -BenchmarkName NIST -Results `$results
    Test-CASecurityBenchmark -BenchmarkName CIS -Results `$results
}

# Ask if user wants remediation recommendations
`$needsRemediation = Read-Host "Do you want to see remediation recommendations? (Y/N)"
if (`$needsRemediation -eq "Y") {
    Invoke-CAComplianceRemediation -Results `$results -WhatIf
}
"@
    
    "Deploy-CATemplates.ps1" = @"
# Deploy-CATemplates.ps1
# Helper script to deploy Microsoft's Conditional Access templates

# Import the module
Import-Module ConditionalAccessAnalyzer

# Connect to Microsoft Graph with the required scopes
Connect-CAAnalyzer -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"

# Prompt for a prefix for the new policies
`$prefix = Read-Host "Enter a prefix for new Conditional Access policies (e.g., company code)"

# Get templates
Write-Host "Retrieving Conditional Access templates..." -ForegroundColor Cyan
`$templates = Get-MgIdentityConditionalAccessTemplate

# Display templates for selection
Write-Host "`nAvailable templates:" -ForegroundColor Cyan
for (`$i = 0; `$i -lt `$templates.Count; `$i++) {
    Write-Host "  [`$i] `$(`$templates[`$i].Description)" -ForegroundColor White
}

# Get user selection
`$selectedIndices = Read-Host "`nEnter template numbers to deploy (comma-separated, or 'all' for all templates)"

`$selectedTemplates = @()
if (`$selectedIndices -eq "all") {
    `$selectedTemplates = `$templates
}
else {
    `$indices = `$selectedIndices.Split(',') | ForEach-Object { `$_.Trim() }
    foreach (`$index in `$indices) {
        if ([int]`$index -ge 0 -and [int]`$index -lt `$templates.Count) {
            `$selectedTemplates += `$templates[[int]`$index]
        }
    }
}

if (`$selectedTemplates.Count -eq 0) {
    Write-Host "No templates selected. Exiting." -ForegroundColor Red
    return
}

# Confirm deployment
Write-Host "`nYou've selected `$(`$selectedTemplates.Count) templates to deploy:" -ForegroundColor Yellow
foreach (`$template in `$selectedTemplates) {
    Write-Host "  - `$(`$template.Description)" -ForegroundColor White
}

`$confirm = Read-Host "`nDo you want to deploy these templates? (Y/N)"
if (`$confirm -ne "Y") {
    Write-Host "Deployment cancelled." -ForegroundColor Red
    return
}

# Choose policy state
`$stateOptions = @("disabled", "enabledForReportingButNotEnforced", "enabled")
Write-Host "`nSelect a state for the new policies:" -ForegroundColor Cyan
for (`$i = 0; `$i -lt `$stateOptions.Count; `$i++) {
    Write-Host "  [`$i] `$(`$stateOptions[`$i])" -ForegroundColor White
}
`$stateChoice = Read-Host "Enter choice (default: 0 - disabled)"
`$state = if ([int]`$stateChoice -ge 0 -and [int]`$stateChoice -lt `$stateOptions.Count) {
    `$stateOptions[[int]`$stateChoice]
} else {
    "disabled"
}

# Deploy templates
Write-Host "`nDeploying templates..." -ForegroundColor Cyan
`$deployedPolicies = @()

foreach (`$template in `$selectedTemplates) {
    `$displayName = "`$prefix - `$(`$template.Description)"
    if (`$displayName.Length -gt 100) {
        `$displayName = `$displayName.Substring(0, 97) + "..."
    }
    
    `$params = @{
        DisplayName = `$displayName
        State = `$state
        TemplateId = `$template.Id
    }
    
    try {
        `$policy = New-MgIdentityConditionalAccessPolicy -BodyParameter `$params
        Write-Host "  ✓ Created policy: `$displayName" -ForegroundColor Green
        `$deployedPolicies += `$policy
    }
    catch {
        Write-Host "  × Failed to create policy: `$displayName. Error: `$_" -ForegroundColor Red
    }
}

Write-Host "`nDeployment complete. Deployed `$(`$deployedPolicies.Count) out of `$(`$selectedTemplates.Count) templates." -ForegroundColor Cyan
"@
}

# Create utility script directory
$utilityDir = Join-Path -Path $HOME -ChildPath "CAAnalyzer-Scripts"
if (-not (Test-Path -Path $utilityDir)) {
    New-Item -Path $utilityDir -ItemType Directory -Force | Out-Null
}

# Write utility scripts
foreach ($scriptName in $utilityScripts.Keys) {
    $scriptPath = Join-Path -Path $utilityDir -ChildPath $scriptName
    Set-Content -Path $scriptPath -Value $utilityScripts[$scriptName] -Force
    Write-Host "Created utility script: $scriptPath" -ForegroundColor Green
}

# Create CAProfiles directory for storing exports
$profilesDir = Join-Path -Path $HOME -ChildPath "CAProfiles"
if (-not (Test-Path -Path $profilesDir)) {
    New-Item -Path $profilesDir -ItemType Directory -Force | Out-Null
    Write-Host "Created profiles directory: $profilesDir" -ForegroundColor Green
}

if ($downloadSuccess) {
    Write-Host "`nAll module files downloaded successfully!" -ForegroundColor Green
    
    # Import the module
    try {
        Import-Module -Name "ConditionalAccessAnalyzer" -Force -ErrorAction Stop
        Write-Host "Conditional Access Analyzer module imported successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Module download succeeded but import failed: $_"
        Write-Host "You may need to restart your PowerShell session or run 'Import-Module ConditionalAccessAnalyzer' manually." -ForegroundColor Yellow
    }
    
    # Display help information
    Write-Host "`nQuick Start Guide:" -ForegroundColor Cyan
    Write-Host "1. To run the analyzer interactively, use:" -ForegroundColor White
    Write-Host "   $utilityDir/Run-CAAnalyzer.ps1" -ForegroundColor Yellow
    Write-Host "2. To deploy Microsoft's Conditional Access templates, use:" -ForegroundColor White
    Write-Host "   $utilityDir/Deploy-CATemplates.ps1" -ForegroundColor Yellow
    Write-Host "3. For more information about available commands:" -ForegroundColor White
    Write-Host "   Get-Command -Module ConditionalAccessAnalyzer | Get-Help" -ForegroundColor Yellow
    
    # Run interactive mode if requested
    if ($Interactive) {
        Write-Host "`nStarting interactive mode..." -ForegroundColor Cyan
        & "$utilityDir/Run-CAAnalyzer.ps1"
    }
    
    return $true
}
else {
    Write-Error "Failed to download all required module files. The module may not work correctly."
    return $false
}
