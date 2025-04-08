<#
.SYNOPSIS
    Exports all available Conditional Access Templates to JSON files and creates a downloadable zip archive in Azure Cloud Shell.
.DESCRIPTION
    This script connects to Microsoft Graph API, retrieves all Conditional Access Templates,
    exports them as individual JSON files named after each template, and packages them into a zip file.
    It's specifically designed to work in Azure Cloud Shell environment.
.NOTES
    Author: Claude
    Version: 1.0
    Requires: Azure Cloud Shell, Microsoft.Graph modules
#>

# Create a timestamped directory for export
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$exportDir = "CA_Templates_$timestamp"
$exportPath = Join-Path -Path $HOME -ChildPath $exportDir
$zipFileName = "$exportDir.zip"
$zipFilePath = Join-Path -Path $HOME -ChildPath $zipFileName

# Create output directory
Write-Host "Creating export directory: $exportPath" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $exportPath -Force | Out-Null

# Function to check if module is installed and install if necessary
function Ensure-Module {
    param (
        [string]$ModuleName
    )
    
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Installing $ModuleName module..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
        Import-Module -Name $ModuleName -Force
        Write-Host "$ModuleName module installed successfully." -ForegroundColor Green
    }
    else {
        Import-Module -Name $ModuleName -Force
        Write-Host "$ModuleName module is already installed." -ForegroundColor Green
    }
}

# Ensure required modules are installed
Ensure-Module -ModuleName "Microsoft.Graph.Authentication"
Ensure-Module -ModuleName "Microsoft.Graph.Identity.SignIns"

# Connect to Microsoft Graph with appropriate scopes
try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    
    # Try to silently connect first - this works well in Cloud Shell where user is already authenticated
    Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome -ErrorAction SilentlyContinue
    
    # If silent connection failed, try interactive
    if (-not (Get-MgContext)) {
        Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome
    }
    
    $context = Get-MgContext
    if (-not $context) {
        throw "Failed to authenticate to Microsoft Graph."
    }
    
    Write-Host "Successfully connected to Microsoft Graph as $($context.Account)" -ForegroundColor Green
}
catch {
    Write-Host "Error connecting to Microsoft Graph: $_" -ForegroundColor Red
    exit 1
}

# Retrieve Conditional Access Templates using Microsoft Graph API
try {
    Write-Host "Retrieving Conditional Access Templates..." -ForegroundColor Cyan
    $apiUrl = "https://graph.microsoft.com/beta/identity/conditionalAccess/templates"
    $templates = Invoke-MgGraphRequest -Method GET -Uri $apiUrl
    
    # Check if templates were found
    if ($null -eq $templates.value -or $templates.value.Count -eq 0) {
        Write-Host "No Conditional Access Templates found." -ForegroundColor Yellow
        exit
    }
    
    Write-Host "Found $($templates.value.Count) Conditional Access Templates." -ForegroundColor Green
}
catch {
    Write-Host "Error retrieving Conditional Access Templates: $_" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Export templates to JSON files
$exportedFiles = @()
$counter = 0

foreach ($template in $templates.value) {
    $counter++
    
    try {
        # Clean up template name to create a valid filename
        $templateName = $template.displayName -replace '[\\\/\:\*\?\"\<\>\|\s]', '_'
        
        # Add counter to ensure unique filenames
        $fileName = "{0:D3}_{1}.json" -f $counter, $templateName
        $filePath = Join-Path -Path $exportPath -ChildPath $fileName
        
        # Convert template to JSON and save to file
        $template | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8 -Force
        
        $fileInfo = [PSCustomObject]@{
            FileName = $fileName
            FilePath = $filePath
            Template = $template.displayName
        }
        $exportedFiles += $fileInfo
        
        Write-Host "Exported template: $($template.displayName)" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error exporting template '$($template.displayName)': $_" -ForegroundColor Red
    }
}

Write-Host "Successfully exported $($exportedFiles.Count) templates to $exportPath" -ForegroundColor Green

# Create zip file using native zip command (more reliable in Cloud Shell)
try {
    Write-Host "Creating zip archive using system zip command..." -ForegroundColor Cyan
    
    # Change to parent directory to include the folder in the zip
    $currentLocation = Get-Location
    Set-Location -Path $HOME
    
    # Use the zip command directly (pre-installed in Cloud Shell)
    $zipCommand = "zip -r $zipFileName $exportDir"
    Invoke-Expression $zipCommand
    
    # Verify zip file was created
    if (Test-Path $zipFilePath) {
        $zipSize = (Get-Item $zipFilePath).Length
        Write-Host "Successfully created zip archive: $zipFilePath ($([Math]::Round($zipSize/1KB, 2)) KB)" -ForegroundColor Green
    } else {
        throw "Zip file was not created."
    }
    
    # Return to original location
    Set-Location -Path $currentLocation
}
catch {
    # If system zip fails, try PowerShell Compress-Archive
    Write-Host "System zip command failed. Trying PowerShell Compress-Archive..." -ForegroundColor Yellow
    
    try {
        Compress-Archive -Path $exportPath -DestinationPath $zipFilePath -Force
        
        if (Test-Path $zipFilePath) {
            $zipSize = (Get-Item $zipFilePath).Length
            Write-Host "Successfully created zip archive using Compress-Archive: $zipFilePath ($([Math]::Round($zipSize/1KB, 2)) KB)" -ForegroundColor Green
        } else {
            throw "Compress-Archive did not create a zip file."
        }
    }
    catch {
        Write-Host "Error creating zip archive with Compress-Archive: $_" -ForegroundColor Red
        Write-Host "JSON files are still available in: $exportPath" -ForegroundColor Yellow
    }
}

# Display instructions for downloading via Cloud Shell
Write-Host "`nTo download the zip file from Azure Cloud Shell:" -ForegroundColor Magenta
Write-Host "1. Click on the 'Download file' icon in the Cloud Shell toolbar (or use the More menu)" -ForegroundColor Magenta
Write-Host "2. Enter the following path: $zipFilePath" -ForegroundColor Magenta
Write-Host "3. Click 'Download'" -ForegroundColor Magenta

# Print a summary
Write-Host "`nSummary:" -ForegroundColor White
Write-Host "- Templates found: $($templates.value.Count)" -ForegroundColor White
Write-Host "- Templates exported: $($exportedFiles.Count)" -ForegroundColor White
Write-Host "- Export directory: $exportPath" -ForegroundColor White
Write-Host "- Zip file: $zipFilePath" -ForegroundColor White

# Optional: List the first few templates
if ($exportedFiles.Count -gt 0) {
    Write-Host "`nFirst few exported templates:" -ForegroundColor White
    $exportedFiles | Select-Object -First 5 | ForEach-Object {
        Write-Host "- $($_.Template)" -ForegroundColor White
    }
    
    if ($exportedFiles.Count -gt 5) {
        Write-Host "- ... and $($exportedFiles.Count - 5) more" -ForegroundColor White
    }
}

Write-Host "`nExport process completed." -ForegroundColor Green
