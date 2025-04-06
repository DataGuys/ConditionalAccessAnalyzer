# Import required modules
Import-Module -Name "./modules/Get-CA-Data.psm1" -Force
Import-Module -Name "./modules/Set-CA-Excel.psm1" -Force
Import-Module -Name "./modules/Get-TimeStamp.psm1" -Force
Import-Module -Name "./modules/Get-Configuration.psm1" -Force

# Configure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check for required modules
$requiredModules = @("ImportExcel", "Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns")
$installedModules = Get-Module -ListAvailable | Select-Object -ExpandProperty Name

foreach ($module in $requiredModules) {
    if ($installedModules -notcontains $module) {
        Write-Host "Installing required module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    }
}

# Import modules after installation
Import-Module ImportExcel
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Identity.SignIns

# Get configuration
$config = Get-Configuration

# Set output paths
$timestamp = Get-TimeStamp
$outputPath = "$($config.OutputPath)\ConditionalAccess_$timestamp.xlsx"

# Connect to Microsoft Graph
try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "Policy.Read.All", "Application.Read.All", "User.Read.All", "Group.Read.All", "Directory.Read.All" -ErrorAction Stop
    Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
}
catch {
    Write-Host "Error connecting to Microsoft Graph: $_" -ForegroundColor Red
    exit
}

# Get CA data
try {
    Write-Host "Getting Conditional Access policy data..." -ForegroundColor Cyan
    $caData = Get-CA-Data
    Write-Host "Successfully retrieved Conditional Access policies." -ForegroundColor Green
}
catch {
    Write-Host "Error retrieving Conditional Access data: $_" -ForegroundColor Red
    exit
}

# Export to Excel
try {
    Write-Host "Exporting data to Excel..." -ForegroundColor Cyan
    Set-CA-Excel -CAPolicies $caData -Path $outputPath
    Write-Host "Data exported successfully to: $outputPath" -ForegroundColor Green
}
catch {
    Write-Host "Error exporting data to Excel: $_" -ForegroundColor Red
    exit
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph
Write-Host "Disconnected from Microsoft Graph." -ForegroundColor Cyan

Write-Host "Script completed successfully!" -ForegroundColor Green
