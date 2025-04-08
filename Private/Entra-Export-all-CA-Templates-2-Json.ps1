# PowerShell script to export Conditional Access Templates to JSON files and create a zip archive

# Create a directory to store the exported templates
$exportDir = "ConditionalAccessTemplates_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

Write-Host "Created directory: $exportDir" -ForegroundColor Green

# Ensure the Microsoft.Graph module is available and import it
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.SignIns)) {
    Write-Host "Installing Microsoft.Graph.Identity.SignIns module..." -ForegroundColor Yellow
    Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
}

# Connect to Microsoft Graph with the required permissions
Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

# Get all Conditional Access Templates
Write-Host "Retrieving Conditional Access Templates..." -ForegroundColor Cyan
$templates = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/templates"

# Check if templates were found
if ($null -eq $templates.value -or $templates.value.Count -eq 0) {
    Write-Host "No Conditional Access Templates found." -ForegroundColor Red
    exit
}

Write-Host "Found $($templates.value.Count) templates." -ForegroundColor Green

# Export each template to a JSON file
foreach ($template in $templates.value) {
    # Clean up the template name to make it a valid filename
    $templateName = $template.displayName -replace '[\\\/\:\*\?\"\<\>\|]', '_'
    
    # Create the full file path
    $filePath = Join-Path -Path $exportDir -ChildPath "$templateName.json"
    
    # Convert the template to JSON and save it
    $template | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding utf8
    
    Write-Host "Exported template: $templateName" -ForegroundColor Cyan
}

# Create a zip archive of all the JSON files
$zipFileName = "$exportDir.zip"
Compress-Archive -Path $exportDir -DestinationPath $zipFileName -Force

Write-Host "Created zip archive: $zipFileName" -ForegroundColor Green
Write-Host "To download the zip file, use the Azure Cloud Shell download function or run: `n`n az storage blob upload --account-name <storage-account-name> --container-name <container-name> --name $zipFileName --file $zipFileName" -ForegroundColor Yellow

# Display instructions for downloading via Cloud Shell
Write-Host "`nTo download from Cloud Shell web interface:" -ForegroundColor Magenta
Write-Host "1. Click on the 'Download file' icon in the Cloud Shell menu" -ForegroundColor Magenta
Write-Host "2. Enter the path: $zipFileName" -ForegroundColor Magenta
Write-Host "3. Click 'Download'" -ForegroundColor Magenta

# Cleanup
Write-Host "`nDo you want to remove the unzipped JSON files directory? (Y/N)" -ForegroundColor Yellow
$response = Read-Host
if ($response -eq 'Y' -or $response -eq 'y') {
    Remove-Item -Path $exportDir -Recurse -Force
    Write-Host "Removed directory: $exportDir" -ForegroundColor Green
}
