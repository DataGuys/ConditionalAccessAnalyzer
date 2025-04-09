#region Module Variables
$Script:CAAnalyzerConnection = $null
$Script:CAAnalyzerLogPath = "$env:TEMP/ConditionalAccessAnalyzer.log"
$Script:CAAnalyzerDebug = $false
$Script:ApplicationCache = @{}

# Detect environment and adapt paths
if ($env:ACC_CLOUD -eq 'Azure' -or (Test-Path -Path "/home/azureuser" -ErrorAction SilentlyContinue)) {
    $Script:IsCloudShell = $true
    $Script:CAAnalyzerLogPath = "$HOME/CAAnalyzer.log"
}

# Detect OS for path handling
$Script:IsWindows = $PSVersionTable.Platform -eq 'Win32NT' -or (-not (Get-Command -Name 'uname' -ErrorAction SilentlyContinue))
$Script:PathSeparator = if ($Script:IsWindows) { '\' } else { '/' }
#endregion

#region Helper Functions
function Get-NormalizedPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$Relative
    )
    
    # Normalize path separators for the current OS
    $normalizedPath = $Path.Replace('\', $Script:PathSeparator).Replace('/', $Script:PathSeparator)
    
    # Get the module root path
    $moduleRoot = $PSScriptRoot
    
    # If relative path is requested and the path is not already relative
    if ($Relative -and $normalizedPath.StartsWith($moduleRoot)) {
        $normalizedPath = $normalizedPath.Substring($moduleRoot.Length)
        if ($normalizedPath.StartsWith($Script:PathSeparator)) {
            $normalizedPath = $normalizedPath.Substring(1)
        }
    }
    
    return $normalizedPath
}

function Import-ModuleFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    $resolvedPath = Join-Path -Path $PSScriptRoot -ChildPath (Get-NormalizedPath -Path $FilePath)
    if (Test-Path -Path $resolvedPath) {
        try {
            . $resolvedPath
            Write-Verbose "Imported file: $resolvedPath"
            return $true
        }
        catch {
            Write-Error "Failed to import file $resolvedPath : $_"
            return $false
        }
    }
    else {
        Write-Warning "File not found: $resolvedPath"
        return $false
    }
}
#endregion

#region Module Initialization
Write-Verbose "Initializing Conditional Access Analyzer Module"

# Create ordered list of file categories to import
$fileCategories = @(
    @{
        Name = "Classes"
        Pattern = "Classes/*.ps1"
        Required = $true
    },
    @{
        Name = "Private Functions" 
        Pattern = "Private/*.ps1"
        Required = $true
    },
    @{
        Name = "Public Functions"
        Pattern = "Public/*.ps1" 
        Required = $true
    },
    @{
        Name = "Templates"
        Pattern = "Templates/*.ps1"
        Required = $false
    }
)

# Import files by category
$importedFiles = @()
$failedFiles = @()

foreach ($category in $fileCategories) {
    Write-Verbose "Importing $($category.Name)..."
    $files = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath $category.Pattern) -ErrorAction SilentlyContinue
    
    if ($files.Count -eq 0 -and $category.Required) {
        Write-Warning "No files found in required category: $($category.Name)"
    }
    
    foreach ($file in $files) {
        $relativePath = Get-NormalizedPath -Path $file.FullName -Relative
        $success = Import-ModuleFile -FilePath $relativePath
        
        if ($success) {
            $importedFiles += $relativePath
        }
        else {
            $failedFiles += $relativePath
            if ($category.Required) {
                Write-Error "Failed to import required file: $relativePath"
            }
        }
    }
}

# Initialize logging
$logDir = Split-Path -Path $Script:CAAnalyzerLogPath -Parent
if (-not (Test-Path -Path $logDir -PathType Container)) {
    try {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    catch {
        Write-Warning "Failed to create log directory: $_"
    }
}

# Export public functions
$publicFunctions = Get-Command -CommandType Function -Module $MyInvocation.MyCommand.ModuleName

# Additional function categories
$connectFunctions = $publicFunctions | Where-Object { $_.Name -like "Connect-*" -or $_.Name -like "Disconnect-*" -or $_.Name -like "Test-*Connection" }
$analysisFunctions = $publicFunctions | Where-Object { $_.Name -like "Get-*" -or $_.Name -like "Test-*" -or $_.Name -like "Invoke-*" }
$reportingFunctions = $publicFunctions | Where-Object { $_.Name -like "Export-*" -or $_.Name -like "ConvertTo-*" }
$remediationFunctions = $publicFunctions | Where-Object { $_.Name -like "New-*" -or $_.Name -like "Set-*" }
$templateFunctions = $publicFunctions | Where-Object { $_.Name -like "Deploy-*" -or $_.Name -eq "Save-CABenchmark" -or $_.Name -eq "Get-CATemplateList" }

# Export all public functions
Export-ModuleMember -Function $publicFunctions.Name

# Display initialization summary
Write-Verbose "Conditional Access Analyzer Module initialized"
Write-Verbose "Imported $($importedFiles.Count) files, $($failedFiles.Count) failed"
Write-Verbose "Exported $($publicFunctions.Count) public functions"
#endregion
