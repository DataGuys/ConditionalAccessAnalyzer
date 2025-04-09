#region Module Variables
$Script:CAAnalyzerConnection = $null
$Script:CAAnalyzerLogPath = "$env:TEMP/ConditionalAccessAnalyzer.log"
$Script:CAAnalyzerDebug = $false
$Script:ApplicationCache = @{}

# Detect Azure Cloud Shell and adapt paths accordingly
if ($env:ACC_CLOUD -eq 'Azure' -or (Test-Path -Path "/home/azureuser" -ErrorAction SilentlyContinue)) {
    $Script:IsCloudShell = $true
    $Script:CAAnalyzerLogPath = "$HOME/CAAnalyzer.log"
}

# Detect if we're running in Linux/macOS or Windows for path handling
$Script:IsWindows = $PSVersionTable.Platform -eq 'Win32NT' -or (-not (Get-Command -Name 'uname' -ErrorAction SilentlyContinue))
$Script:PathSeparator = if ($Script:IsWindows) { '\' } else { '/' }
#endregion

#region Path Handling Function
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
#endregion

#region Import Classes
$classFiles = @(
    "Classes/ComplianceScore.ps1",
    "Classes/PolicyResult.ps1",
    "Classes/ReportData.ps1"
)

foreach ($file in $classFiles) {
    $filePath = Join-Path -Path $PSScriptRoot -ChildPath (Get-NormalizedPath -Path $file)
    if (Test-Path -Path $filePath) {
        try {
            . $filePath
            Write-Verbose "Imported class file: $filePath"
        }
        catch {
            Write-Error "Failed to import class file $filePath : $_"
        }
    }
    else {
        Write-Warning "Class file $filePath not found"
    }
}
#endregion

#region Import Private Functions
$privateFunctions = @(
    "Private/Logging.ps1",
    "Private/GraphHelpers.ps1",
    "Private/DataProcessing.ps1",
    "Private/PolicyEvaluation.ps1"
)

foreach ($function in $privateFunctions) {
    $functionPath = Join-Path -Path $PSScriptRoot -ChildPath (Get-NormalizedPath -Path $function)
    if (Test-Path -Path $functionPath) {
        try {
            . $functionPath
            Write-Verbose "Imported private function: $functionPath"
        }
        catch {
            Write-Error "Failed to import function from $functionPath : $_"
        }
    }
    else {
        Write-Warning "Function file $functionPath not found"
    }
}
#endregion

#region Import Public Functions
$publicFunctions = @(
    "Public/Connect.ps1",
    "Public/Analysis.ps1",
    "Public/Reporting.ps1",
    "Public/Remediation.ps1"
)

foreach ($function in $publicFunctions) {
    $functionPath = Join-Path -Path $PSScriptRoot -ChildPath (Get-NormalizedPath -Path $function)
    if (Test-Path -Path $functionPath) {
        try {
            . $functionPath
            Write-Verbose "Imported public function: $functionPath"
        }
        catch {
            Write-Error "Failed to import function from $functionPath : $_"
        }
    }
    else {
        Write-Warning "Function file $functionPath not found"
    }
}
#endregion

#region Import Template Files
$templateFiles = @(
    "Templates/CABestPracticePolicy.ps1",
