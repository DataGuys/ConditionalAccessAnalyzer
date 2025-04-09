#region Module Variables
$Script:CAAnalyzerConnection = $null
$Script:CAAnalyzerLogPath = "$env:TEMP\ConditionalAccessAnalyzer.log"
$Script:CAAnalyzerDebug = $false
#endregion

#region Import Classes
$classFiles = @(
    "Classes\ComplianceScore.ps1",
    "Classes\PolicyResult.ps1",
    "Classes\ReportData.ps1"
)

foreach ($file in $classFiles) {
    $filePath = Join-Path -Path $PSScriptRoot -ChildPath $file
    if (Test-Path -Path $filePath) {
        try {
            . $filePath
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
    "Private\Logging.ps1",
    "Private\GraphHelpers.ps1",
    "Private\DataProcessing.ps1",
    "Private\PolicyEvaluation.ps1"
)

foreach ($function in $privateFunctions) {
    $functionPath = Join-Path -Path $PSScriptRoot -ChildPath $function
    if (Test-Path -Path $functionPath) {
        try {
            . $functionPath
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
    "Public\Connect.ps1",
    "Public\Analysis.ps1",
    "Public\Reporting.ps1",
    "Public\Remediation.ps1"
)

foreach ($function in $publicFunctions) {
    $functionPath = Join-Path -Path $PSScriptRoot -ChildPath $function
    if (Test-Path -Path $functionPath) {
        try {
            . $functionPath
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
    "Templates\CABestPracticePolicy.ps1",
    "Templates\BenchmarkAnalyzer.ps1",
    "Templates\CIS.ps1",
    "Templates\NIST.ps1",
    "Templates\ZeroTrust.ps1"
)

foreach ($template in $templateFiles) {
    $templatePath = Join-Path -Path $PSScriptRoot -ChildPath $template
    if (Test-Path -Path $templatePath) {
        try {
            . $templatePath
        }
        catch {
            Write-Error "Failed to import template from $templatePath : $_"
        }
    }
    else {
        Write-Warning "Template file $templatePath not found"
    }
}
#endregion

#region Module Initialization
Write-Verbose "Initializing Conditional Access Analyzer Module"

# Initialize logging
Initialize-CALogging -LogPath $Script:CAAnalyzerLogPath

# Export public functions
Export-ModuleMember -Function $FunctionsToExport
#endregion
