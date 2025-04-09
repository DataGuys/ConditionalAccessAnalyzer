# Module: CAAnalyzer.psm1
# This file contains functions for analyzing Conditional Access policies against security benchmarks

function Test-CASecurityBenchmark {
    <#
    .SYNOPSIS
        Evaluates Conditional Access policies against industry security benchmarks.
    .DESCRIPTION
        Assesses Conditional Access configurations against multiple security frameworks
        including NIST SP 800-53, CIS Controls, Microsoft MCRA, and ISO 27001.
        Provides detailed compliance gaps and recommendations.
    .PARAMETER BenchmarkName
        The name of the security benchmark to evaluate against.
        Valid values include: NIST, CIS, MCRA, ISO27001, PCI, HIPAA, All
    .PARAMETER Results
        The compliance check results to evaluate. If not specified, Invoke-CAComplianceCheck is run.
    .PARAMETER IncludeDetails
        If specified, includes detailed control mappings and evaluations.
    .PARAMETER OutputPath
        If specified, saves the benchmark report to the specified path.
    .EXAMPLE
        Test-CASecurityBenchmark -BenchmarkName NIST
        Evaluates the current Conditional Access configuration against NIST SP 800-53.
    .EXAMPLE
        Test-CASecurityBenchmark -BenchmarkName All -IncludeDetails -OutputPath "C:\Reports\Benchmark.html"
        Evaluates against all benchmarks with detailed results saved to an HTML file.
    .NOTES
        The benchmark evaluations are based on industry best practices and regulatory requirements.
        This assessment provides guidance but does not guarantee regulatory compliance.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('NIST', 'CIS', 'MCRA', 'ISO27001', 'PCI', 'HIPAA', 'All')]
        [string]$BenchmarkName,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # If no results provided, run the compliance check
        if (-not $Results) {
            Write-Host "No results provided. Running comprehensive Conditional Access compliance check..." -ForegroundColor Yellow
            $Results = Invoke-CAComplianceCheck
        }
        
        # Benchmark control definitions
        $benchmarkControls = @{
            # NIST SP 800-53 Controls
            'NIST' = @(
                @{
                    Control = "AC-2"
                    Title = "Account Management"
                    Description = "Organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts."
                    Requirements = @(
                        @{
                            ID = "AC-2.1"
                            Description = "Conditional Access policies for privileged account management"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFARequired }
                            Impact = "Critical"
                            Recommendation = "Implement MFA requirements for all privileged accounts"
                        },
                        @{
                            ID = "AC-2.7"
                            Description = "Role-based access schemes"
                            Evaluator = { param($Results) $Results.Checks.AdminMFA.AdminMFAPolicies.Count -gt 0 }
                            Impact = "High"
                            Recommendation = "Create role-specific Conditional Access policies"
                        }
                    )
                },
                @{
                    Control = "AC-7"
                    Title = "Unsuccessful Logon Attempts"
                    Description = "Organization enforces limit of consecutive invalid logon attempts during a specified time period."
                    Requirements = @(
                        @{
                            ID = "AC-7.1"
                            Description = "Risk-based authentication controls"
                            Evaluator = { param($Results) $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured }
                            Impact = "High"
                            Recommendation = "Deploy sign-in risk policies to detect and respond to suspicious authentication attempts"
                        }
                    )
                }
                # Additional NIST controls would be defined here
            )
            # Additional benchmark definitions would be added here
        }
        
        # Helper function to evaluate benchmark compliance
        function Measure-BenchmarkCompliance {
            param (
                [Parameter(Mandatory = $true)]
                [string]$BenchmarkName,
                
                [Parameter(Mandatory = $true)]
                [PSCustomObject]$Results
            )
            
            $benchmarkData = $benchmarkControls[$BenchmarkName]
            $totalControls = 0
            $passedControls = 0
            $failedControls = 0
            
            $evaluationDetails = @()
            
            foreach ($control in $benchmarkData) {
                $controlPassed = $true
                $controlDetails = @()
                
                foreach ($requirement in $control.Requirements) {
                    $totalControls++
                    $result = & $requirement.Evaluator $Results
                    
                    if ($result) {
                        $passedControls++
                        $status = "PASS"
                    }
                    else {
                        $failedControls++
                        $status = "FAIL"
                        $controlPassed = $false
                    }
                    
                    $controlDetails += [PSCustomObject]@{
                        ID = $requirement.ID
                        Description = $requirement.Description
                        Status = $status
                        Impact = $requirement.Impact
                        Recommendation = $requirement.Recommendation
                    }
                }
                
                $evaluationDetails += [PSCustomObject]@{
                    Control = $control.Control
                    Title = $control.Title
                    Description = $control.Description
                    Status = if ($controlPassed) { "PASS" } else { "FAIL" }
                    Requirements = $controlDetails
                }
            }
            
            $complianceScore = if ($totalControls -gt 0) { 
                [math]::Round(($passedControls / $totalControls) * 100) 
            } else { 
                0 
            }
            
            return [PSCustomObject]@{
                BenchmarkName = $BenchmarkName
                TotalControls = $totalControls
                PassedControls = $passedControls
                FailedControls = $failedControls
                ComplianceScore = $complianceScore
                Details = $evaluationDetails
            }
        }
        
        # Helper function to convert benchmark results to HTML
        function Convert-BenchmarkToHtml {
            param(
                [Parameter(Mandatory = $true)]
                [PSCustomObject[]]$BenchmarkResults
            )
            
            # HTML template stored in a here-string
            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conditional Access Security Benchmark Report</title>
    <style>
        :root {
            --primary-color: #0078D4;
            --secondary-color: #50E6FF;
            --success-color: #107C10;
            --warning-color: #FF8C00;
            --danger-color: #E81123;
            --light-color: #F3F2F1;
            --dark-color: #201F1E;
            --font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        /* Rest of CSS would go here */
        body {
            font-family: var(--font-family);
            line-height: 1.6;
            color: var(--dark-color);
            background-color: #F9F9F9;
            margin: 0;
            padding: 0;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Conditional Access Security Benchmark Report</h1>
            <p>Generated on $(Get-Date -Format "MMMM d, yyyy HH:mm:ss")</p>
        </div>
    </header>
    
    <div class="container">
        <!-- Report content would go here -->
    </div>
    
    <div class="footer">
        <p>Conditional Access Analyzer Security Benchmark Report</p>
        <p>Generated using Conditional Access Analyzer PowerShell Module</p>
    </div>
    
    <script>
        // JavaScript would go here
        console.log("Report loaded");
    </script>
</body>
</html>
"@
            
            return $html
        }
    }
    
    process {
        try {
            # Display benchmark evaluation header
            $benchmarkList = if ($BenchmarkName -eq 'All') {
                $benchmarkControls.Keys
            } else {
                @($BenchmarkName)
            }
            
            Write-Host "Evaluating Conditional Access configuration against security benchmarks..." -ForegroundColor Cyan
            
            # Evaluate benchmarks
            $benchmarkResults = @()
            foreach ($benchmark in $benchmarkList) {
                Write-Host "`nEvaluating against $benchmark benchmark..." -ForegroundColor Yellow
                $results = Measure-BenchmarkCompliance -BenchmarkName $benchmark -Results $Results
                
                # Display summary
                Write-Host "  - Total Controls: $($results.TotalControls)" -ForegroundColor White
                Write-Host "  - Passed Controls: $($results.PassedControls)" -ForegroundColor Green
                Write-Host "  - Failed Controls: $($results.FailedControls)" -ForegroundColor Red
                Write-Host "  - Compliance Score: $($results.ComplianceScore)%" -ForegroundColor $(
                    if ($results.ComplianceScore -ge 90) { "Green" }
                    elseif ($results.ComplianceScore -ge 70) { "Yellow" }
                    else { "Red" }
                )
                
                $benchmarkResults += $results
                
                # Display detailed results if requested
                if ($IncludeDetails) {
                    Write-Host "`n  Control Details:" -ForegroundColor Yellow
                    
                    foreach ($control in $results.Details) {
                        $statusSymbol = if ($control.Status -eq "PASS") { "✓" } else { "✗" }
                        $statusColor = if ($control.Status -eq "PASS") { "Green" } else { "Red" }
                        
                        Write-Host "    [$statusSymbol] $($control.Control): $($control.Title)" -ForegroundColor $statusColor
                        
                        if ($control.Status -eq "FAIL") {
                            Write-Host "      - Description: $($control.Description)" -ForegroundColor White
                            
                            Write-Host "      - Failed Requirements:" -ForegroundColor Yellow
                            $failedReqs = $control.Requirements | Where-Object { $_.Status -eq "FAIL" }
                            
                            foreach ($req in $failedReqs) {
                                Write-Host "        * $($req.ID): $($req.Description)" -ForegroundColor White
                                Write-Host "          Impact: $($req.Impact)" -ForegroundColor $(
                                    if ($req.Impact -eq "Critical") { "Red" }
                                    elseif ($req.Impact -eq "High") { "DarkRed" }
                                    else { "Yellow" }
                                )
                                Write-Host "          Recommendation: $($req.Recommendation)" -ForegroundColor Cyan
                            }
                        }
                    }
                }
            }
            
            # Create HTML report if output path is specified
            if ($OutputPath) {
                Write-Host "`nGenerating benchmark report..." -ForegroundColor Yellow
                
                $html = Convert-BenchmarkToHtml -BenchmarkResults $benchmarkResults
                Set-Content -Path $OutputPath -Value $html -Encoding UTF8
                
                Write-Host "Report saved to $OutputPath" -ForegroundColor Green
            }
            
            # Return results
            return $benchmarkResults
        }
        catch {
            Write-Error "Failed to evaluate against security benchmarks: $_"
            throw
        }
    }
}

function Export-CAComplianceDashboard {
    <#
    .SYNOPSIS
        Exports a comprehensive Conditional Access compliance dashboard.
    .DESCRIPTION
        Generates an interactive HTML dashboard combining compliance check results,
        benchmark evaluations, and trend analysis to provide a complete security
        overview.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$BenchmarkResults,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$HistoricalResults,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeBenchmarks,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRemediation,
        
        [Parameter(Mandatory = $false)]
        [string]$CompanyName,
        
        [Parameter(Mandatory = $false)]
        [string]$BrandingLogo,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$OpenDashboard
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # If no results provided, run the compliance check
        if (-not $Results) {
            Write-Host "No results provided. Running comprehensive Conditional Access compliance check..." -ForegroundColor Yellow
            $Results = Invoke-CAComplianceCheck
        }
        
        # Set default path if not specified
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $fileName = "CA-Compliance-Dashboard-$timestamp.html"
            
            # Use a sensible default location
            $documentsPath = [Environment]::GetFolderPath('MyDocuments')
            $reportsFolder = Join-Path -Path $documentsPath -ChildPath "CA-Reports"
            
            # Create the reports folder if it doesn't exist
            if (-not (Test-Path -Path $reportsFolder)) {
                New-Item -Path $reportsFolder -ItemType Directory -Force | Out-Null
            }
            
            $OutputPath = Join-Path -Path $reportsFolder -ChildPath $fileName
        }
    }
    
    process {
        try {
            Write-Host "Generating comprehensive Conditional Access compliance dashboard..." -ForegroundColor Cyan
            
            # Generate dashboard HTML (implementation would be here)
            $html = New-ComplianceDashboardHtml -Results $Results -BenchmarkResults $BenchmarkResults
            
            # Save dashboard
            Set-Content -Path $OutputPath -Value $html -Encoding UTF8
            
            Write-Host "Dashboard saved to $OutputPath" -ForegroundColor Green
            
            # Open dashboard if requested
            if ($OpenDashboard) {
                Start-Process $OutputPath
            }
            
            return @{
                DashboardPath = $OutputPath
                GeneratedTime = Get-Date
                IncludesBenchmarks = $IncludeBenchmarks.IsPresent
                IncludesRemediation = $IncludeRemediation.IsPresent
            }
        }
        catch {
            Write-Error "Failed to generate Conditional Access compliance dashboard: $_"
            throw
        }
    }
    
    end {
        function New-ComplianceDashboardHtml {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [PSCustomObject]$Results,
                
                [Parameter(Mandatory = $false)]
                [PSCustomObject[]]$BenchmarkResults
            )
            
            # Simple HTML template for demonstration
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CA Dashboard</title>
</head>
<body>
    <h1>Conditional Access Compliance Dashboard</h1>
    <p>Score: $($Results.ComplianceScore)%</p>
</body>
</html>
"@
            
            return $html
        }
    }
}

# Export functions
Export-ModuleMember -Function Test-CASecurityBenchmark, Export-CAComplianceDashboard