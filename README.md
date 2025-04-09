# Conditional Access Analyzer

A comprehensive PowerShell module for analyzing, assessing, and remediating Conditional Access policies in Microsoft Entra ID (formerly Azure AD).

## Quick Installation

### Azure Cloud Shell One-Liner

```powershell
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/DataGuys/ConditionalAccessAnalyzer/refs/heads/main/Install-CAAnalyzer.ps1" -UseBasicParsing).Content
```

This command downloads and installs the module from GitHub, then sets up everything needed to run the analyzer.

## Features

- **Compliance Checks**: Evaluate Conditional Access policies against security best practices
- **Security Benchmarks**: Compare policies against NIST SP 800-53, CIS Controls, and Zero Trust principles
- **Interactive Dashboards**: Generate HTML dashboards with visualizations of compliance status
- **Excel & PowerPoint Reports**: Create detailed reports for documentation and presentations
- **Remediation Assistance**: Get actionable recommendations and deploy baseline policies
- **Emergency Access Management**: Configure emergency access exclusions for break-glass scenarios
- **Policy Templates**: Deploy Microsoft's recommended Conditional Access policies with a single command

## Requirements

- PowerShell 5.1 or higher (works with PowerShell Core 7.x as well)
- Microsoft.Graph modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.DeviceManagement

## Key Commands

After installing the module, you can use the following commands:

```powershell
# Connect to Microsoft Graph
Connect-CAAnalyzer

# Run a comprehensive compliance check
$results = Invoke-CAComplianceCheck

# Generate HTML report
Export-CAComplianceReport -Results $results -ReportType HTML -Path "./CAReport.html"

# Test against security benchmarks
Test-CASecurityBenchmark -BenchmarkName NIST -Results $results
Test-CASecurityBenchmark -BenchmarkName CIS -Results $results

# Create best practice policies
New-CABestPracticePolicy -PolicyType AdminMFA -DeployPolicy

# Get remediation recommendations
Invoke-CAComplianceRemediation -Results $results -WhatIf
```

## Utility Scripts

The installer creates utility scripts in your home directory under `~/CAAnalyzer-Scripts/`:

- `Run-CAAnalyzer.ps1`: Interactive script to connect, analyze policies, and generate reports
- `Deploy-CATemplates.ps1`: Simplified script to deploy Microsoft's recommended Conditional Access templates

## Support

If you encounter any issues, please open an issue on the GitHub repository.

## License

MIT
