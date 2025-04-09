# Conditional Access Analyzer

A comprehensive PowerShell module for analyzing, assessing, and remediating Conditional Access policies in Microsoft Entra ID (formerly Azure AD).

## Overview

Conditional Access Analyzer helps security administrators evaluate their Conditional Access implementation against security best practices, industry frameworks, and Zero Trust principles. It provides detailed reports, remediation recommendations, and the ability to deploy baseline policies.

## Features

- **Compliance Checks**: Evaluate Conditional Access policies against security best practices
- **Security Benchmarks**: Compare policies against NIST SP 800-53, CIS Controls, and Zero Trust principles
- **Interactive Dashboards**: Generate HTML dashboards with visualizations of compliance status
- **Excel & PowerPoint Reports**: Create detailed reports for documentation and presentations
- **Remediation Assistance**: Get actionable recommendations and deploy baseline policies
- **Emergency Access Management**: Configure emergency access exclusions for break-glass scenarios
- **Policy Templates**: Create best-practice Conditional Access policies with a single command

## Quick Start

### One-Liner for Azure Cloud Shell

```powershell
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/DataGuys/ConditionalAccessAnalyzer/refs/heads/main/InstallModule.ps1" -UseBasicParsing).Content
```

This command downloads and installs the module from GitHub, then launches the analyzer in interactive mode.

## Requirements

- PowerShell 5.1 or higher
- Microsoft.Graph modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.DeviceManagement

## Installation

### Manual Installation

1. Clone this repository:

   ```powershell
   git clone https://github.com/DataGuys/ConditionalAccessAnalyzer.git
   ```

2. Import the module:

   ```powershell
   Import-Module .\ConditionalAccessAnalyzer\ConditionalAccessAnalyzer.psd1
   ```

## Usage

### Connect to Microsoft Graph

```powershell
Connect-CAAnalyzer
```

### Run Compliance Check

```powershell
$results = Invoke-CAComplianceCheck
```

### Generate Compliance Report

```powershell
Export-CAComplianceReport -Results $results -ReportType HTML -Path ".\CAReport.html"
```

### Evaluate Against Security Benchmark

```powershell
Test-CASecurityBenchmark -BenchmarkName NIST -Results $results
```

### Create Best Practice Policies

```powershell
# Create MFA policy for administrators
New-CABestPracticePolicy -PolicyType AdminMFA -DeployPolicy
```

### Get Remediation Recommendations

```powershell
Invoke-CAComplianceRemediation -Results $results -WhatIf
```

## Example Workflows

### Security Assessment

```powershell
# Connect to Microsoft Graph
Connect-CAAnalyzer

# Run compliance check
$results = Invoke-CAComplianceCheck

# Export comprehensive dashboard
Export-CAComplianceDashboard -Results $results -IncludeBenchmarks -OutputPath ".\CADashboard.html" -OpenDashboard
```

### Implementing Zero Trust

```powershell
# Deploy Zero Trust baseline policies
New-CABestPracticePolicy -PolicyType ZeroTrustBase -DeployPolicy -State "enabledForReportingButNotEnforced"

# Get Zero Trust maturity level
$policies = Get-MgIdentityConditionalAccessPolicy
Get-ZeroTrustJourneyStage -Policies $policies
```

## License

MIT
