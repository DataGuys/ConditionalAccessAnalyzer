# Conditional Access Analyzer

A comprehensive PowerShell module for analyzing, assessing, and remediating Conditional Access policies in Microsoft Entra ID (formerly Azure AD).

![Conditional Access Analyzer Logo](https://raw.githubusercontent.com/DataGuys/ConditionalAccess/main/assets/logo.png)

## Overview

The Conditional Access Analyzer is designed to help security professionals and Identity administrators evaluate their Conditional Access configuration against Zero Trust security best practices. It performs automated checks across all key security pillars including identity protection, device trust, session controls, risk-based access, and data protection.

**Key features:**
- Comprehensive security assessment against industry best practices
- Detailed compliance reporting with rich visualizations
- Automated remediation capabilities
- Policy template generation based on security frameworks
- Industry benchmark evaluation (NIST, CIS, ISO 27001, etc.)
- Azure Cloud Shell optimized for quick assessments

![Compliance Report Example](https://raw.githubusercontent.com/DataGuys/ConditionalAccess/main/assets/report-example.png)

## Quick Start

### Option 1: Run in Azure Cloud Shell (Recommended)

1. Open [Azure Cloud Shell](https://shell.azure.com/) in PowerShell mode
2. Copy and paste this one-liner to run a quick assessment:

```powershell
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/DataGuys/ConditionalAccess/main/QuickStart.ps1')
```

This will:
- Install required modules
- Connect to Microsoft Graph
- Run a comprehensive assessment
- Generate an HTML report
- Provide security recommendations

### Option 2: Install the Module

```powershell
# Install from PowerShell Gallery
Install-Module -Name ConditionalAccessAnalyzer

# Import the module
Import-Module ConditionalAccessAnalyzer

# Connect to Microsoft Graph
Connect-CAAnalyzer

# Run the assessment
Invoke-CAComplianceCheck
```

## Core Features

### Comprehensive Security Assessment

The module evaluates your Conditional Access configuration against key Zero Trust pillars:

1. **Identity Protection**
   - MFA enforcement for administrators
   - MFA requirements for regular users
   - Authentication session controls

2. **Device Trust**
   - Device compliance requirements
   - Device platform conditions
   - Browser and client app restrictions

3. **Risk-Based Access**
   - User risk protection
   - Sign-in risk mitigation
   - Automated remediation on risk detection

4. **Data Protection**
   - Mobile Application Management policies
   - App protection data controls
   - Cut/copy/paste restrictions

5. **Network Security**
   - Microsoft Defender for Cloud Apps integration
   - Global Secure Access configuration
   - Zero Trust Network Access controls

### Advanced Reporting

Generate detailed reports in multiple formats:
- Interactive HTML dashboards with compliance scoring
- Excel reports with filtering and drill-down capabilities
- CSV export for data analysis
- JSON output for integration with other tools

![Dashboard Example](https://raw.githubusercontent.com/DataGuys/ConditionalAccess/main/assets/dashboard-example.png)

### Industry Benchmark Compliance

Evaluate your Conditional Access configuration against industry standards:
- NIST SP 800-53
- CIS Controls
- Microsoft MCRA (Microsoft Cybersecurity Reference Architecture)
- ISO 27001
- PCI DSS
- HIPAA

### Automated Remediation

The module can automatically remediate identified issues by creating or updating policies according to security best practices:

```powershell
# Remediate all identified issues
Invoke-CAComplianceRemediation -RemediateAll

# Create policies in report-only mode
Invoke-CAComplianceRemediation -RemediateAll -DeployInReportOnlyMode

# Remediate specific issues
Invoke-CAComplianceRemediation -IncludeAdminMFA -IncludeUserMFA
```

### Policy Templates

Generate best practice policy templates that administrators can use to implement security improvements:

```powershell
# Create an admin MFA policy template
New-CABestPracticePolicy -PolicyType AdminMFA

# Create a comprehensive set of Zero Trust baseline policies
New-CABestPracticePolicy -PolicyType ZeroTrustBase

# Create and deploy a policy requiring device compliance
New-CABestPracticePolicy -PolicyType DeviceCompliance -DeployPolicy

# Create NIST SP 800-63 Digital Identity Guidelines compliant policies
New-CABestPracticePolicy -PolicyType NIST80063 -DeployPolicy -State "enabledForReportingButNotEnforced"
```

## Command Reference

### Core Assessment Commands

#### Connect-CAAnalyzer
Connects to Microsoft Graph with the required permissions for Conditional Access analysis.

```powershell
# Interactive authentication
Connect-CAAnalyzer

# Certificate-based authentication
Connect-CAAnalyzer -AuthMethod CertificateThumbprint -TenantId "00000000-0000-0000-0000-000000000000" -ClientId "11111111-1111-1111-1111-111111111111" -CertificateThumbprint "ABCDEF1234567890ABCDEF1234567890ABCDEF12"

# Connect to US Government cloud
Connect-CAAnalyzer -National USGov
```

#### Invoke-CAComplianceCheck
Performs a comprehensive Conditional Access compliance check.

```powershell
# Run a basic compliance check
Invoke-CAComplianceCheck

# Run a detailed compliance check and store results for further analysis
$results = Invoke-CAComplianceCheck
```

#### Export-CAComplianceReport
Exports a Conditional Access compliance report in various formats.

```powershell
# Export as HTML and open in browser
Export-CAComplianceReport -Format HTML -Path "C:\Reports\CAReport.html" -OpenReport

# Export previous check results as JSON
$results = Invoke-CAComplianceCheck
Export-CAComplianceReport -Results $results -Format JSON -Path "C:\Reports\CAReport.json"

# Export as Excel with detailed recommendations
Export-CAComplianceReport -Format Excel -Path "C:\Reports\CAReport.xlsx" -IncludeRecommendations
```

### Analysis Commands

#### Get-CAPoliciesSummary
Gets a comprehensive summary of all Conditional Access policies.

```powershell
# Get summary of enabled policies
Get-CAPoliciesSummary

# Include disabled policies in analysis
Get-CAPoliciesSummary -IncludeDisabled

# Include named location details
Get-CAPoliciesSummary -IncludeNamedLocations
```

#### Test-AdminMFARequired
Checks if MFA is required for administrators.

```powershell
Test-AdminMFARequired
```

#### Test-UserMFARequired
Checks if MFA is required for regular users.

```powershell
Test-UserMFARequired
```

#### Test-DeviceComplianceRequired
Checks if device compliance is required for resource access.

```powershell
Test-DeviceComplianceRequired
```

#### Test-TokenSessionBinding
Checks if token session binding to devices is configured.

```powershell
Test-TokenSessionBinding
```

#### Test-RiskBasedPolicies
Checks if risk-based Conditional Access policies are configured.

```powershell
Test-RiskBasedPolicies
```

#### Test-MAMPolicies
Checks if Mobile Application Management policies are configured.

```powershell
Test-MAMPolicies
```

#### Test-ZeroTrustNetwork
Checks if Zero Trust Network Access components are configured.

```powershell
Test-ZeroTrustNetwork
```

### Benchmark Evaluation Commands

#### Test-CASecurityBenchmark
Evaluates Conditional Access policies against industry security benchmarks.

```powershell
# Test against NIST SP 800-53
Test-CASecurityBenchmark -BenchmarkName NIST

# Test against all supported benchmarks with detailed output
Test-CASecurityBenchmark -BenchmarkName All -IncludeDetails

# Save benchmark results to HTML report
Test-CASecurityBenchmark -BenchmarkName CIS -OutputPath "C:\Reports\CISBenchmark.html"
```

#### Export-CAComplianceDashboard
Exports a comprehensive Conditional Access compliance dashboard.

```powershell
# Generate a basic dashboard
Export-CAComplianceDashboard -OutputPath "C:\Reports\CADashboard.html" -OpenDashboard

# Include benchmark evaluations
Export-CAComplianceDashboard -IncludeBenchmarks -OutputPath "C:\Reports\CADashboard.html"

# Include detailed remediation recommendations
Export-CAComplianceDashboard -IncludeRemediation -CompanyName "Contoso" -OutputPath "C:\Reports\CADashboard.html"
```

### Remediation Commands

#### Invoke-CAComplianceRemediation
Automatically remediates Conditional Access compliance issues.

```powershell
# Remediate all identified issues
Invoke-CAComplianceRemediation -RemediateAll

# Create policies in report-only mode
Invoke-CAComplianceRemediation -RemediateAll -DeployInReportOnlyMode

# Remediate specific issues
Invoke-CAComplianceRemediation -IncludeAdminMFA -IncludeUserMFA

# Exclude specific users from remediated policies
Invoke-CAComplianceRemediation -RemediateAll -ExcludeUsers "emergency@contoso.com"
```

#### Set-CAEmergencyAccess
Configures emergency access exclusions for Conditional Access policies.

```powershell
# Add emergency access account exclusions to all enabled policies
Set-CAEmergencyAccess

# Add specific emergency users to specific policies
Set-CAEmergencyAccess -PolicyIds "00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111" -EmergencyUsers "emergency@contoso.com", "breakglass@contoso.com"
```

#### Set-CAStaggeredRollout
Configures a staged rollout plan for Conditional Access policies.

```powershell
# Setup staged MFA rollout across pilot and department groups
$pilotGroup = (Get-MgGroup -Filter "displayName eq 'Pilot Users'").Id
$phase1Group = (Get-MgGroup -Filter "displayName eq 'Sales'").Id
$phase2Group = (Get-MgGroup -Filter "displayName eq 'Marketing'").Id
Set-CAStaggeredRollout -PolicyType UserMFA -StagingGroups $pilotGroup, $phase1Group, $phase2Group -StagingDays 14
```

### Policy Template Commands

#### New-CABestPracticePolicy
Creates Conditional Access policy templates based on security best practices.

```powershell
# Create admin MFA policy template
New-CABestPracticePolicy -PolicyType AdminMFA

# Create and deploy user MFA policy
New-CABestPracticePolicy -PolicyType UserMFA -DeployPolicy

# Create device compliance policy in report-only mode
New-CABestPracticePolicy -PolicyType DeviceCompliance -DeployPolicy -State "enabledForReportingButNotEnforced"

# Create NIST-compliant policies
New-CABestPracticePolicy -PolicyType NIST80063 -DeployPolicy

# Create comprehensive Zero Trust baseline
New-CABestPracticePolicy -PolicyType ZeroTrustBase -DeployPolicy
```

## Requirements

- PowerShell 5.1 or higher (PowerShell Core 7.x supported)
- The following Microsoft Graph PowerShell modules:
  - Microsoft.Graph.Authentication (1.20.0+)
  - Microsoft.Graph.Identity.SignIns (1.20.0+)
  - Microsoft.Graph.Identity.DirectoryManagement (1.20.0+)
  - Microsoft.Graph.DeviceManagement (1.20.0+)
- Appropriate permissions in your Entra ID tenant:
  - Policy.Read.All (required for assessment)
  - Policy.ReadWrite.ConditionalAccess (required for remediation)
  - Directory.Read.All (required for all functions)
  - DeviceManagementConfiguration.Read.All (required for device compliance checks)
  - DeviceManagementApps.Read.All (required for MAM policy checks)
  - IdentityRiskyUser.Read.All (required for risk-based policy checks)

## Best Practices

### Zero Trust Implementation Stages

The module supports a phased approach to Zero Trust implementation:

1. **Assessment Phase**
   - Run `Invoke-CAComplianceCheck` to identify gaps
   - Generate reports with `Export-CAComplianceReport`
   - Evaluate against benchmarks with `Test-CASecurityBenchmark`

2. **Planning Phase**
   - Generate policy templates with `New-CABestPracticePolicy`
   - Design staged rollout with `Set-CAStaggeredRollout`
   - Configure emergency access with `Set-CAEmergencyAccess`

3. **Implementation Phase**
   - Deploy report-only policies to validate impact
   - Use gradual enforcement on pilot groups
   - Monitor and adjust policies as needed

4. **Maintenance Phase**
   - Regular reassessment with `Invoke-CAComplianceCheck`
   - Update policies to address new security requirements
   - Validate against updated benchmarks

### Recommended Policy Sequence

When implementing Conditional Access policies from scratch, follow this recommended sequence:

1. **Emergency Access Protection**
   - Configure break-glass accounts
   - Exclude from policies with `Set-CAEmergencyAccess`

2. **Admin Protection**
   - Require MFA for all administrative roles
   - Implement session controls for privileged accounts

3. **Identity Baseline**
   - Implement MFA for all users
   - Configure risk-based policies

4. **Device Trust**
   - Require compliant devices
   - Configure platform-specific policies

5. **Zero Trust Network**
   - Set up Microsoft Defender for Cloud Apps integration
   - Configure Global Secure Access

## Troubleshooting

### Common Issues and Solutions

1. **Connection Problems**
   - Ensure Microsoft Graph modules are up to date
   - Verify you have the required permissions
   - For MFA-enabled accounts, complete the authentication prompt

2. **Module Import Issues**
   - Try importing directly from GitHub:
     ```powershell
     Import-Module (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/DataGuys/ConditionalAccess/refs/heads/main/ConditionalAccessAnalyzer.psm1" -UseBasicParsing).Content
     ```

3. **Permission Errors**
   - Ensure your account has the required permissions
   - Use `Connect-CAAnalyzer -ShowConnectionDetails` to verify scopes

4. **Report Generation Fails**
   - Check available disk space
   - Ensure you have write permissions to the destination folder
   - Try a different format (CSV instead of HTML)

5. **Remediation Fails**
   - Check for the Policy.ReadWrite.ConditionalAccess permission
   - Verify you have sufficient privileges in the tenant
   - Ensure you have appropriate administrative role

## Advanced Usage

### Integration with Other Tools

The module can be integrated with other security and identity management workflows:

1. **Azure DevOps Pipelines**
   - Include in CI/CD pipelines for policy validation
   - Generate reports as build artifacts
   - Use benchmark tests as quality gates

2. **PowerBI Dashboards**
   - Export to CSV and import into PowerBI
   - Create trend analysis dashboards
   - Monitor compliance scores over time

3. **Security Information and Event Management (SIEM)**
   - Export assessment results for security monitoring
   - Generate alerts for compliance violations
   - Correlate with other security telemetry

### Customizing Policies and Reports

Customize the module's behavior to fit your organization's needs:

1. **Custom Policy Templates**
   - Modify existing templates with organization-specific settings
   - Add conditional parameters for different environments
   - Create custom evaluation criteria

2. **Branded Reports**
   - Add company logo to reports
   - Customize colors and styling
   - Add executive summaries or custom sections

3. **Extended Evaluations**
   - Add custom benchmark definitions
   - Create specialized tests for regulated industries
   - Implement organizational policy baselines

## Contributing

We welcome contributions to improve the Conditional Access Analyzer. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

© 2025 DataGuys. All rights reserved.
