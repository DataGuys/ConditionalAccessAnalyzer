@{
    # Script module or binary module file associated with this manifest
    RootModule = 'ConditionalAccessAnalyzer.psm1'
    
    # Version number of this module (format: major.minor.build.revision)
    ModuleVersion = '1.1.0'
    
    # ID used to uniquely identify this module
    GUID = '48b10e1c-2a42-4b73-8f85-d9a8f6e3a2d9'
    
    # Author of this module
    Author = 'Gregory Hall'
    
    # Company or vendor of this module
    CompanyName = 'DataGuys'
    
    # Copyright statement for this module
    Copyright = '(c) 2025 Gregory Hall. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'A comprehensive PowerShell module for analyzing, assessing, and remediating Conditional Access policies in Microsoft Entra ID (formerly Azure AD).'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{
            ModuleName = 'Microsoft.Graph.Authentication'
            ModuleVersion = '1.20.0'
        },
        @{
            ModuleName = 'Microsoft.Graph.Identity.SignIns'
            ModuleVersion = '1.20.0'
        },
        @{
            ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'
            ModuleVersion = '1.20.0'
        },
        @{
            ModuleName = 'Microsoft.Graph.DeviceManagement'
            ModuleVersion = '1.20.0'
        }
    )
    
    # Functions to export from this module
    FunctionsToExport = @(
        # Connection functions
        'Connect-CAAnalyzer',
        'Disconnect-CAAnalyzer',
        'Test-CAAnalyzerConnection',
        
        # Analysis functions
        'Invoke-CAComplianceCheck',
        'Get-CAPoliciesSummary',
        'Test-AdminMFARequired',
        'Test-UserMFARequired',
        'Test-DeviceComplianceRequired',
        'Test-TokenSessionBinding',
        'Test-RiskBasedPolicies',
        'Test-MAMPolicies',
        'Test-ZeroTrustNetwork',
        
        # Reporting functions
        'Export-CAComplianceReport',
        'Export-CAComplianceDashboard',
        
        # Remediation functions
        'Invoke-CAComplianceRemediation',
        'Set-CAEmergencyAccess',
        'Set-CAStaggeredRollout',
        'New-CABestPracticePolicy',
        
        # Benchmark functions
        'Test-CASecurityBenchmark',
        'Test-CISBenchmark',
        'Test-NISTBenchmark'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('ConditionalAccess', 'Security', 'EntraID', 'AzureAD', 'MicrosoftGraph', 'ZeroTrust')
            
            # A URL to the license for this module
            LicenseUri = 'https://github.com/DataGuys/ConditionalAccessAnalyzer/blob/main/LICENSE'
            
            # A URL to the main website for this project
            ProjectUri = 'https://github.com/DataGuys/ConditionalAccessAnalyzer'
            
            # ReleaseNotes of this module
            ReleaseNotes = @'
## 1.1.0
- Added support for Azure Cloud Shell
- Improved cross-platform compatibility
- Added template deployment utility
- Enhanced benchmark assessments

## 1.0.0 
- Initial release with core functionality
- Support for compliance checks and remediation
- NIST and CIS benchmark evaluations
'@
        }
    }
}
