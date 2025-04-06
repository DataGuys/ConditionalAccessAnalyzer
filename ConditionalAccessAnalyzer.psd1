@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'ConditionalAccessAnalyzer.psm1'
    
    # Version number of this module.
    ModuleVersion = '1.0.0'
    
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
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Connect-CAAnalyzer',
        'Disconnect-CAAnalyzer',
        'Test-CAAnalyzerConnection',
        'Invoke-CAComplianceCheck',
        'Export-CAComplianceReport',
        'Get-CAPoliciesSummary',
        'Test-AdminMFARequired',
        'Test-UserMFARequired',
        'Test-DeviceComplianceRequired',
        'Test-TokenSessionBinding',
        'Test-RiskBasedPolicies',
        'Test-MAMPolicies',
        'Test-ZeroTrustNetwork',
        'Invoke-CAComplianceRemediation',
        'Set-CAEmergencyAccess',
        'Set-CAStaggeredRollout',
        'New-CABestPracticePolicy',
        'Test-CASecurityBenchmark',
        'Export-CAComplianceDashboard'
    )
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('EntraID', 'AzureAD', 'ConditionalAccess', 'Security', 'ZeroTrust', 'Identity')
            
            # A URL to the license for this module.
            LicenseUri = 'https://github.com/DataGuys/ConditionalAccess/blob/main/LICENSE'
            
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/DataGuys/ConditionalAccess'
            
            # A URL to an icon representing this module.
            IconUri = 'https://raw.githubusercontent.com/DataGuys/ConditionalAccess/main/assets/logo.png'
            
            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release of Conditional Access Analyzer'
        }
    }
}
