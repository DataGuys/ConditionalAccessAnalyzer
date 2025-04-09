# Analysis.ps1 - Core analysis functions for Conditional Access Analyzer

function Invoke-CAComplianceCheck {
    <#
    .SYNOPSIS
        Runs a comprehensive compliance check on Conditional Access policies.
    .DESCRIPTION
        Analyzes all Conditional Access policies against best practices and security benchmarks,
        providing a comprehensive assessment of security posture and remediation recommendations.
    .PARAMETER IncludeDisabled
        If specified, disabled policies are included in the analysis.
    .PARAMETER IncludeBenchmarks
        If specified, includes benchmark assessments (NIST, CIS) in the results.
    .PARAMETER IncludeRemediation
        If specified, generates remediation recommendations as part of the results.
    .PARAMETER BenchmarkNames
        The security benchmarks to evaluate against. Default is 'All'.
    .PARAMETER TenantId
        If specified, restricts analysis to this specific tenant.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisabled,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeBenchmarks,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRemediation,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('NIST', 'CIS', 'All')]
        [string]$BenchmarkNames = 'All',
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        Write-CALog -Message "Starting comprehensive Conditional Access compliance check" -Level "Info"
        
        # Function to calculate the overall compliance score
        function Calculate-ComplianceScore {
            param (
                [hashtable]$Checks
            )
            
            $scoreCollection = [CAComplianceScoreCollection]::new()
            
            # Add scores for each check category
            if ($Checks.AdminMFA) {
                $scoreCollection.AddScore(
                    "Admin MFA", 
                    [int]$Checks.AdminMFA.AdminMFARequired * 100,
                    "MFA for administrative roles", 
                    $true
                )
            }
            
            if ($Checks.UserMFA) {
                $scoreCollection.AddScore(
                    "User MFA", 
                    [int]$Checks.UserMFA.BroadUserMFARequired * 100,
                    "MFA for regular users", 
                    $true
                )
            }
            
            if ($Checks.DeviceCompliance) {
                $scoreCollection.AddScore(
                    "Device Compliance", 
                    [int]$Checks.DeviceCompliance.BroadDeviceComplianceRequired * 100,
                    "Device compliance requirements"
                )
            }
            
            if ($Checks.TokenBinding) {
                $scoreCollection.AddScore(
                    "Token Binding", 
                    [int]$Checks.TokenBinding.TokenSessionBindingConfigured * 100,
                    "Token session controls"
                )
            }
            
            if ($Checks.RiskPolicies) {
                $scoreCollection.AddScore(
                    "Sign-in Risk", 
                    [int]$Checks.RiskPolicies.SignInRiskPoliciesConfigured * 100,
                    "Sign-in risk-based policies"
                )
                
                $scoreCollection.AddScore(
                    "User Risk", 
                    [int]$Checks.RiskPolicies.UserRiskPoliciesConfigured * 100,
                    "User risk-based policies"
                )
            }
            
            if ($Checks.MAMPolicies) {
                $scoreCollection.AddScore(
                    "MAM Policies", 
                    [int]$Checks.MAMPolicies.MAMPoliciesConfigured * 100,
                    "Mobile application management"
                )
            }
            
            if ($Checks.ZeroTrust) {
                $scoreCollection.AddScore(
                    "MDCA Integration", 
                    [int]$Checks.ZeroTrust.MDCAIntegrated * 100,
                    "Microsoft Defender for Cloud Apps integration"
                )
                
                $scoreCollection.AddScore(
                    "Global Secure Access", 
                    [int]$Checks.ZeroTrust.GlobalSecureAccessConfigured * 100,
                    "Zero Trust Network Access"
                )
            }
            
            # Return the overall score
            return $scoreCollection.OverallScore
        }
    }
    
    process {
        try {
            # Get all policies
            $parameters = @{}
            if ($TenantId) {
                $parameters['TenantId'] = $TenantId
            }
            
            $allPolicies = Get-MgIdentityConditionalAccessPolicy @parameters
            
            # Filter policies if needed
            $policies = if (-not $IncludeDisabled) {
                $allPolicies | Where-Object { $_.State -ne "disabled" }
            } else {
                $allPolicies
            }
            
            Write-CALog -Message "Retrieved $($policies.Count) Conditional Access policies for analysis" -Level "Info"
            
            # Run all compliance checks
            $checks = @{}
            
            # Admin MFA check
            Write-Host "Checking Admin MFA requirement..." -ForegroundColor Yellow
            $adminMfa = Test-AdminMFARequired
            $checks["AdminMFA"] = $adminMfa
            
            # User MFA check
            Write-Host "Checking User MFA requirement..." -ForegroundColor Yellow
            $userMfa = Test-UserMFARequired
            $checks["UserMFA"] = $userMfa
            
            # Device compliance check
            Write-Host "Checking Device Compliance requirement..." -ForegroundColor Yellow
            $deviceCompliance = Test-DeviceComplianceRequired
            $checks["DeviceCompliance"] = $deviceCompliance
            
            # Token binding check
            Write-Host "Checking Token Session Binding..." -ForegroundColor Yellow
            $tokenBinding = Test-TokenSessionBinding
            $checks["TokenBinding"] = $tokenBinding
            
            # Risk-based policies check
            Write-Host "Checking Risk-Based Policies..." -ForegroundColor Yellow
            $riskPolicies = Test-RiskBasedPolicies
            $checks["RiskPolicies"] = $riskPolicies
            
            # MAM policies check
            Write-Host "Checking Mobile Application Management Policies..." -ForegroundColor Yellow
            $mamPolicies = Test-MAMPolicies
            $checks["MAMPolicies"] = $mamPolicies
            
            # Zero Trust network check
            Write-Host "Checking Zero Trust Network Controls..." -ForegroundColor Yellow
            $zeroTrust = Test-ZeroTrustNetwork
            $checks["ZeroTrust"] = $zeroTrust
            
            # Calculate compliance score
            $complianceScore = Calculate-ComplianceScore -Checks $checks
            
            # Run benchmark checks if requested
            $benchmarks = @{}
            if ($IncludeBenchmarks) {
                if ($BenchmarkNames -eq 'All' -or $BenchmarkNames -eq 'NIST') {
                    Write-Host "Evaluating against NIST SP 800-53 controls..." -ForegroundColor Yellow
                    $nistResults = Test-NISTBenchmark -Policies $policies
                    $benchmarks["NIST"] = $nistResults
                }
                
                if ($BenchmarkNames -eq 'All' -or $BenchmarkNames -eq 'CIS') {
                    Write-Host "Evaluating against CIS Controls..." -ForegroundColor Yellow
                    $cisResults = Test-CISBenchmark -Policies $policies
                    $benchmarks["CIS"] = $cisResults
                }
            }
            
            # Generate remediation recommendations if requested
            $remediation = $null
            if ($IncludeRemediation) {
                Write-Host "Generating remediation recommendations..." -ForegroundColor Yellow
                $remediation = @{
                    RequiresAdminMFA = -not $adminMfa.AdminMFARequired
                    RequiresUserMFA = -not $userMfa.BroadUserMFARequired
                    RequiresDeviceCompliance = -not $deviceCompliance.BroadDeviceComplianceRequired
                    RequiresTokenBinding = -not $tokenBinding.TokenSessionBindingConfigured
                    RequiresRiskPolicies = -not ($riskPolicies.SignInRiskPoliciesConfigured -and $riskPolicies.UserRiskPoliciesConfigured)
                    RequiresMAMPolicies = -not $mamPolicies.MAMPoliciesConfigured
                    RequiresZeroTrust = -not ($zeroTrust.MDCAIntegrated -and $zeroTrust.GlobalSecureAccessConfigured)
                    Recommendations = @()
                }
                
                # Add recommendations based on failed checks
                if (-not $adminMfa.AdminMFARequired) {
                    $remediation.Recommendations += "Implement MFA for all administrative roles to protect privileged accounts"
                }
                
                if (-not $userMfa.BroadUserMFARequired) {
                    $remediation.Recommendations += "Implement MFA for all users to protect against credential compromise"
                }
                
                if (-not $deviceCompliance.BroadDeviceComplianceRequired) {
                    $remediation.Recommendations += "Require device compliance for better endpoint security"
                }
                
                if (-not $tokenBinding.TokenSessionBindingConfigured) {
                    $remediation.Recommendations += "Configure token session binding to limit session persistence and improve security"
                }
                
                if (-not $riskPolicies.SignInRiskPoliciesConfigured) {
                    $remediation.Recommendations += "Implement sign-in risk-based policies to protect against suspicious sign-in attempts"
                }
                
                if (-not $riskPolicies.UserRiskPoliciesConfigured) {
                    $remediation.Recommendations += "Implement user risk-based policies to protect compromised accounts"
                }
                
                if (-not $mamPolicies.MAMPoliciesConfigured) {
                    $remediation.Recommendations += "Configure mobile application management policies to protect data on mobile devices"
                }
                
                if (-not $zeroTrust.MDCAIntegrated) {
                    $remediation.Recommendations += "Integrate Microsoft Defender for Cloud Apps with Conditional Access"
                }
                
                if (-not $zeroTrust.GlobalSecureAccessConfigured) {
                    $remediation.Recommendations += "Configure Global Secure Access for Zero Trust Network Access"
                }
            }
            
            # Create the result object
            $result = [PSCustomObject]@{
                TenantId = (Get-MgContext).TenantId
                TenantName = (Get-MgContext).TenantId  # Ideally, get the actual tenant name
                GeneratedDate = Get-Date
                ComplianceScore = $complianceScore
                Checks = $checks
                PolicyCount = $policies.Count
                EnabledPolicyCount = ($policies | Where-Object { $_.State -eq "enabled" }).Count
                ReportOnlyPolicyCount = ($policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }).Count
                DisabledPolicyCount = ($policies | Where-Object { $_.State -eq "disabled" }).Count
            }
            
            # Add benchmarks if included
            if ($IncludeBenchmarks) {
                $result | Add-Member -MemberType NoteProperty -Name "Benchmarks" -Value $benchmarks
            }
            
            # Add remediation if included
            if ($IncludeRemediation) {
                $result | Add-Member -MemberType NoteProperty -Name "Remediation" -Value $remediation
            }
            
            # Display a summary of the results
            Write-Host "`nCompliance Check Complete" -ForegroundColor Cyan
            Write-Host "Compliance Score: $($result.ComplianceScore)%" -ForegroundColor $(
                if ($result.ComplianceScore -ge 90) { "Green" }
                elseif ($result.ComplianceScore -ge 70) { "Yellow" }
                else { "Red" }
            )
            
            Write-Host "Policy Count: $($result.PolicyCount) ($($result.EnabledPolicyCount) enabled, $($result.ReportOnlyPolicyCount) report-only, $($result.DisabledPolicyCount) disabled)" -ForegroundColor White
            
            # Return the result object
            return $result
        }
        catch {
            Write-CALog -Message "Error during compliance check: $_" -Level "Error"
            throw "Failed to complete compliance check: $_"
        }
    }
}

function Get-CAPoliciesSummary {
    <#
    .SYNOPSIS
        Gets a comprehensive summary of all Conditional Access policies.
    .DESCRIPTION
        Retrieves all Conditional Access policies and provides an enhanced analysis
        of their state, configuration, and coverage.
    .PARAMETER IncludeDisabled
        If specified, disabled policies are included in the analysis.
    .PARAMETER PolicyIds
        Specific policy IDs to analyze. If not specified, all policies are analyzed.
    .PARAMETER IncludeNamedLocations
        If specified, named location details are included in the analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisabled,
        
        [Parameter(Mandatory = $false)]
        [string[]]$PolicyIds,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNamedLocations
    )
    
    begin {
        Write-Verbose "Starting comprehensive Conditional Access policy analysis"
        
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # Helper function to convert user/group/role IDs to names
        function Get-DirectoryObjectName {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Id,
                
                [Parameter(Mandatory = $false)]
                [ValidateSet('User', 'Group', 'Role', 'Application')]
                [string]$Type = 'User'
            )
            
            try {
                switch ($Type) {
                    'User' {
                        if ($Id -eq 'All') { return 'All users' }
                        if ($Id -eq 'GuestsOrExternalUsers') { return 'Guests' }
                        if ($Id -eq 'None') { return 'No users' }
                        
                        $user = Get-MgUser -UserId $Id -ErrorAction SilentlyContinue
                        if ($user) {
                            return $user.DisplayName
                        }
                    }
                    'Group' {
                        $group = Get-MgGroup -GroupId $Id -ErrorAction SilentlyContinue
                        if ($group) {
                            return $group.DisplayName
                        }
                    }
                    'Role' {
                        $role = Get-MgDirectoryRole -DirectoryRoleId $Id -ErrorAction SilentlyContinue
                        if (-not $role) {
                            $template = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $Id -ErrorAction SilentlyContinue
                            if ($template) {
                                return $template.DisplayName
                            }
                        }
                        else {
                            return $role.DisplayName
                        }
                    }
                    'Application' {
                        if ($Id -eq 'All') { return 'All applications' }
                        if ($Id -eq 'Office365') { return 'Microsoft 365' }
                        
                        $app = Get-MgServicePrincipal -ServicePrincipalId $Id -ErrorAction SilentlyContinue
                        if ($app) {
                            return $app.DisplayName
                        }
                    }
                }
                
                return $Id  # Return the ID if name lookup fails
            }
            catch {
                Write-Warning "Failed to get name for $Type with ID $Id ${_}"
                return $Id
            }
        }
    }
    
    process {
        try {
            # Get named locations if requested
            $namedLocations = @{}
            if ($IncludeNamedLocations) {
                Write-Verbose "Retrieving named locations"
                try {
                    $locations = Get-MgIdentityConditionalAccessNamedLocation -ErrorAction Stop
                    foreach ($location in $locations) {
                        $namedLocations[$location.Id] = $location
                    }
                    Write-Verbose "Retrieved $($locations.Count) named locations"
                }
                catch {
                    Write-Warning "Failed to retrieve named locations: $_"
                }
            }
            
            # Get all policies
            Write-Verbose "Retrieving Conditional Access policies"
            $allPolicies = @()
            
            if ($PolicyIds) {
                foreach ($id in $PolicyIds) {
                    $policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id -ErrorAction SilentlyContinue
                    if ($policy) {
                        $allPolicies += $policy
                    }
                    else {
                        Write-Warning "Policy with ID $id not found"
                    }
                }
            }
            else {
                $allPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
            }
            
            Write-Verbose "Retrieved $($allPolicies.Count) policies"
            
            # Filter policies if needed
            $policies = if (-not $IncludeDisabled) {
                $allPolicies | Where-Object { $_.State -eq "enabled" }
            }
            else {
                $allPolicies
            }
            
            Write-Verbose "Analyzing $($policies.Count) policies"
            
            # Process policies and generate enhanced objects
            $enhancedPolicies = @()
            foreach ($policy in $policies) {
                # Process policy into enhanced object with lookups for names
                # (Implementation details omitted for brevity)
                
                $enhancedPolicy = [PSCustomObject]@{
                    Id = $policy.Id
                    DisplayName = $policy.DisplayName
                    State = $policy.State
                    CreatedDateTime = $policy.CreatedDateTime
                    ModifiedDateTime = $policy.ModifiedDateTime
                    # Add more properties based on policy analysis
                }
                
                $enhancedPolicies += $enhancedPolicy
            }
            
            return $enhancedPolicies
        }
        catch {
            Write-Error "Failed to retrieve and analyze Conditional Access policies: $_"
            throw
        }
    }
}

# Individual test functions
function Test-AdminMFARequired {
    [CmdletBinding()]
    param()
    
    process {
        $adminRoles = Get-AdminRoles -PrivilegedOnly
        $adminRoleIds = $adminRoles.Id
        
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $adminMfaPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyRequiresMFA -Policy $_) -and
            (Test-PolicyTargetsAdmins -Policy $_ -AdminRoleIds $adminRoleIds)
        }
        
        $isCompliant = $adminMfaPolicies.Count -gt 0
        
        return [PSCustomObject]@{
            AdminMFARequired = $isCompliant
            AdminMFAPolicies = $adminMfaPolicies
            Recommendation = if (-not $isCompliant) {
                "Configure Conditional Access policies requiring MFA for all administrative roles"
            } else {
                $null
            }
        }
    }
}

function Test-UserMFARequired {
    [CmdletBinding()]
    param()
    
    process {
        # Implementation details
        return [PSCustomObject]@{
            BroadUserMFARequired = $false # Placeholder - real implementation would evaluate policies
            UserMFAPolicies = @()
            Recommendation = "Configure Conditional Access policies requiring MFA for all users"
        }
    }
}

function Test-DeviceComplianceRequired {
    [CmdletBinding()]
    param()
    
    process {
        # Implementation details
        return [PSCustomObject]@{
            BroadDeviceComplianceRequired = $false # Placeholder
            DeviceCompliancePolicies = @()
            Recommendation = "Configure Conditional Access policies requiring device compliance"
        }
    }
}

function Test-TokenSessionBinding {
    [CmdletBinding()]
    param()
    
    process {
        # Implementation details
        return [PSCustomObject]@{
            TokenSessionBindingConfigured = $false # Placeholder
            TokenBindingPolicies = @()
            Recommendation = "Configure Conditional Access policies with session controls for sign-in frequency"
        }
    }
}

function Test-RiskBasedPolicies {
    [CmdletBinding()]
    param()
    
    process {
        # Implementation details
        return [PSCustomObject]@{
            SignInRiskPoliciesConfigured = $false # Placeholder
            UserRiskPoliciesConfigured = $false # Placeholder
            SignInRiskPolicies = @()
            UserRiskPolicies = @()
            Recommendation = "Configure risk-based Conditional Access policies"
        }
    }
}

function Test-MAMPolicies {
    [CmdletBinding()]
    param()
    
    process {
        # Implementation details
        return [PSCustomObject]@{
            MAMPoliciesConfigured = $false # Placeholder
            MAMPolicies = @()
            Recommendation = "Configure Conditional Access policies requiring approved or compliant applications"
        }
    }
}

function Test-ZeroTrustNetwork {
    [CmdletBinding()]
    param()
    
    process {
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $mdcaPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyHasSessionControls -Policy $_ -ControlType "CloudAppSecurity")
        }
        
        $gsaPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            ($_.DisplayName -like "*Global Secure Access*" -or $_.DisplayName -like "*Zero Trust*")
        }
        
        $mdcaIntegrated = $mdcaPolicies.Count -gt 0
        $gsaConfigured = $gsaPolicies.Count -gt 0
        
        return [PSCustomObject]@{
            MDCAIntegrated = $mdcaIntegrated
            GlobalSecureAccessConfigured = $gsaConfigured
            MDCAPolicies = $mdcaPolicies
            GSAPolicies = $gsaPolicies
            Recommendation = if (-not ($mdcaIntegrated -and $gsaConfigured)) {
                "Configure Zero Trust Network Access controls through MDCA integration and Global Secure Access"
            } else {
                $null
            }
        }
    }
}
