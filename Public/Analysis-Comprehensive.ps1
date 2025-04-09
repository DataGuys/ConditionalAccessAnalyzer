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
    .EXAMPLE
        Invoke-CAComplianceCheck
        Runs a basic compliance check on all enabled policies.
    .EXAMPLE
        Invoke-CAComplianceCheck -IncludeBenchmarks -IncludeRemediation
        Runs a comprehensive compliance check with benchmark evaluations and remediation recommendations.
    .NOTES
        This function requires an active connection to Microsoft Graph with the appropriate permissions.
        Use Connect-CAAnalyzer before running this function.
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

function Test-UserMFARequired {
    [CmdletBinding()]
    param()
    
    process {
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $userMfaPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyRequiresMFA -Policy $_) -and
            (
                ($_.Conditions.Users.IncludeUsers -contains "All") -or
                ($_.Conditions.Applications.IncludeApplications -contains "All") -or
                ($_.Conditions.Applications.IncludeApplications -contains "Office365")
            ) -and
            (-not (Test-PolicyTargetsAdmins -Policy $_))
        }
        
        $isCompliant = $userMfaPolicies.Count -gt 0
        
        return [PSCustomObject]@{
            BroadUserMFARequired = $isCompliant
            UserMFAPolicies = $userMfaPolicies
            Recommendation = if (-not $isCompliant) {
                "Configure Conditional Access policies requiring MFA for all users"
            } else {
                $null
            }
        }
    }
}

function Test-DeviceComplianceRequired {
    [CmdletBinding()]
    param()
    
    process {
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $deviceCompliancePolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyRequiresCompliantDevice -Policy $_) -and
            (
                ($_.Conditions.Users.IncludeUsers -contains "All") -or
                ($_.Conditions.Applications.IncludeApplications -contains "All") -or
                ($_.Conditions.Applications.IncludeApplications -contains "Office365")
            )
        }
        
        $isCompliant = $deviceCompliancePolicies.Count -gt 0
        
        return [PSCustomObject]@{
            BroadDeviceComplianceRequired = $isCompliant
            DeviceCompliancePolicies = $deviceCompliancePolicies
            Recommendation = if (-not $isCompliant) {
                "Configure Conditional Access policies requiring device compliance"
            } else {
                $null
            }
        }
    }
}

function Test-TokenSessionBinding {
    [CmdletBinding()]
    param()
    
    process {
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $tokenBindingPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyHasSessionControls -Policy $_ -ControlType "SignInFrequency") -and
            (
                ($_.Conditions.Users.IncludeUsers -contains "All") -or
                ($_.Conditions.Applications.IncludeApplications -contains "All") -or
                ($_.Conditions.Applications.IncludeApplications -contains "Office365")
            )
        }
        
        $isCompliant = $tokenBindingPolicies.Count -gt 0
        
        return [PSCustomObject]@{
            TokenSessionBindingConfigured = $isCompliant
            TokenBindingPolicies = $tokenBindingPolicies
            Recommendation = if (-not $isCompliant) {
                "Configure Conditional Access policies with session controls for sign-in frequency"
            } else {
                $null
            }
        }
    }
}

function Test-RiskBasedPolicies {
    [CmdletBinding()]
    param()
    
    process {
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $signInRiskPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "SignIn")
        }
        
        $userRiskPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "User")
        }
        
        $signInRiskConfigured = $signInRiskPolicies.Count -gt 0
        $userRiskConfigured = $userRiskPolicies.Count -gt 0
        
        return [PSCustomObject]@{
            SignInRiskPoliciesConfigured = $signInRiskConfigured
            UserRiskPoliciesConfigured = $userRiskConfigured
            SignInRiskPolicies = $signInRiskPolicies
            UserRiskPolicies = $userRiskPolicies
            Recommendation = if (-not ($signInRiskConfigured -and $userRiskConfigured)) {
                "Configure risk-based Conditional Access policies to protect against suspicious sign-ins and compromised accounts"
            } else {
                $null
            }
        }
    }
}

function Test-MAMPolicies {
    [CmdletBinding()]
    param()
    
    process {
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $mamPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            ($null -ne $_.GrantControls.BuiltInControls) -and
            (
                ($_.GrantControls.BuiltInControls -contains "compliantApplication") -or
                ($_.GrantControls.BuiltInControls -contains "approvedApplication")
            )
        }
        
        $isCompliant = $mamPolicies.Count -gt 0
        
        return [PSCustomObject]@{
            MAMPoliciesConfigured = $isCompliant
            MAMPolicies = $mamPolicies
            Recommendation = if (-not $isCompliant) {
                "Configure Conditional Access policies requiring approved or compliant applications"
            } else {
                $null
            }
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
