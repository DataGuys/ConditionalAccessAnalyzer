# ZeroTrust.ps1 - Zero Trust security model implementation with Conditional Access

function Test-ZeroTrustBenchmark {
    <#
    .SYNOPSIS
        Tests Conditional Access policies against Zero Trust principles.
    .DESCRIPTION
        Evaluates Conditional Access policies against the core principles of the
        Zero Trust security model to determine alignment with modern security best practices.
    .PARAMETER Policies
        The collection of policies to evaluate.
    .PARAMETER DetailLevel
        The level of detail to include in the results.
    .EXAMPLE
        $results = Test-ZeroTrustBenchmark -Policies $policies
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Policies,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Detailed", "Comprehensive")]
        [string]$DetailLevel = "Detailed"
    )
    
    process {
        Write-Verbose "Evaluating Conditional Access policies against Zero Trust principles"
        
        # Define Zero Trust principles relevant to Conditional Access
        $ztPrinciples = @(
            @{
                Id = "ZT-1"
                Name = "Verify Explicitly"
                Description = "Always authenticate and authorize based on all available data points"
                SubPrinciples = @(
                    @{
                        Id = "ZT-1.1"
                        Name = "Strong Authentication"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for MFA requirements
                            $mfaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresMFA -Policy $_)
                            }
                            
                            # We need both admin and broad user MFA policies
                            $adminMfaPolicies = $mfaPolicies | Where-Object {
                                (Test-PolicyTargetsAdmins -Policy $_)
                            }
                            
                            $userMfaPolicies = $mfaPolicies | Where-Object {
                                (Test-PolicyAppliesToAllUsers -Policy $_) -or
                                (Test-PolicyHasBroadAppCoverage -Policy $_)
                            }
                            
                            $adminMfaCompliant = $adminMfaPolicies.Count -gt 0
                            $userMfaCompliant = $userMfaPolicies.Count -gt 0
                            $compliant = $adminMfaCompliant -and $userMfaCompliant
                            
                            return @{
                                Compliant = $compliant
                                Score = if ($adminMfaCompliant -and $userMfaCompliant) {
                                    100
                                } elseif ($adminMfaCompliant -or $userMfaCompliant) {
                                    50
                                } else {
                                    0
                                }
                                Details = @{
                                    AdminMFA = $adminMfaPolicies
                                    UserMFA = $userMfaPolicies
                                }
                                Reason = if ($compliant) {
                                    "Both admin and user MFA policies found"
                                } else {
                                    if (-not $adminMfaCompliant -and -not $userMfaCompliant) {
                                        "No MFA policies found"
                                    } elseif (-not $adminMfaCompliant) {
                                        "No admin MFA policies found"
                                    } else {
                                        "No broad user MFA policies found"
                                    }
                                }
                                Recommendation = if (-not $compliant) {
                                    if (-not $adminMfaCompliant -and -not $userMfaCompliant) {
                                        "Create Conditional Access policies requiring MFA for all users and administrative roles"
                                    } elseif (-not $adminMfaCompliant) {
                                        "Create Conditional Access policies requiring MFA for administrative roles"
                                    } else {
                                        "Create Conditional Access policies requiring MFA for all users"
                                    }
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "ZT-1.2"
                        Name = "Risk-Based Authentication"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for risk-based policies
                            $signInRiskPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "SignIn")
                            }
                            
                            $userRiskPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "User")
                            }
                            
                            $signInRiskCompliant = $signInRiskPolicies.Count -gt 0
                            $userRiskCompliant = $userRiskPolicies.Count -gt 0
                            $compliant = $signInRiskCompliant -or $userRiskCompliant
                            $fullyCompliant = $signInRiskCompliant -and $userRiskCompliant
                            
                            return @{
                                Compliant = $compliant
                                Score = if ($fullyCompliant) {
                                    100
                                } elseif ($compliant) {
                                    70
                                } else {
                                    0
                                }
                                Details = @{
                                    SignInRiskPolicies = $signInRiskPolicies
                                    UserRiskPolicies = $userRiskPolicies
                                }
                                Reason = if ($fullyCompliant) {
                                    "Both sign-in and user risk policies found"
                                } elseif ($signInRiskCompliant) {
                                    "Sign-in risk policies found, but no user risk policies"
                                } elseif ($userRiskCompliant) {
                                    "User risk policies found, but no sign-in risk policies"
                                } else {
                                    "No risk-based policies found"
                                }
                                Recommendation = if (-not $fullyCompliant) {
                                    if (-not $signInRiskCompliant -and -not $userRiskCompliant) {
                                        "Create both sign-in risk and user risk Conditional Access policies"
                                    } elseif (-not $signInRiskCompliant) {
                                        "Create sign-in risk Conditional Access policies"
                                    } else {
                                        "Create user risk Conditional Access policies"
                                    }
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "ZT-2"
                Name = "Use Least Privileged Access"
                Description = "Limit user access with Just-In-Time and Just-Enough-Access (JIT/JEA), risk-based adaptive policies, and data protection"
                SubPrinciples = @(
                    @{
                        Id = "ZT-2.1"
                        Name = "Admin Role Protection"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for admin-specific policies
                            $adminPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyTargetsAdmins -Policy $_)
                            }
                            
                            $compliant = $adminPolicies.Count -gt 0
                            
                            # Look for stronger controls on admin policies
                            $strongAdminPolicies = $adminPolicies | Where-Object {
                                (Test-PolicyRequiresMFA -Policy $_) -and
                                ((Test-PolicyRequiresCompliantDevice -Policy $_) -or
                                 (Test-PolicyHasSessionControls -Policy $_ -ControlType "SignInFrequency"))
                            }
                            
                            $fullyCompliant = $strongAdminPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Score = if ($fullyCompliant) {
                                    100
                                } elseif ($compliant) {
                                    60
                                } else {
                                    0
                                }
                                Details = $adminPolicies
                                Reason = if ($fullyCompliant) {
                                    "Strong admin protection policies found with MFA and additional controls"
                                } elseif ($compliant) {
                                    "Basic admin protection policies found"
                                } else {
                                    "No admin-specific policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create dedicated Conditional Access policies for administrative roles with MFA and additional controls"
                                } elseif (-not $fullyCompliant) {
                                    "Enhance admin policies with additional controls like device compliance or session limits"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "ZT-2.2"
                        Name = "App-Specific Controls"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies targeting specific apps
                            $appSpecificPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.Conditions.Applications.IncludeApplications) -and
                                ($_.Conditions.Applications.IncludeApplications -notcontains "All") -and
                                ($_.Conditions.Applications.IncludeApplications -notcontains "Office365") -and
                                ($_.Conditions.Applications.IncludeApplications.Count -gt 0)
                            }
                            
                            $compliant = $appSpecificPolicies.Count -gt 0
                            
                            # Look for policies with session controls for specific apps
                            $appSessionPolicies = $appSpecificPolicies | Where-Object {
                                (Test-PolicyHasSessionControls -Policy $_)
                            }
                            
                            $fullyCompliant = $appSessionPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Score = if ($fullyCompliant) {
                                    100
                                } elseif ($compliant) {
                                    60
                                } else {
                                    0
                                }
                                Details = @{
                                    AppSpecificPolicies = $appSpecificPolicies
                                    AppSessionPolicies = $appSessionPolicies
                                }
                                Reason = if ($fullyCompliant) {
                                    "App-specific policies with session controls found"
                                } elseif ($compliant) {
                                    "Basic app-specific policies found"
                                } else {
                                    "No app-specific policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies tailored to specific sensitive applications"
                                } elseif (-not $fullyCompliant) {
                                    "Enhance app-specific policies with session controls"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "ZT-3"
                Name = "Assume Breach"
                Description = "Minimize blast radius and segment access. Verify end-to-end encryption and use analytics to detect threats and improve defenses."
                SubPrinciples = @(
                    @{
                        Id = "ZT-3.1"
                        Name = "Session Security"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for session controls
                            $sessionPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyHasSessionControls -Policy $_)
                            }
                            
                            $compliant = $sessionPolicies.Count -gt 0
                            
                            # Look for MDCA integration
                            $mdcaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyHasSessionControls -Policy $_ -ControlType "CloudAppSecurity")
                            }
                            
                            $fullyCompliant = $mdcaPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Score = if ($fullyCompliant) {
                                    100
                                } elseif ($compliant) {
                                    60
                                } else {
                                    0
                                }
                                Details = @{
                                    SessionPolicies = $sessionPolicies
                                    MDCAPolicies = $mdcaPolicies
                                }
                                Reason = if ($fullyCompliant) {
                                    "Session controls with MDCA integration found"
                                } elseif ($compliant) {
                                    "Basic session controls found"
                                } else {
                                    "No session control policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies with session controls"
                                } elseif (-not $fullyCompliant) {
                                    "Enhance session controls with Microsoft Defender for Cloud Apps integration"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "ZT-3.2"
                        Name = "Device Trust"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for device compliance policies
                            $devicePolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresCompliantDevice -Policy $_)
                            }
                            
                            $compliant = $devicePolicies.Count -gt 0
                            
                            # Look for comprehensive device compliance
                            $broadDevicePolicies = $devicePolicies | Where-Object {
                                (Test-PolicyAppliesToAllUsers -Policy $_) -or
                                (Test-PolicyHasBroadAppCoverage -Policy $_)
                            }
                            
                            $fullyCompliant = $broadDevicePolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Score = if ($fullyCompliant) {
                                    100
                                } elseif ($compliant) {
                                    60
                                } else {
                                    0
                                }
                                Details = @{
                                    DevicePolicies = $devicePolicies
                                    BroadDevicePolicies = $broadDevicePolicies
                                }
                                Reason = if ($fullyCompliant) {
                                    "Broad device compliance policies found"
                                } elseif ($compliant) {
                                    "Limited device compliance policies found"
                                } else {
                                    "No device compliance policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies requiring device compliance"
                                } elseif (-not $fullyCompliant) {
                                    "Expand device compliance policies to cover all users or applications"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            }
        )
        
        # Evaluate each Zero Trust principle
        $results = @()
        
        foreach ($principle in $ztPrinciples) {
            $subResults = @()
            
            foreach ($subPrinciple in $principle.SubPrinciples) {
                try {
                    $evaluation = & $subPrinciple.Evaluation $Policies
                    
                    $subResult = [PSCustomObject]@{
                        PrincipleId = "$($principle.Id).$($subPrinciple.Id)"
                        Name = $subPrinciple.Name
                        Compliant = $evaluation.Compliant
                        Score = $evaluation.Score
                        Status = if ($evaluation.Compliant) { "PASS" } else { "FAIL" }
                        Reason = $evaluation.Reason
                        Recommendation = $evaluation.Recommendation
                    }
                    
                    if ($DetailLevel -ne "Basic") {
                        $subResult | Add-Member -MemberType NoteProperty -Name "Details" -Value $evaluation.Details
                    }
                    
                    $subResults += $subResult
                }
                catch {
                    Write-Warning "Error evaluating $($principle.Id) - $($subPrinciple.Id): $_"
                    
                    $subResults += [PSCustomObject]@{
                        PrincipleId = "$($principle.Id).$($subPrinciple.Id)"
                        Name = $subPrinciple.Name
                        Compliant = $false
                        Score = 0
                        Status = "ERROR"
                        Reason = "Evaluation error: $_"
                        Recommendation = "Check logs for details"
                    }
                }
            }
            
            $principleResult = [PSCustomObject]@{
                PrincipleId = $principle.Id
                Name = $principle.Name
                Description = $principle.Description
                SubPrinciples = $subResults
                ComplianceScore = if ($subResults.Count -gt 0) {
                    [math]::Round(($subResults | Measure-Object -Property Score -Average).Average)
                } else {
                    0
                }
            }
            
            $results += $principleResult
        }
        
        # Calculate overall score
        $overallScore = if ($results.Count -gt 0) {
            [math]::Round(($results | Measure-Object -Property ComplianceScore -Average).Average)
        } else {
            0
        }
        
        # Determine compliance level
        $complianceLevel = switch ($overallScore) {
            { $_ -ge 90 } { "Excellent" }
            { $_ -ge 75 } { "Good" }
            { $_ -ge 60 } { "Fair" }
            { $_ -ge 40 } { "Poor" }
            default { "Critical" }
        }
        
        # Determine compliant principles
        $compliantPrinciples = ($results | Where-Object { $_.ComplianceScore -ge 70 }).Count
        
        return [PSCustomObject]@{
            Results = $results
            OverallScore = $overallScore
            ComplianceLevel = $complianceLevel
            CompliantPrinciples = $compliantPrinciples
            TotalPrinciples = $results.Count
            EvaluationDate = Get-Date
            DetailLevel = $DetailLevel
        }
    }
}

function Get-ZeroTrustJourneyStage {
    <#
    .SYNOPSIS
        Determines the Zero Trust journey stage based on Conditional Access implementation.
    .DESCRIPTION
        Analyzes Conditional Access policies to determine the organization's current
        stage in the Zero Trust journey, and provides recommendations for the next stage.
    .PARAMETER Policies
        The collection of policies to evaluate.
    .EXAMPLE
        $ztStage = Get-ZeroTrustJourneyStage -Policies $policies
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Policies
    )
    
    process {
        # Define the Zero Trust journey stages
        $ztStages = @(
            @{
                Stage = 0
                Name = "Traditional Security"
                Description = "Relying primarily on perimeter security with little or no Conditional Access"
                Criteria = {
                    param($Policies)
                    
                    # Count enabled policies
                    $enabledPolicies = ($Policies | Where-Object { $_.State -eq "enabled" }).Count
                    
                    # If very few or no policies, still in traditional security
                    return $enabledPolicies -le 1
                }
                NextSteps = "Implement basic Conditional Access policies for admin MFA and user MFA"
            },
            @{
                Stage = 1
                Name = "Basic Identity Protection"
                Description = "Basic MFA implementation for administrators and users"
                Criteria = {
                    param($Policies)
                    
                    # Look for admin MFA
                    $adminMfaPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyRequiresMFA -Policy $_) -and
                        (Test-PolicyTargetsAdmins -Policy $_)
                    }
                    
                    # Look for user MFA, either for all users or major apps
                    $userMfaPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyRequiresMFA -Policy $_) -and
                        ((Test-PolicyAppliesToAllUsers -Policy $_) -or
                         (Test-PolicyHasBroadAppCoverage -Policy $_))
                    }
                    
                    # Stage 1 requires at least admin MFA
                    return ($adminMfaPolicies.Count -gt 0) -and ($userMfaPolicies.Count -gt 0)
                }
                NextSteps = "Implement risk-based policies and device compliance requirements"
            },
            @{
                Stage = 2
                Name = "Risk-Based Security"
                Description = "Implementation of risk-based policies and device compliance"
                Criteria = {
                    param($Policies)
                    
                    # First check Stage 1 criteria
                    $stage1Criteria = & $ztStages[1].Criteria $Policies
                    if (-not $stage1Criteria) {
                        return $false
                    }
                    
                    # Look for risk-based policies
                    $riskPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "Any")
                    }
                    
                    # Look for device compliance
                    $devicePolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyRequiresCompliantDevice -Policy $_)
                    }
                    
                    # Stage 2 requires either risk or device compliance
                    return ($riskPolicies.Count -gt 0) -or ($devicePolicies.Count -gt 0)
                }
                NextSteps = "Implement session controls and Microsoft Defender for Cloud Apps integration"
            },
            @{
                Stage = 3
                Name = "Comprehensive Access Control"
                Description = "Implementation of session controls and app protection"
                Criteria = {
                    param($Policies)
                    
                    # First check Stage 2 criteria
                    $stage2Criteria = & $ztStages[2].Criteria $Policies
                    if (-not $stage2Criteria) {
                        return $false
                    }
                    
                    # Look for session controls
                    $sessionPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyHasSessionControls -Policy $_)
                    }
                    
                    # Stage 3 requires session controls
                    return $sessionPolicies.Count -gt 0
                }
                NextSteps = "Enable MDCA integration and advanced session controls"
            },
            @{
                Stage = 4
                Name = "Zero Trust Security"
                Description = "Full implementation of Zero Trust principles with Conditional Access"
                Criteria = {
                    param($Policies)
                    
                    # First check Stage 3 criteria
                    $stage3Criteria = & $ztStages[3].Criteria $Policies
                    if (-not $stage3Criteria) {
                        return $false
                    }
                    
                    # Look for MDCA integration
                    $mdcaPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyHasSessionControls -Policy $_ -ControlType "CloudAppSecurity")
                    }
                    
                    # Look for comprehensive coverage - both risk and device compliance
                    $riskPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "Any")
                    }
                    
                    $devicePolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyRequiresCompliantDevice -Policy $_)
                    }
                    
                    # Stage 4 requires MDCA and both risk and device policies
                    return ($mdcaPolicies.Count -gt 0) -and ($riskPolicies.Count -gt 0) -and ($devicePolicies.Count -gt 0)
                }
                NextSteps = "Refine and optimize policies, implement Global Secure Access"
            }
        )
        
        # Determine current stage
        $currentStage = 0
        $matchedStage = $null
        
        # Evaluate stages in reverse order (highest to lowest)
        for ($i = $ztStages.Count - 1; $i -ge 0; $i--) {
            $stageCriteria = & $ztStages[$i].Criteria $Policies
            
            if ($stageCriteria) {
                $currentStage = $ztStages[$i].Stage
                $matchedStage = $ztStages[$i]
                break
            }
        }
        
        # Determine next steps
        $nextSteps = $null
        if ($currentStage -lt 4) {
            $nextStageIndex = [Math]::Min($currentStage + 1, 4)
            $nextStage = $ztStages[$nextStageIndex]
            $nextSteps = $nextStage.NextSteps
        }
        else {
            $nextSteps = $matchedStage.NextSteps
        }
        
        # Return the result
        return [PSCustomObject]@{
            Stage = $currentStage
            Name = $matchedStage.Name
            Description = $matchedStage.Description
            NextSteps = $nextSteps
            EvaluationDate = Get-Date
        }
    }
}
