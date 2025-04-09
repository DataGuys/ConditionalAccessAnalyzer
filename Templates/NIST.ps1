# NIST.ps1 - NIST SP 800-53 benchmark definitions for Conditional Access
# Provides functions to test against NIST security controls

function Test-NISTBenchmark {
    <#
    .SYNOPSIS
        Tests Conditional Access policies against NIST SP 800-53 controls.
    .DESCRIPTION
        Evaluates Conditional Access policies against the NIST SP 800-53 security framework
        to determine compliance with recommended security controls.
    .PARAMETER Policies
        The collection of policies to evaluate.
    .PARAMETER DetailLevel
        The level of detail to include in the results.
    .EXAMPLE
        $results = Test-NISTBenchmark -Policies $policies
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
        Write-Verbose "Evaluating Conditional Access policies against NIST SP 800-53 controls"
        
        # Define NIST controls relevant to Conditional Access
        $nistControls = @{
            'AC-2' = @(
                @{
                    Id = "AC-2.1"
                    Name = "Account Management"
                    Description = "Organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts."
                    Evaluation = {
                        param($Policies)
                        
                        # Look for admin management policies
                        $adminPolicies = $Policies | Where-Object {
                            ($_.State -eq "enabled") -and
                            (Test-PolicyTargetsAdmins -Policy $_)
                        }
                        
                        $compliant = $adminPolicies.Count -gt 0
                        
                        return @{
                            Compliant = $compliant
                            Details = $adminPolicies
                            Reason = if ($compliant) {
                                "Found policies targeting administrative accounts"
                            } else {
                                "No policies specifically targeting administrative accounts"
                            }
                            Recommendation = if (-not $compliant) {
                                "Create Conditional Access policies specifically for administrative accounts"
                            } else {
                                $null
                            }
                        }
                    }
                },
                @{
                    Id = "AC-2.7"
                    Name = "Role-Based Schemes"
                    Description = "Organization establishes and administers privileged user accounts in accordance with a role-based access scheme."
                    Evaluation = {
                        param($Policies)
                        
                        # Look for role-specific policies
                        $rolePolicies = $Policies | Where-Object {
                            ($_.State -eq "enabled") -and
                            ($null -ne $_.Conditions.Users.IncludeRoles) -and
                            ($_.Conditions.Users.IncludeRoles.Count -gt 0)
                        }
                        
                        $compliant = $rolePolicies.Count -gt 0
                        
                        return @{
                            Compliant = $compliant
                            Details = $rolePolicies
                            Reason = if ($compliant) {
                                "Found role-specific access policies"
                            } else {
                                "No role-specific access policies found"
                            }
                            Recommendation = if (-not $compliant) {
                                "Create Conditional Access policies targeting specific administrative roles"
                            } else {
                                $null
                            }
                        }
                    }
                }
            )
        }
        
        $nistControls['AC-7'] = @(
            @{
                Id = "AC-7.1"
                Name = "Unsuccessful Logon Attempts"
                Description = "Organization enforces limit of consecutive invalid logon attempts during a specified time period."
                Evaluation = {
                    param($Policies)
                    
                    # Look for risk-based policies
                    $riskPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "SignIn")
                    }
                    
                    $compliant = $riskPolicies.Count -gt 0
                    
                    return @{
                        Compliant = $compliant
                        Details = $riskPolicies
                        Reason = if ($compliant) {
                            "Found sign-in risk-based policies"
                        } else {
                            "No sign-in risk-based policies found"
                        }
                        Recommendation = if (-not $compliant) {
                            "Create Conditional Access policies that use sign-in risk detection"
                        } else {
                            $null
                        }
                    }
                }
            }
        )
        
        $nistControls['AC-11'] = @(
            @{
                Id = "AC-11.1"
                Name = "Session Termination"
                Description = "Organization terminates a user session after a defined time-period of inactivity."
                Evaluation = {
                    param($Policies)
                    
                    # Look for session controls
                    $sessionPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyHasSessionControls -Policy $_ -ControlType "SignInFrequency")
                    }
                    
                    $compliant = $sessionPolicies.Count -gt 0
                    
                    return @{
                        Compliant = $compliant
                        Details = $sessionPolicies
                        Reason = if ($compliant) {
                            "Found session control policies"
                        } else {
                            "No session control policies found"
                        }
                        Recommendation = if (-not $compliant) {
                            "Create Conditional Access policies with sign-in frequency controls"
                        } else {
                            $null
                        }
                    }
                }
            }
        )
        
        # Continue with more NIST controls relevant to Conditional Access...
        $nistControls['IA-2'] = @(
            @{
                Id = "IA-2.1"
                Name = "Multifactor Authentication"
                Description = "Organization implements multifactor authentication for access to privileged accounts."
                Evaluation = {
                    param($Policies)
                    
                    # Look for admin MFA
                    $adminMfaPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyRequiresMFA -Policy $_) -and
                        (Test-PolicyTargetsAdmins -Policy $_)
                    }
                    
                    $compliant = $adminMfaPolicies.Count -gt 0
                    
                    return @{
                        Compliant = $compliant
                        Details = $adminMfaPolicies
                        Reason = if ($compliant) {
                            "Found MFA policies for administrative accounts"
                        } else {
                            "No MFA policies for administrative accounts found"
                        }
                        Recommendation = if (-not $compliant) {
                            "Create Conditional Access policies requiring MFA for administrative accounts"
                        } else {
                            $null
                        }
                    }
                }
            },
            @{
                Id = "IA-2.2"
                Name = "Multifactor Authentication for Non-Privileged Accounts"
                Description = "Organization implements multifactor authentication for access to non-privileged accounts."
                Evaluation = {
                    param($Policies)
                    
                    # Look for user MFA
                    $userMfaPolicies = $Policies | Where-Object {
                        ($_.State -eq "enabled") -and
                        (Test-PolicyRequiresMFA -Policy $_) -and
                        (
                            (Test-PolicyAppliesToAllUsers -Policy $_) -or
                            (Test-PolicyHasBroadAppCoverage -Policy $_)
                        )
                    }
                    
                    $compliant = $userMfaPolicies.Count -gt 0
                    
                    return @{
                        Compliant = $compliant
                        Details = $userMfaPolicies
                        Reason = if ($compliant) {
                            "Found MFA policies for regular user accounts"
                        } else {
                            "No MFA policies for regular user accounts found"
                        }
                        Recommendation = if (-not $compliant) {
                            "Create Conditional Access policies requiring MFA for all users"
                        } else {
                            $null
                        }
                    }
                }
            }
        )
        
        # Evaluate each NIST control
        $results = @()
        
        foreach ($controlId in $nistControls.Keys) {
            $subResults = @()
            $control = $nistControls[$controlId]
            
            foreach ($subControl in $control) {
                try {
                    $evaluation = & $subControl.Evaluation $Policies
                    
                    $subResult = [PSCustomObject]@{
                        ControlId = $subControl.Id
                        Name = $subControl.Name
                        Compliant = $evaluation.Compliant
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
                    Write-Warning "Error evaluating $($subControl.Id): ${_}"
                    
                    $subResults += [PSCustomObject]@{
                        ControlId = $subControl.Id
                        Name = $subControl.Name
                        Compliant = $false
                        Status = "ERROR"
                        Reason = "Evaluation error: ${_}"
                        Recommendation = "Check logs for details"
                    }
                }
            }
            
            $controlResult = [PSCustomObject]@{
                ControlId = $controlId
                Name = $control[0].Name
                Description = $control[0].Description
                SubControls = $subResults
                ComplianceScore = if ($subResults.Count -gt 0) {
                    [math]::Round(($subResults.Where({ $_.Compliant -eq $true }).Count / $subResults.Count) * 100)
                } else {
                    0
                }
            }
            
            $results += $controlResult
        }
        
        # Calculate overall score
        $totalSubControls = ($results.SubControls | Measure-Object).Count
        $compliantSubControls = ($results.SubControls | Where-Object { $_.Compliant -eq $true } | Measure-Object).Count
        
        $overallScore = if ($totalSubControls -gt 0) {
            [math]::Round(($compliantSubControls / $totalSubControls) * 100)
        } else {
            0
        }
        
        return [PSCustomObject]@{
            Results = $results
            OverallScore = $overallScore
            CompliantControls = $compliantSubControls
            TotalControls = $totalSubControls
            EvaluationDate = Get-Date
            DetailLevel = $DetailLevel
            Framework = "NIST"
        }
    }
}
