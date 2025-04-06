# NIST.ps1 - NIST SP 800-53 benchmark definitions for Conditional Access

function Test-NISTBenchmark {
    <#
    .SYNOPSIS
        Tests Conditional Access policies against NIST SP 800-53 controls.
    .DESCRIPTION
        Evaluates Conditional Access policies against the NIST SP 800-53 security
        and privacy controls to determine compliance with federal standards.
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
        $nistControls = @(
            @{
                Id = "AC-2"
                Name = "Account Management"
                Description = "Organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts."
                SubControls = @(
                    @{
                        Id = "AC-2(1)"
                        Name = "Automated System Account Management"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies targeting admin accounts
                            $adminPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyTargetsAdmins -Policy $_)
                            }
                            
                            $compliant = $adminPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $adminPolicies
                                Reason = if ($compliant) {
                                    "Admin-specific Conditional Access policies found: $($adminPolicies.Count)"
                                } else {
                                    "No admin-specific Conditional Access policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create dedicated Conditional Access policies for administrative roles"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "AC-2(11)"
                        Name = "Usage Conditions"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies with terms of use controls
                            $touPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.GrantControls.TermsOfUse) -and
                                ($_.GrantControls.TermsOfUse.Count -gt 0)
                            }
                            
                            $compliant = $touPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $touPolicies
                                Reason = if ($compliant) {
                                    "Policies with Terms of Use requirements found: $($touPolicies.Count)"
                                } else {
                                    "No policies requiring Terms of Use acceptance"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies with Terms of Use requirements for sensitive access"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "AC-7"
                Name = "Unsuccessful Logon Attempts"
                Description = "Organization enforces limit of consecutive invalid logon attempts during a specified time period."
                SubControls = @(
                    @{
                        Id = "AC-7(1)"
                        Name = "Automatic Account Lock"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for sign-in risk policies
                            $riskPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "SignIn")
                            }
                            
                            $compliant = $riskPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $riskPolicies
                                Reason = if ($compliant) {
                                    "Sign-in risk policies found: $($riskPolicies.Count)"
                                } else {
                                    "No sign-in risk policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that block or enforce MFA for risky sign-ins"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "AC-11"
                Name = "Session Termination"
                Description = "Organization terminates a user session after a defined time-period of inactivity."
                SubControls = @(
                    @{
                        Id = "AC-11(1)"
                        Name = "User-Initiated Logouts"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for sign-in frequency or session controls
                            $sessionPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyHasSessionControls -Policy $_ -ControlType "SignInFrequency")
                            }
                            
                            $compliant = $sessionPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $sessionPolicies
                                Reason = if ($compliant) {
                                    "Policies with sign-in frequency requirements found: $($sessionPolicies.Count)"
                                } else {
                                    "No policies with sign-in frequency requirements"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies with sign-in frequency requirements to enforce session timeouts"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "IA-2"
                Name = "Identification and Authentication"
                Description = "Organization uniquely identifies and authenticates users and devices."
                SubControls = @(
                    @{
                        Id = "IA-2(1)"
                        Name = "Multi-Factor Authentication to Privileged Accounts"
                        Evaluation = {
                            param($Policies)
                            
                            # Find admin MFA policies
                            $adminRoles = Get-AdminRoles -PrivilegedOnly
                            $adminRoleIds = $adminRoles.Id
                            
                            $adminMfaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresMFA -Policy $_) -and
                                (Test-PolicyTargetsAdmins -Policy $_ -AdminRoleIds $adminRoleIds)
                            }
                            
                            $compliant = $adminMfaPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $adminMfaPolicies
                                Reason = if ($compliant) {
                                    "Admin MFA policies found: $($adminMfaPolicies.Count)"
                                } else {
                                    "No policies requiring MFA for administrative access"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that require MFA for all administrative roles"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "IA-2(2)"
                        Name = "Multi-Factor Authentication to Non-Privileged Accounts"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for broad MFA policies
                            $userMfaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresMFA -Policy $_) -and
                                ((Test-PolicyAppliesToAllUsers -Policy $_) -or
                                 (Test-PolicyHasBroadAppCoverage -Policy $_))
                            }
                            
                            $compliant = $userMfaPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $userMfaPolicies
                                Reason = if ($compliant) {
                                    "User MFA policies with broad coverage found: $($userMfaPolicies.Count)"
                                } else {
                                    "No policies requiring MFA for all users"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that require MFA for all users"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "IA-2(6)"
                        Name = "Access to Accounts - Separate Device"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for device compliance policies
                            $devicePolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresCompliantDevice -Policy $_)
                            }
                            
                            $compliant = $devicePolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $devicePolicies
                                Reason = if ($compliant) {
                                    "Device compliance policies found: $($devicePolicies.Count)"
                                } else {
                                    "No policies requiring device compliance"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that require compliant devices"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "SC-7"
                Name = "Boundary Protection"
                Description = "Organization implements boundary protection mechanisms to control communications at external and internal boundaries."
                SubControls = @(
                    @{
                        Id = "SC-7(5)"
                        Name = "Deny by Default / Allow by Exception"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for location-based policies
                            $locationPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.Conditions.Locations) -and
                                (($null -ne $_.Conditions.Locations.IncludeLocations -and $_.Conditions.Locations.IncludeLocations.Count -gt 0) -or
                                 ($null -ne $_.Conditions.Locations.ExcludeLocations -and $_.Conditions.Locations.ExcludeLocations.Count -gt 0))
                            }
                            
                            $compliant = $locationPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $locationPolicies
                                Reason = if ($compliant) {
                                    "Location-based policies found: $($locationPolicies.Count)"
                                } else {
                                    "No location-based policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create location-based Conditional Access policies to restrict access from untrusted networks"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "SC-7(10)"
                        Name = "Prevent Unauthorized Exfiltration"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for MDCA/Cloud App Security integration
                            $mdcaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyHasSessionControls -Policy $_ -ControlType "CloudAppSecurity")
                            }
                            
                            $compliant = $mdcaPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $mdcaPolicies
                                Reason = if ($compliant) {
                                    "MDCA/Cloud App Security integrated policies found: $($mdcaPolicies.Count)"
                                } else {
                                    "No policies with MDCA/Cloud App Security integration"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that integrate with Microsoft Defender for Cloud Apps"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "SI-4"
                Name = "Information System Monitoring"
                Description = "Organization monitors the information system to detect attacks and unauthorized actions."
                SubControls = @(
                    @{
                        Id = "SI-4(5)"
                        Name = "System-Generated Alerts"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies using risk detection
                            $riskPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "Any")
                            }
                            
                            $compliant = $riskPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $riskPolicies
                                Reason = if ($compliant) {
                                    "Risk-based policies found: $($riskPolicies.Count)"
                                } else {
                                    "No risk-based policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that respond to user and sign-in risk"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            }
        )
        
        # Evaluate each NIST control
        $results = @()
        
        foreach ($control in $nistControls) {
            $subResults = @()
            
            foreach ($subControl in $control.SubControls) {
                try {
                    $evaluation = & $subControl.Evaluation $Policies
                    
                    $subResult = [PSCustomObject]@{
                        ControlId = "$($control.Id)($($subControl.Id.Split('(')[1])"
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
                    Write-Warning "Error evaluating $($control.Id) - $($subControl.Id): $_"
                    
                    $subResults += [PSCustomObject]@{
                        ControlId = "$($control.Id)($($subControl.Id.Split('(')[1])"
                        Name = $subControl.Name
                        Compliant = $false
                        Status = "ERROR"
                        Reason = "Evaluation error: $_"
                        Recommendation = "Check logs for details"
                    }
                }
            }
            
            $controlResult = [PSCustomObject]@{
                ControlId = $control.Id
                Name = $control.Name
                Description = $control.Description
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
        }
    }
}

function Get-NISTControlMappings {
    <#
    .SYNOPSIS
        Returns mappings between NIST SP 800-53 controls and Conditional Access capabilities.
    .DESCRIPTION
        Provides a mapping reference that shows which Conditional Access features
        map to specific NIST SP 800-53 security controls.
    .EXAMPLE
        $mappings = Get-NISTControlMappings
    #>
    [CmdletBinding()]
    param()
    
    process {
        $controlMappings = @(
            [PSCustomObject]@{
                NISTControl = "AC-2"
                ControlTitle = "Account Management"
                CACapability = "Admin role management"
                Description = "Conditional Access policies targeting admin roles help enforce principle of least privilege"
                Implementation = "Create separate policies for each admin role with appropriate controls"
            },
            [PSCustomObject]@{
                NISTControl = "AC-3"
                ControlTitle = "Access Enforcement"
                CACapability = "Application access control"
                Description = "Conditional Access enforces access control decisions for cloud applications"
                Implementation = "Define policies that control access to specific applications"
            },
            [PSCustomObject]@{
                NISTControl = "AC-7"
                ControlTitle = "Unsuccessful Logon Attempts"
                CACapability = "Sign-in risk detection"
                Description = "Conditional Access with Identity Protection detects and responds to suspicious sign-in attempts"
                Implementation = "Create policies that block or require MFA for risky sign-ins"
            },
            [PSCustomObject]@{
                NISTControl = "AC-11"
                ControlTitle = "Session Termination"
                CACapability = "Sign-in frequency"
                Description = "Conditional Access can enforce session timeouts and re-authentication"
                Implementation = "Configure sign-in frequency requirements in session controls"
            },
            [PSCustomObject]@{
                NISTControl = "IA-2(1)"
                ControlTitle = "Identification and Authentication (Organizational Users) | Network Access to Privileged Accounts"
                CACapability = "Admin MFA"
                Description = "Conditional Access enforces MFA for administrators"
                Implementation = "Create policies requiring MFA for admin roles"
            },
            [PSCustomObject]@{
                NISTControl = "IA-2(2)"
                ControlTitle = "Identification and Authentication (Organizational Users) | Network Access to Non-Privileged Accounts"
                CACapability = "User MFA"
                Description = "Conditional Access enforces MFA for all users"
                Implementation = "Create policies requiring MFA for all users"
            },
            [PSCustomObject]@{
                NISTControl = "IA-2(6)"
                ControlTitle = "Identification and Authentication (Organizational Users) | Network Access to Privileged Accounts - Separate Device"
                CACapability = "Device compliance"
                Description = "Conditional Access can require trusted devices for privileged access"
                Implementation = "Create policies requiring device compliance for admin roles"
            },
            [PSCustomObject]@{
                NISTControl = "SC-7"
                ControlTitle = "Boundary Protection"
                CACapability = "Location-based conditions"
                Description = "Conditional Access can restrict access based on IP addresses or countries"
                Implementation = "Create location-based access policies"
            },
            [PSCustomObject]@{
                NISTControl = "SC-7(10)"
                ControlTitle = "Boundary Protection | Prevent Unauthorized Exfiltration"
                CACapability = "Microsoft Defender for Cloud Apps"
                Description = "MDCA integration enables monitoring and control of sensitive data"
                Implementation = "Configure session controls with MDCA integration"
            },
            [PSCustomObject]@{
                NISTControl = "SC-8"
                ControlTitle = "Transmission Confidentiality and Integrity"
                CACapability = "App protection policies"
                Description = "Conditional Access can enforce MAM policies for data protection in transit"
                Implementation = "Require approved applications and app protection"
            },
            [PSCustomObject]@{
                NISTControl = "SI-4"
                ControlTitle = "Information System Monitoring"
                CACapability = "Risk detection"
                Description = "Conditional Access responds to risks detected by Identity Protection"
                Implementation = "Create risk-based Conditional Access policies"
            }
        )
        
        return $controlMappings
    }
}
