# CIS.ps1 - CIS Controls benchmark definitions for Conditional Access
# Updated for 2025 security recommendations based on CIS Controls v8

function Test-CISBenchmark {
    <#
    .SYNOPSIS
        Tests Conditional Access policies against CIS Controls v8.
    .DESCRIPTION
        Evaluates Conditional Access policies against the CIS Controls v8 framework
        with forward-looking 2025 security enhancements to determine compliance with 
        industry best practices.
    .PARAMETER Policies
        The collection of policies to evaluate.
    .PARAMETER DetailLevel
        The level of detail to include in the results.
    .EXAMPLE
        $results = Test-CISBenchmark -Policies $policies
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
        Write-Verbose "Evaluating Conditional Access policies against CIS Controls v8 with 2025 enhancements"
        
        # Define CIS Controls relevant to Conditional Access
        # Updated for CIS Controls v8 with 2025 security recommendations
        $cisControls = @(
            @{
                Id = "CIS 3"
                Name = "Data Protection"
                Description = "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data."
                SubControls = @(
                    @{
                        Id = "3.3"
                        Name = "Configure Data Access Control Lists"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies with app protection controls
                            $dataProtectionPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (
                                    (Test-PolicyHasSessionControls -Policy $_ -ControlType "CloudAppSecurity") -or
                                    ($null -ne $_.GrantControls.BuiltInControls -and 
                                     ($_.GrantControls.BuiltInControls -contains "compliantApplication" -or 
                                      $_.GrantControls.BuiltInControls -contains "approvedApplication"))
                                )
                            }
                            
                            $compliant = $dataProtectionPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $dataProtectionPolicies
                                Reason = if ($compliant) {
                                    "Data protection policies found: $($dataProtectionPolicies.Count)"
                                } else {
                                    "No policies with data protection controls"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that enforce data protection through approved applications or MDCA integration"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "3.10"
                        Name = "Encrypt Sensitive Data in Transit"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for mobile app management policies
                            $mamPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.GrantControls.BuiltInControls) -and
                                (
                                    ($_.GrantControls.BuiltInControls -contains "compliantApplication") -or
                                    ($_.GrantControls.BuiltInControls -contains "approvedApplication")
                                )
                            }
                            
                            $compliant = $mamPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $mamPolicies
                                Reason = if ($compliant) {
                                    "Mobile app management policies found: $($mamPolicies.Count)"
                                } else {
                                    "No policies requiring approved or compliant applications"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that enforce the use of approved applications with data protection capabilities"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 4"
                Name = "Secure Configuration of Enterprise Assets and Software"
                Description = "Establish and maintain the secure configuration of enterprise assets and software."
                SubControls = @(
                    @{
                        Id = "4.1"
                        Name = "Establish and Maintain a Secure Configuration Process"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for device compliance policies
                            $deviceCompliancePolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresCompliantDevice -Policy $_)
                            }
                            
                            $compliant = $deviceCompliancePolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $deviceCompliancePolicies
                                Reason = if ($compliant) {
                                    "Device compliance policies found: $($deviceCompliancePolicies.Count)"
                                } else {
                                    "No policies requiring device compliance"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that require device compliance"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 5"
                Name = "Account Management"
                Description = "Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts, and service accounts."
                SubControls = @(
                    @{
                        Id = "5.2"
                        Name = "Use Unique Passwords"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for user risk policies, which help enforce password reset for compromised accounts
                            $userRiskPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "User") -and
                                ($null -ne $_.GrantControls.BuiltInControls) -and
                                ($_.GrantControls.BuiltInControls -contains "passwordChange")
                            }
                            
                            $compliant = $userRiskPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $userRiskPolicies
                                Reason = if ($compliant) {
                                    "User risk policies requiring password change found: $($userRiskPolicies.Count)"
                                } else {
                                    "No policies requiring password change for risky users"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that enforce password change for users with detected risk"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "5.3"
                        Name = "Disable Dormant Accounts"
                        Evaluation = {
                            param($Policies)
                            
                            # This is more of a lifecycle management check than CA, but we can check for policies that might help
                            $signInRiskPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "SignIn")
                            }
                            
                            # Not enough to fully comply, but helpful
                            $partiallyCompliant = $signInRiskPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $partiallyCompliant # Partially compliant if sign-in risk policies exist
                                Details = $signInRiskPolicies
                                Reason = "Conditional Access does not directly disable dormant accounts, but sign-in risk policies can help identify unusual sign-ins from inactive accounts"
                                Recommendation = "Implement account lifecycle management processes outside of Conditional Access to handle dormant accounts"
                            }
                        }
                    },
                    @{
                        Id = "5.4"
                        Name = "Restrict Administrator Privileges to Dedicated Administrator Accounts"
                        Evaluation = {
                            param($Policies)
                            
                            $adminRoles = Get-AdminRoles -PrivilegedOnly
                            $adminRoleIds = $adminRoles.Id
                            
                            $adminSpecificPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.Conditions.Users.IncludeRoles) -and
                                ($_.Conditions.Users.IncludeRoles | Where-Object { $adminRoleIds -contains $_ }).Count -gt 0
                            }
                            
                            $compliant = $adminSpecificPolicies.Count -gt 0
                            
                            # For 2025, check for stronger admin controls
                            $strongAdminPolicies = $adminSpecificPolicies | Where-Object {
                                (Test-PolicyRequiresMFA -Policy $_) -and
                                (
                                    (Test-PolicyRequiresCompliantDevice -Policy $_) -or
                                    (Test-PolicyHasSessionControls -Policy $_ -ControlType "SignInFrequency")
                                )
                            }
                            
                            $fullyCompliant = $strongAdminPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $adminSpecificPolicies
                                Reason = if ($fullyCompliant) {
                                    "Strong admin-specific Conditional Access policies found: $($strongAdminPolicies.Count)"
                                } elseif ($compliant) {
                                    "Basic admin-specific Conditional Access policies found: $($adminSpecificPolicies.Count)"
                                } else {
                                    "No admin-specific Conditional Access policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create dedicated Conditional Access policies for administrative roles"
                                } elseif (-not $fullyCompliant) {
                                    "Enhance admin policies with both MFA and device compliance or session control requirements"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "5.6"
                        Name = "Centralize Account Management"
                        Evaluation = {
                            param($Policies)
                            
                            # This is more about architecture than specific policies
                            # Check for broad policies that would indicate centralized identity
                            $broadPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyAppliesToAllUsers -Policy $_) -and
                                (Test-PolicyHasBroadAppCoverage -Policy $_)
                            }
                            
                            $compliant = $broadPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $broadPolicies
                                Reason = if ($compliant) {
                                    "Broad organizational policies found, indicating centralized identity management: $($broadPolicies.Count)"
                                } else {
                                    "No broad organizational policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create organization-wide Conditional Access policies, indicating centralized identity management"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 6"
                Name = "Access Control Management"
                Description = "Use processes and tools to create, assign, manage, and revoke access credentials and privileges."
                SubControls = @(
                    @{
                        Id = "6.3"
                        Name = "Require MFA for Externally-Exposed Applications"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for MFA policies targeting cloud apps
                            $externalAppMfaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresMFA -Policy $_) -and
                                (
                                    (Test-PolicyHasBroadAppCoverage -Policy $_) -or
                                    ($null -ne $_.Conditions.Applications.IncludeApplications -and
                                     $_.Conditions.Applications.IncludeApplications.Count -gt 0 -and
                                     $_.Conditions.Applications.IncludeApplications -notcontains "Office365")
                                )
                            }
                            
                            $compliant = $externalAppMfaPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $externalAppMfaPolicies
                                Reason = if ($compliant) {
                                    "MFA policies for externally-exposed applications found: $($externalAppMfaPolicies.Count)"
                                } else {
                                    "No MFA policies targeting externally-exposed applications"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies requiring MFA for all externally-exposed applications"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "6.4"
                        Name = "Require MFA for Remote Network Access"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for MFA policies with location conditions
                            $remoteMfaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresMFA -Policy $_) -and
                                ($null -ne $_.Conditions.Locations) -and
                                (
                                    ($null -ne $_.Conditions.Locations.IncludeLocations -and 
                                     $_.Conditions.Locations.IncludeLocations -contains "All") -or
                                    ($null -ne $_.Conditions.Locations.ExcludeLocations -and 
                                     $_.Conditions.Locations.ExcludeLocations -contains "AllTrusted")
                                )
                            }
                            
                            $compliant = $remoteMfaPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $remoteMfaPolicies
                                Reason = if ($compliant) {
                                    "MFA policies for remote access found: $($remoteMfaPolicies.Count)"
                                } else {
                                    "No MFA policies specifically targeting remote network access"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies requiring MFA for access from outside trusted locations"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "6.5"
                        Name = "Require MFA for Administrative Access"
                        Evaluation = {
                            param($Policies)
                            
                            $adminRoles = Get-AdminRoles -PrivilegedOnly
                            $adminRoleIds = $adminRoles.Id
                            
                            $adminMfaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresMFA -Policy $_) -and
                                (Test-PolicyTargetsAdmins -Policy $_ -AdminRoleIds $adminRoleIds)
                            }
                            
                            $compliant = $adminMfaPolicies.Count -gt 0
                            
                            # For 2025, check for FIDO2/Passwordless
                            $strongAdminPolicies = $adminMfaPolicies | Where-Object {
                                (Test-PolicyRequiresCompliantDevice -Policy $_)
                            }
                            
                            $fullyCompliant = $strongAdminPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $adminMfaPolicies
                                Reason = if ($fullyCompliant) {
                                    "Strong admin MFA policies requiring device compliance found: $($strongAdminPolicies.Count)"
                                } elseif ($compliant) {
                                    "Admin MFA policies found: $($adminMfaPolicies.Count)"
                                } else {
                                    "No policies requiring MFA for administrative access"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies requiring MFA for all administrative roles"
                                } elseif (-not $fullyCompliant) {
                                    "Enhance admin MFA policies with device compliance requirements or phishing-resistant authentication"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "6.6"
                        Name = "Establish and Maintain an Inventory of Authentication and Authorization Systems"
                        Evaluation = {
                            param($Policies)
                            
                            # This is more about inventory than specific policies
                            # We can check if policies exist that would indicate good governance
                            
                            # Look for diversity of policy types
                            $mfaPolicies = ($Policies | Where-Object { ($_.State -eq "enabled") -and (Test-PolicyRequiresMFA -Policy $_) }).Count -gt 0
                            $devicePolicies = ($Policies | Where-Object { ($_.State -eq "enabled") -and (Test-PolicyRequiresCompliantDevice -Policy $_) }).Count -gt 0
                            $riskPolicies = ($Policies | Where-Object { ($_.State -eq "enabled") -and (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "Any") }).Count -gt 0
                            $sessionPolicies = ($Policies | Where-Object { ($_.State -eq "enabled") -and (Test-PolicyHasSessionControls -Policy $_) }).Count -gt 0
                            
                            # Need at least 3 different policy types to show good governance
                            $typesCount = @($mfaPolicies, $devicePolicies, $riskPolicies, $sessionPolicies).Where({ $_ -eq $true }).Count
                            $compliant = $typesCount -ge 3
                            
                            return @{
                                Compliant = $compliant
                                Details = @{
                                    HasMfaPolicies = $mfaPolicies
                                    HasDevicePolicies = $devicePolicies
                                    HasRiskPolicies = $riskPolicies
                                    HasSessionPolicies = $sessionPolicies
                                    TypesCount = $typesCount
                                }
                                Reason = if ($compliant) {
                                    "Found $typesCount different types of authentication policies, indicating good authentication system governance"
                                } else {
                                    "Only found $typesCount different types of authentication policies, indicating limited authentication system governance"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Implement a more diverse set of Conditional Access policies, including MFA, device compliance, risk-based, and session controls"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "6.7"
                        Name = "Centralize Access Control"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies that would indicate centralized access control
                            $broadPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (
                                    (Test-PolicyAppliesToAllUsers -Policy $_) -or
                                    (Test-PolicyHasBroadAppCoverage -Policy $_)
                                )
                            }
                            
                            # Need at least 3 policies with broad coverage
                            $compliant = $broadPolicies.Count -ge 3
                            
                            return @{
                                Compliant = $compliant
                                Details = $broadPolicies
                                Reason = if ($compliant) {
                                    "Found $($broadPolicies.Count) policies with broad coverage, indicating centralized access control"
                                } else {
                                    "Only found $($broadPolicies.Count) policies with broad coverage, indicating limited centralized access control"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create more organization-wide Conditional Access policies to implement centralized access control"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "6.8"
                        Name = "Define and Maintain Role-Based Access Control"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies targeting specific roles or groups
                            $rolePolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (
                                    ($null -ne $_.Conditions.Users.IncludeRoles -and $_.Conditions.Users.IncludeRoles.Count -gt 0) -or
                                    ($null -ne $_.Conditions.Users.IncludeGroups -and $_.Conditions.Users.IncludeGroups.Count -gt 0 -and 
                                     $_.Conditions.Users.IncludeGroups -notcontains "All")
                                )
                            }
                            
                            $compliant = $rolePolicies.Count -gt 1 # Need at least 2 different role-specific policies
                            
                            return @{
                                Compliant = $compliant
                                Details = $rolePolicies
                                Reason = if ($compliant) {
                                    "Found $($rolePolicies.Count) role-specific policies, indicating role-based access control"
                                } else {
                                    "Found only $($rolePolicies.Count) role-specific policies, indicating limited role-based access control"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies targeting specific roles or groups with appropriate access controls"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 10"
                Name = "Malware Defenses"
                Description = "Prevent or control the installation, spread, and execution of malicious applications, code, or scripts."
                SubControls = @(
                    @{
                        Id = "10.2"
                        Name = "Configure Automatic Anti-Malware Scanning of Removable Media"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for device compliance policies which can enforce this
                            $deviceCompliancePolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresCompliantDevice -Policy $_)
                            }
                            
                            # Not fully enforceable via CA directly, but device compliance helps
                            $partiallyCompliant = $deviceCompliancePolicies.Count -gt 0
                            
                            return @{
                                Compliant = $partiallyCompliant
                                Details = $deviceCompliancePolicies
                                Reason = if ($partiallyCompliant) {
                                    "Device compliance policies found which may enforce anti-malware requirements: $($deviceCompliancePolicies.Count)"
                                } else {
                                    "No device compliance policies found"
                                }
                                Recommendation = if (-not $partiallyCompliant) {
                                    "Create Conditional Access policies requiring device compliance, which can enforce anti-malware requirements"
                                } else {
                                    "Ensure device compliance policies include anti-malware requirements in Intune"
                                }
                            }
                        }
                    },
                    @{
                        Id = "10.5"
                        Name = "Enable Anti-Exploitation Features"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for device compliance policies which can enforce this
                            $deviceCompliancePolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresCompliantDevice -Policy $_)
                            }
                            
                            $compliant = $deviceCompliancePolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $deviceCompliancePolicies
                                Reason = if ($compliant) {
                                    "Device compliance policies found: $($deviceCompliancePolicies.Count)"
                                } else {
                                    "No policies requiring device compliance"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that require device compliance, which can enforce anti-exploitation features"
                                } else {
                                    "Ensure device compliance policies include anti-exploitation requirements in Intune"
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 12"
                Name = "Network Infrastructure Management"
                Description = "Establish, implement, and actively manage the security configuration of network infrastructure devices."
                SubControls = @(
                    @{
                        Id = "12.2"
                        Name = "Establish and Maintain a Secure Network Architecture"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for location-based and Global Secure Access policies
                            $networkPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (
                                    ($null -ne $_.Conditions.Locations -and 
                                     (
                                        ($null -ne $_.Conditions.Locations.IncludeLocations -and $_.Conditions.Locations.IncludeLocations.Count -gt 0) -or
                                        ($null -ne $_.Conditions.Locations.ExcludeLocations -and $_.Conditions.Locations.ExcludeLocations.Count -gt 0)
                                     )
                                    ) -or
                                    ($_.DisplayName -like "*Global Secure Access*" -or $_.DisplayName -like "*Network Access*")
                                )
                            }
                            
                            $compliant = $networkPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $networkPolicies
                                Reason = if ($compliant) {
                                    "Network security policies found: $($networkPolicies.Count)"
                                } else {
                                    "No network security policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create location-based Conditional Access policies or implement Global Secure Access for network security"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 13"
                Name = "Network Monitoring and Defense"
                Description = "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense."
                SubControls = @(
                    @{
                        Id = "13.2"
                        Name = "Deploy a Host-Based Intrusion Detection Solution"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for device compliance policies which can enforce EDR
                            $deviceCompliancePolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresCompliantDevice -Policy $_)
                            }
                            
                            # Not fully enforceable via CA directly, but device compliance helps
                            $partiallyCompliant = $deviceCompliancePolicies.Count -gt 0
                            
                            return @{
                                Compliant = $partiallyCompliant
                                Details = $deviceCompliancePolicies
                                Reason = if ($partiallyCompliant) {
                                    "Device compliance policies found which may enforce EDR requirements: $($deviceCompliancePolicies.Count)"
                                } else {
                                    "No device compliance policies found"
                                }
                                Recommendation = if (-not $partiallyCompliant) {
                                    "Create Conditional Access policies requiring device compliance, which can enforce EDR requirements"
                                } else {
                                    "Ensure device compliance policies include EDR requirements in Intune"
                                }
                            }
                        }
                    },
                    @{
                        Id = "13.6"
                        Name = "Collect Network Traffic Flow Data"
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
                    },
                    @{
                        Id = "13.10"
                        Name = "Perform Application Layer Filtering"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for MDCA session controls for app filtering
                            $mdcaSessionPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyHasSessionControls -Policy $_ -ControlType "CloudAppSecurity") -and
                                ($null -ne $_.SessionControls.CloudAppSecurity.CloudAppSecurityType) -and
                                ($_.SessionControls.CloudAppSecurity.CloudAppSecurityType -ne "monitorOnly")
                            }
                            
                            $compliant = $mdcaSessionPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $mdcaSessionPolicies
                                Reason = if ($compliant) {
                                    "MDCA session control policies found for application layer filtering: $($mdcaSessionPolicies.Count)"
                                } else {
                                    "No MDCA session control policies found for application layer filtering"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies with Microsoft Defender for Cloud Apps session controls in control mode, not just monitor mode"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 14"
                Name = "Security Awareness and Skills Training"
                Description = "Establish and maintain a security awareness program."
                SubControls = @(
                    @{
                        Id = "14.6"
                        Name = "Train Workforce on Secure Authentication"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for MFA policies which indicate secure authentication practices
                            $mfaPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (Test-PolicyRequiresMFA -Policy $_)
                            }
                            
                            $compliant = $mfaPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $mfaPolicies
                                Reason = if ($compliant) {
                                    "MFA policies found: $($mfaPolicies.Count)"
                                } else {
                                    "No MFA policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Implement MFA policies and security defaults"
                                } else {
                                    $null
                                }
                            }
                        }
                    }
                )
            },
            @{
                Id = "CIS 16"
                Name = "Application Software Security"
                Description = "Manage the security life cycle of all in-house developed and acquired software."
                SubControls = @(
                    @{
                        Id = "16.9"
                        Name = "Separate Production and Non-Production Systems"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for location-based policies that might segment environments
                            $locationPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.Conditions.Locations) -and
                                (($null -ne $_.Conditions.Locations.IncludeLocations -and $_.Conditions.Locations.IncludeLocations.Count -gt 0) -or
                                 ($null -ne $_.Conditions.Locations.ExcludeLocations -and $_.Conditions.Locations.ExcludeLocations.Count -gt 0))
                            }
                            
                            # For 2025, also look for app-specific policies
                            $appPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.Conditions.Applications.IncludeApplications) -and
                                ($_.Conditions.Applications.IncludeApplications -notcontains "All") -and
                                ($_.Conditions.Applications.IncludeApplications -notcontains "Office365") -and
                                ($_.Conditions.Applications.IncludeApplications.Count -ge 2) # At least 2 specific apps
                            }
                            
                            # Either location or app-specific policies can help segment environments
                            $compliant = ($locationPolicies.Count -gt 0) -or ($appPolicies.Count -gt 0)
                            
                            # Both types indicate better segmentation
                            $fullyCompliant = ($locationPolicies.Count -gt 0) -and ($appPolicies.Count -gt 0)
                            
                            return @{
                                Compliant = $compliant
                                Details = @{
                                    LocationPolicies = $locationPolicies
                                    AppPolicies = $appPolicies
                                }
                                Reason = if ($fullyCompliant) {
                                    "Both location-based and app-specific policies found, indicating strong environment segmentation"
                                } elseif ($locationPolicies.Count -gt 0) {
                                    "Location-based policies found: $($locationPolicies.Count)"
                                } elseif ($appPolicies.Count -gt 0) {
                                    "App-specific policies found: $($appPolicies.Count)"
                                } else {
                                    "No location-based or app-specific policies found"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create location-based or app-specific Conditional Access policies to help separate production and non-production environments"
                                } elseif (-not $fullyCompliant) {
                                    "Enhance environment segmentation by creating both location-based and app-specific policies"
                                } else {
                                    $null
                                }
                            }
                        }
                    },
                    @{
                        Id = "16.10"
                        Name = "Apply Secure Design Principles"
                        Evaluation = {
                            param($Policies)
                            
                            # Zero Trust principles implementation
                            # 1. Verify explicitly (MFA + Risk)
                            $explicitVerification = ($Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (
                                    (Test-PolicyRequiresMFA -Policy $_) -or
                                    (Test-PolicyUsesRiskDetection -Policy $_ -RiskType "Any")
                                )
                            }).Count -gt 0
                            
                            # 2. Least privilege (Role-specific policies)
                            $leastPrivilege = ($Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (
                                    ($null -ne $_.Conditions.Users.IncludeRoles -and $_.Conditions.Users.IncludeRoles.Count -gt 0) -or
                                    ($null -ne $_.Conditions.Users.IncludeGroups -and $_.Conditions.Users.IncludeGroups.Count -gt 0 -and 
                                     $_.Conditions.Users.IncludeGroups -notcontains "All")
                                )
                            }).Count -gt 0
                            
                            # 3. Assume breach (Session controls + MDCA)
                            $assumeBreach = ($Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                (
                                    (Test-PolicyHasSessionControls -Policy $_) -or
                                    (Test-PolicyRequiresCompliantDevice -Policy $_)
                                )
                            }).Count -gt 0
                            
                            # Need at least 2 of 3 Zero Trust principles
                            $zeroTrustScore = @($explicitVerification, $leastPrivilege, $assumeBreach).Where({ $_ -eq $true }).Count
                            $compliant = $zeroTrustScore -ge 2
                            
                            return @{
                                Compliant = $compliant
                                Details = @{
                                    ExplicitVerification = $explicitVerification
                                    LeastPrivilege = $leastPrivilege
                                    AssumeBreach = $assumeBreach
                                    ZeroTrustScore = $zeroTrustScore
                                }
                                Reason = if ($compliant) {
                                    "Found $zeroTrustScore of 3 Zero Trust principles implemented"
                                } else {
                                    "Only found $zeroTrustScore of 3 Zero Trust principles implemented"
                                }
                                Recommendation = if (-not $compliant) {
                                    if (-not $explicitVerification) {
                                        "Implement MFA and risk-based policies (Verify Explicitly principle)"
                                    } elseif (-not $leastPrivilege) {
                                        "Implement role-specific policies (Least Privilege principle)"
                                    } elseif (-not $assumeBreach) {
                                        "Implement session controls and device compliance (Assume Breach principle)"
                                    } else {
                                        "Implement more Zero Trust principles in your Conditional Access policies"
                                    }
                                } else {
                                    if ($zeroTrustScore -lt 3) {
                                        "Continue enhancing Zero Trust implementation by adding the missing principle"
                                    } else {
                                        $null
                                    }
                                }
                            }
                        }
                    }
                )
            }
        )
        
        # Evaluate each CIS control
        $results = @()
        
        foreach ($control in $cisControls) {
            $subResults = @()
            
            foreach ($subControl in $control.SubControls) {
                try {
                    $evaluation = & $subControl.Evaluation $Policies
                    
                    $subResult = [PSCustomObject]@{
                        ControlId = "$($control.Id).$($subControl.Id)"
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
                        ControlId = "$($control.Id).$($subControl.Id)"
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
            Version = "CIS Controls v8 with 2025 enhancements"
            Framework = "CIS"
        }
    }
}
