# CIS.ps1 - CIS Controls benchmark definitions for Conditional Access

function Test-CISBenchmark {
    <#
    .SYNOPSIS
        Tests Conditional Access policies against CIS Controls.
    .DESCRIPTION
        Evaluates Conditional Access policies against the CIS Controls framework
        to determine compliance with industry best practices.
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
        Write-Verbose "Evaluating Conditional Access policies against CIS Controls"
        
        # Define CIS Controls relevant to Conditional Access
        $cisControls = @(
            @{
                Id = "CIS 5"
                Name = "Account Management"
                Description = "Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts, and service accounts."
                SubControls = @(
                    @{
                        Id = "5.3"
                        Name = "Require Multi-Factor Authentication for Administrative Access"
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
                            
                            return @{
                                Compliant = $compliant
                                Details = $adminSpecificPolicies
                                Reason = if ($compliant) {
                                    "Admin-specific Conditional Access policies found: $($adminSpecificPolicies.Count)"
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
                    }
                )
            },
            @{
                Id = "CIS 6"
                Name = "Access Control Management"
                Description = "Use processes and tools to create, assign, manage, and revoke access credentials and privileges."
                SubControls = @(
                    @{
                        Id = "6.5"
                        Name = "Require Multi-Factor Authentication for All Users"
                        Evaluation = {
                            param($Policies)
                            
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
                        Id = "6.7"
                        Name = "Disable Access for Non-Consumer Identity Sources"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies that restrict external/guest users
                            $externalUserPolicies = $Policies | Where-Object {
                                ($_.State -eq "enabled") -and
                                ($null -ne $_.Conditions.Users) -and
                                ($_.Conditions.Users.IncludeUsers -contains "GuestsOrExternalUsers")
                            }
                            
                            # We can't fully determine compliance, but having guest-specific
                            # policies is a good indicator
                            $compliant = $externalUserPolicies.Count -gt 0
                            
                            return @{
                                Compliant = $compliant
                                Details = $externalUserPolicies
                                Reason = if ($compliant) {
                                    "Guest/external user policies found: $($externalUserPolicies.Count)"
                                } else {
                                    "No policies specifically targeting guest/external users"
                                }
                                Recommendation = if (-not $compliant) {
                                    "Create Conditional Access policies that provide additional security controls for guest and external users"
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
                        Id = "10.5"
                        Name = "Enable Anti-Exploitation Features"
                        Evaluation = {
                            param($Policies)
                            
                            # Look for policies that require compliant devices
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
                Id = "CIS 13"
                Name = "Network Monitoring and Defense"
                Description = "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense."
                SubControls = @(
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
                            
                            # Not enough information to fully determine compliance
                            # so partial credit for having location-based policies
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
                                    "Create location-based Conditional Access policies to help separate production and non-production environments"
                                } else {
                                    $null
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
        }
    }
}
