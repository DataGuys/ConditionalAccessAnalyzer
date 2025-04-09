# PolicyEvaluation.ps1 - Contains functions for evaluating Conditional Access policies

function Test-PolicyRequiresMFA {
    <#
    .SYNOPSIS
        Tests if a policy requires MFA.
    .DESCRIPTION
        Analyzes a Conditional Access policy to determine if it requires MFA.
    .PARAMETER Policy
        The policy object to evaluate.
    .EXAMPLE
        $requiresMFA = Test-PolicyRequiresMFA -Policy $policyObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy
    )
    
    process {
        if (-not $Policy.GrantControls) {
            return $false
        }
        
        if ($Policy.GrantControls.BuiltInControls -contains "mfa") {
            return $true
        }
        
        return $false
    }
}

function Test-PolicyTargetsAdmins {
    <#
    .SYNOPSIS
        Tests if a policy targets administrative roles.
    .DESCRIPTION
        Analyzes a Conditional Access policy to determine if it targets admin roles.
    .PARAMETER Policy
        The policy object to evaluate.
    .PARAMETER AdminRoleIds
        Optional array of admin role IDs to check against.
    .EXAMPLE
        $targetsAdmins = Test-PolicyTargetsAdmins -Policy $policyObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AdminRoleIds
    )
    
    process {
        if (-not $Policy.Conditions -or -not $Policy.Conditions.Users) {
            return $false
        }
        
        # If no admin role IDs provided, get them
        if (-not $AdminRoleIds -or $AdminRoleIds.Count -eq 0) {
            try {
                $roles = Get-AdminRoles -PrivilegedOnly
                $AdminRoleIds = $roles.Id
            }
            catch {
                Write-Warning "Failed to retrieve admin roles: $_"
                # Default to Global Admin and Privileged Role Admin
                $AdminRoleIds = @(
                    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                    "e8611ab8-c189-46e8-94e1-60213ab1f814"   # Privileged Role Administrator
                )
            }
        }
        
        # Check if policy includes any admin roles
        if ($Policy.Conditions.Users.IncludeRoles) {
            foreach ($role in $Policy.Conditions.Users.IncludeRoles) {
                if ($AdminRoleIds -contains $role) {
                    return $true
                }
            }
        }
        
        # Check if policy applies to all users and doesn't exclude admin roles
        if ($Policy.Conditions.Users.IncludeUsers -contains "All") {
            if ($Policy.Conditions.Users.ExcludeRoles) {
                # Check if any admin roles are excluded
                $adminRolesExcluded = $false
                foreach ($adminRole in $AdminRoleIds) {
                    if ($Policy.Conditions.Users.ExcludeRoles -contains $adminRole) {
                        $adminRolesExcluded = $true
                        break
                    }
                }
                
                # If no admin roles are excluded, the policy applies to admins
                return -not $adminRolesExcluded
            }
            
            # No exclusions, so the policy applies to all users including admins
            return $true
        }
        
        return $false
    }
}

function Test-PolicyRequiresCompliantDevice {
    <#
    .SYNOPSIS
        Tests if a policy requires a compliant device.
    .DESCRIPTION
        Analyzes a Conditional Access policy to determine if it requires device compliance.
    .PARAMETER Policy
        The policy object to evaluate.
    .EXAMPLE
        $requiresCompliance = Test-PolicyRequiresCompliantDevice -Policy $policyObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy
    )
    
    process {
        if (-not $Policy.GrantControls) {
            return $false
        }
        
        if ($Policy.GrantControls.BuiltInControls -contains "compliantDevice" -or 
            $Policy.GrantControls.BuiltInControls -contains "domainJoinedDevice") {
            return $true
        }
        
        return $false
    }
}

function Test-PolicyUsesRiskDetection {
    <#
    .SYNOPSIS
        Tests if a policy uses risk detection.
    .DESCRIPTION
        Analyzes a Conditional Access policy to determine if it uses sign-in
        or user risk detection.
    .PARAMETER Policy
        The policy object to evaluate.
    .PARAMETER RiskType
        The type of risk to check for (SignIn, User, or Any).
    .EXAMPLE
        $usesRisk = Test-PolicyUsesRiskDetection -Policy $policyObject -RiskType Any
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("SignIn", "User", "Any")]
        [string]$RiskType = "Any"
    )
    
    process {
        if (-not $Policy.Conditions) {
            return $false
        }
        
        switch ($RiskType) {
            "SignIn" {
                return $null -ne $Policy.Conditions.SignInRisk -and 
                       $null -ne $Policy.Conditions.SignInRisk.RiskLevels -and 
                       $Policy.Conditions.SignInRisk.RiskLevels.Count -gt 0
            }
            "User" {
                return $null -ne $Policy.Conditions.UserRiskLevels -and 
                       $Policy.Conditions.UserRiskLevels.Count -gt 0
            }
            "Any" {
                $signInRisk = $null -ne $Policy.Conditions.SignInRisk -and 
                              $null -ne $Policy.Conditions.SignInRisk.RiskLevels -and 
                              $Policy.Conditions.SignInRisk.RiskLevels.Count -gt 0
                              
                $userRisk = $null -ne $Policy.Conditions.UserRiskLevels -and 
                            $Policy.Conditions.UserRiskLevels.Count -gt 0
                            
                return $signInRisk -or $userRisk
            }
        }
    }
}

function Test-PolicyHasSessionControls {
    <#
    .SYNOPSIS
        Tests if a policy has session controls.
    .DESCRIPTION
        Analyzes a Conditional Access policy to determine if it implements
        any session controls.
    .PARAMETER Policy
        The policy object to evaluate.
    .PARAMETER ControlType
        The type of control to check for (All or specific control).
    .EXAMPLE
        $hasControls = Test-PolicyHasSessionControls -Policy $policyObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "SignInFrequency", "PersistentBrowser", "CloudAppSecurity", "AppEnforcedRestrictions")]
        [string]$ControlType = "All"
    )
    
    process {
        if (-not $Policy.SessionControls) {
            return $false
        }
        
        switch ($ControlType) {
            "SignInFrequency" {
                return $null -ne $Policy.SessionControls.SignInFrequency -and 
                       $Policy.SessionControls.SignInFrequency.IsEnabled -eq $true
            }
            "PersistentBrowser" {
                return $null -ne $Policy.SessionControls.PersistentBrowser -and 
                       $Policy.SessionControls.PersistentBrowser.IsEnabled -eq $true
            }
            "CloudAppSecurity" {
                return $null -ne $Policy.SessionControls.CloudAppSecurity -and 
                       $Policy.SessionControls.CloudAppSecurity.IsEnabled -eq $true
            }
            "AppEnforcedRestrictions" {
                return $null -ne $Policy.SessionControls.ApplicationEnforcedRestrictions -and 
                       $Policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled -eq $true
            }
            "All" {
                return ($null -ne $Policy.SessionControls.SignInFrequency -and $Policy.SessionControls.SignInFrequency.IsEnabled -eq $true) -or
                       ($null -ne $Policy.SessionControls.PersistentBrowser -and $Policy.SessionControls.PersistentBrowser.IsEnabled -eq $true) -or
                       ($null -ne $Policy.SessionControls.CloudAppSecurity -and $Policy.SessionControls.CloudAppSecurity.IsEnabled -eq $true) -or
                       ($null -ne $Policy.SessionControls.ApplicationEnforcedRestrictions -and $Policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled -eq $true)
            }
        }
    }
}

function Test-PolicyAppliesToAllUsers {
    <#
    .SYNOPSIS
        Tests if a policy applies to all users.
    .DESCRIPTION
        Analyzes a Conditional Access policy to determine if it applies to all users.
    .PARAMETER Policy
        The policy object to evaluate.
    .EXAMPLE
        $appliesToAll = Test-PolicyAppliesToAllUsers -Policy $policyObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy
    )
    
    process {
        if (-not $Policy.Conditions -or -not $Policy.Conditions.Users) {
            return $false
        }
        
        return $Policy.Conditions.Users.IncludeUsers -contains "All"
    }
}

function Test-PolicyHasBroadAppCoverage {
    <#
    .SYNOPSIS
        Tests if a policy has broad application coverage.
    .DESCRIPTION
        Analyzes a Conditional Access policy to determine if it applies broadly to applications.
    .PARAMETER Policy
        The policy object to evaluate.
    .EXAMPLE
        $hasBroadCoverage = Test-PolicyHasBroadAppCoverage -Policy $policyObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy
    )
    
    process {
        if (-not $Policy.Conditions -or -not $Policy.Conditions.Applications) {
            return $false
        }
        
        return $Policy.Conditions.Applications.IncludeApplications -contains "All" -or 
               $Policy.Conditions.Applications.IncludeApplications -contains "Office365"
    }
}

function Measure-PolicyEffectiveness {
    <#
    .SYNOPSIS
        Evaluates the overall effectiveness of a Conditional Access policy.
    .DESCRIPTION
        Performs a comprehensive analysis of a policy to determine its effectiveness
        for security and assigns a score.
    .PARAMETER Policy
        The policy object to evaluate.
    .PARAMETER MaxScore
        The maximum score for the evaluation.
    .EXAMPLE
        $effectiveness = Evaluate-PolicyEffectiveness -Policy $policyObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Policy,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxScore = 100
    )
    
    process {
        if ($Policy.State -ne "enabled") {
            # Policy is not active
            return @{
                Score = 0
                Evaluation = "Policy is not enabled"
                Details = @{
                    State = $Policy.State
                }
            }
        }
        
        $score = 0
        $evaluationDetails = @{}
        
        # User coverage (max 25 points)
        if (Test-PolicyAppliesToAllUsers -Policy $Policy) {
            $score += 25
            $evaluationDetails["UserCoverage"] = "All users (25/25)"
        }
        elseif ($Policy.Conditions.Users.IncludeRoles -and $Policy.Conditions.Users.IncludeRoles.Count -gt 0) {
            $score += 15
            $evaluationDetails["UserCoverage"] = "Admin roles (15/25)"
        }
        elseif ($Policy.Conditions.Users.IncludeGroups -and $Policy.Conditions.Users.IncludeGroups.Count -gt 0) {
            $score += 10
            $evaluationDetails["UserCoverage"] = "Specific groups (10/25)"
        }
        elseif ($Policy.Conditions.Users.IncludeUsers -and $Policy.Conditions.Users.IncludeUsers.Count -gt 0 -and 
                $Policy.Conditions.Users.IncludeUsers -notcontains "All" -and 
                $Policy.Conditions.Users.IncludeUsers -notcontains "None") {
            $score += 5
            $evaluationDetails["UserCoverage"] = "Specific users (5/25)"
        }
        else {
            $evaluationDetails["UserCoverage"] = "Limited user coverage (0/25)"
        }
        
        # Application coverage (max 25 points)
        if ($Policy.Conditions.Applications.IncludeApplications -contains "All") {
            $score += 25
            $evaluationDetails["AppCoverage"] = "All applications (25/25)"
        }
        elseif ($Policy.Conditions.Applications.IncludeApplications -contains "Office365") {
            $score += 20
            $evaluationDetails["AppCoverage"] = "Microsoft 365 (20/25)"
        }
        elseif ($Policy.Conditions.Applications.IncludeApplications.Count -gt 5) {
            $score += 15
            $evaluationDetails["AppCoverage"] = "Multiple applications (15/25)"
        }
        elseif ($Policy.Conditions.Applications.IncludeApplications.Count -gt 0) {
            $score += 10
            $evaluationDetails["AppCoverage"] = "Limited applications (10/25)"
        }
        else {
            $evaluationDetails["AppCoverage"] = "No application coverage (0/25)"
        }
        
        # Security controls (max 50 points)
        $securityScore = 0
        
        if (Test-PolicyRequiresMFA -Policy $Policy) {
            $securityScore += 20
            $evaluationDetails["MFA"] = "Requires MFA (20 points)"
        }
        
        if (Test-PolicyRequiresCompliantDevice -Policy $Policy) {
            $securityScore += 15
            $evaluationDetails["DeviceCompliance"] = "Requires compliant device (15 points)"
        }
        
        if (Test-PolicyUsesRiskDetection -Policy $Policy -RiskType "SignIn") {
            $securityScore += 10
            $evaluationDetails["SignInRisk"] = "Uses sign-in risk detection (10 points)"
        }
        
        if (Test-PolicyUsesRiskDetection -Policy $Policy -RiskType "User") {
            $securityScore += 10
            $evaluationDetails["UserRisk"] = "Uses user risk detection (10 points)"
        }
        
        if (Test-PolicyHasSessionControls -Policy $Policy) {
            $securityScore += 5
            $evaluationDetails["SessionControls"] = "Has session controls (5 points)"
        }
        
        # Cap security score at 50
        $securityScore = [Math]::Min(50, $securityScore)
        $score += $securityScore
        $evaluationDetails["SecurityScore"] = "$securityScore/50"
        
        # Determine effectiveness level
        $effectivenessLevel = switch ($score) {
            { $_ -ge 90 } { "Excellent" }
            { $_ -ge 80 } { "Good" }
            { $_ -ge 70 } { "Fair" }
            { $_ -ge 60 } { "Poor" }
            default { "Critical" }
        }
        
        # Recommendations
        $recommendations = @()
        
        if (-not (Test-PolicyRequiresMFA -Policy $Policy)) {
            $recommendations += "Consider requiring MFA for stronger authentication"
        }
        
        if (-not (Test-PolicyRequiresCompliantDevice -Policy $Policy)) {
            $recommendations += "Consider requiring compliant devices for stronger endpoint security"
        }
        
        if (-not (Test-PolicyUsesRiskDetection -Policy $Policy -RiskType "Any")) {
            $recommendations += "Consider using risk-based conditions to enhance security"
        }
        
        if (-not (Test-PolicyHasSessionControls -Policy $Policy)) {
            $recommendations += "Consider adding session controls like sign-in frequency"
        }
        
        # Normalize score if needed
        if ($MaxScore -ne 100) {
            $score = [Math]::Round(($score / 100) * $MaxScore)
        }
        
        return @{
            Score = $score
            MaxScore = $MaxScore
            Evaluation = $effectivenessLevel
            Details = $evaluationDetails
            Recommendations = $recommendations
        }
    }
}
