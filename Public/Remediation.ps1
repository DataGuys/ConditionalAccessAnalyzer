function Invoke-CAComplianceRemediation {
    <#
    .SYNOPSIS
        Automatically remediates Conditional Access compliance issues.
    .DESCRIPTION
        Analyzes Conditional Access configuration, identifies security gaps,
        and automatically fixes them by creating or updating policies according to
        security best practices.
    .PARAMETER Results
        The compliance check results to remediate. If not specified, Invoke-CAComplianceCheck is run.
    .PARAMETER IncludeAdminMFA
        If specified, remediates administrator MFA issues.
    .PARAMETER IncludeUserMFA
        If specified, remediates regular user MFA issues.
    .PARAMETER IncludeDeviceCompliance
        If specified, remediates device compliance issues.
    .PARAMETER IncludeTokenBinding
        If specified, remediates token session binding issues.
    .PARAMETER IncludeRiskPolicies
        If specified, remediates risk-based access issues.
    .PARAMETER IncludeMAMPolicies
        If specified, remediates Mobile Application Management issues.
    .PARAMETER IncludeZeroTrust
        If specified, remediates Zero Trust Network Access issues.
    .PARAMETER RemediateAll
        If specified, remediates all identified issues.
    .PARAMETER ExcludeUsers
        Specifies which users to exclude from the remediated policies.
    .PARAMETER ExcludeGroups
        Specifies which groups to exclude from the remediated policies.
    .PARAMETER DeployInReportOnlyMode
        If specified, policies are created in "enabledForReportingButNotEnforced" state.
    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet doesn't make any changes.
    .PARAMETER Force
        If specified, any confirmations are suppressed.
    .EXAMPLE
        Invoke-CAComplianceRemediation -RemediateAll -DeployInReportOnlyMode
        Remediates all compliance issues with policies created in report-only mode.
    .EXAMPLE
        Invoke-CAComplianceRemediation -IncludeAdminMFA -IncludeUserMFA
        Remediates only MFA-related compliance issues.
    .NOTES
        The remediation follows industry security best practices and implements the
        recommendations provided by the compliance check. Only missing policies are 
        created, and existing ones are not modified unless specifically requested.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeAdminMFA,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeUserMFA,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDeviceCompliance,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTokenBinding,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRiskPolicies,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeMAMPolicies,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeZeroTrust,
        
        [Parameter(Mandatory = $false)]
        [switch]$RemediateAll,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeUsers,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeGroups,
        
        [Parameter(Mandatory = $false)]
        [switch]$DeployInReportOnlyMode,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # Check if required permissions are available
        $requiredPermission = "Policy.ReadWrite.ConditionalAccess"
        $context = Get-MgContext
        if ($context.Scopes -notcontains $requiredPermission) {
            throw "The current connection does not have the required permission: $requiredPermission. Please reconnect with the appropriate scope."
        }
        
        # If no results provided, run the compliance check
        if (-not $Results) {
            Write-Host "No results provided. Running comprehensive Conditional Access compliance check..." -ForegroundColor Yellow
            $Results = Invoke-CAComplianceCheck
        }
        
        # Determine policy state
        $policyState = if ($DeployInReportOnlyMode) { "enabledForReportingButNotEnforced" } else { "enabled" }
        
        # Create empty lists for exclusions if not specified
        if (-not $ExcludeUsers) {
            $ExcludeUsers = @()
        }
        
        if (-not $ExcludeGroups) {
            $ExcludeGroups = @()
        }
        
        # Create empty list for remediation actions
        $remediationActions = @()
        
        # Function to add a remediation action
        function Add-RemediationAction {
            param (
                [string]$Issue,
                [string]$Action,
                [string]$PolicyType,
                [bool]$Required,
                [string]$Recommendation
            )
            
            $remediationActions += [PSCustomObject]@{
                Issue = $Issue
                Action = $Action
                PolicyType = $PolicyType
                Required = $Required
                Recommendation = $Recommendation
            }
        }
    }
    
    process {
        try {
            Write-Host "Analyzing Conditional Access compliance issues for remediation..." -ForegroundColor Cyan
            
            # Check Admin MFA
            if ($RemediateAll -or $IncludeAdminMFA) {
                if (-not $Results.Checks.AdminMFA.AdminMFARequired) {
                    Add-RemediationAction -Issue "Admin MFA not required" -Action "Create AdminMFA policy" -PolicyType "AdminMFA" -Required $true -Recommendation $Results.Checks.AdminMFA.Recommendation
                }
                else {
                    Write-Host "✓ Admin MFA is already properly configured." -ForegroundColor Green
                }
            }
            
            # Check User MFA
            if ($RemediateAll -or $IncludeUserMFA) {
                if (-not $Results.Checks.UserMFA.BroadUserMFARequired) {
                    Add-RemediationAction -Issue "User MFA not broadly required" -Action "Create UserMFA policy" -PolicyType "UserMFA" -Required $true -Recommendation $Results.Checks.UserMFA.Recommendation
                }
                else {
                    Write-Host "✓ User MFA is already properly configured." -ForegroundColor Green
                }
            }
            
            # Check Device Compliance
            if ($RemediateAll -or $IncludeDeviceCompliance) {
                if (-not $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) {
                    Add-RemediationAction -Issue "Device compliance not required" -Action "Create DeviceCompliance policy" -PolicyType "DeviceCompliance" -Required $true -Recommendation $Results.Checks.DeviceCompliance.Recommendation
                }
                else {
                    Write-Host "✓ Device compliance is already properly configured." -ForegroundColor Green
                }
            }
            
            # Check Token Session Binding
            if ($RemediateAll -or $IncludeTokenBinding) {
                if (-not $Results.Checks.TokenBinding.TokenSessionBindingConfigured) {
                    Add-RemediationAction -Issue "Token session binding not configured" -Action "Create TokenBinding policy" -PolicyType "TokenBinding" -Required $false -Recommendation $Results.Checks.TokenBinding.Recommendation
                }
                else {
                    Write-Host "✓ Token session binding is already properly configured." -ForegroundColor Green
                }
            }
            
            # Check Risk-Based Policies
            if ($RemediateAll -or $IncludeRiskPolicies) {
                if (-not $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured) {
                    Add-RemediationAction -Issue "Sign-in risk policies not configured" -Action "Create SignInRisk policy" -PolicyType "SignInRisk" -Required $true -Recommendation "Configure CA policy based on sign-in risk to protect against suspicious sign-in attempts"
                }
                else {
                    Write-Host "✓ Sign-in risk policies are already properly configured." -ForegroundColor Green
                }
                
                if (-not $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) {
                    Add-RemediationAction -Issue "User risk policies not configured" -Action "Create UserRisk policy" -PolicyType "UserRisk" -Required $true -Recommendation "Configure CA policy based on user risk to protect compromised accounts"
                }
                else {
                    Write-Host "✓ User risk policies are already properly configured." -ForegroundColor Green
                }
            }
            
            # Check MAM Policies
            if ($RemediateAll -or $IncludeMAMPolicies) {
                if (-not $Results.Checks.MAMPolicies.MAMPoliciesConfigured) {
                    Add-RemediationAction -Issue "Mobile Application Management not configured" -Action "Create MAMPolicy" -PolicyType "MAMPolicy" -Required $false -Recommendation $Results.Checks.MAMPolicies.Recommendation
                }
                else {
                    Write-Host "✓ Mobile Application Management is already properly configured." -ForegroundColor Green
                }
            }
            
            # Check Zero Trust Network Access
            if ($RemediateAll -or $IncludeZeroTrust) {
                if (-not $Results.Checks.ZeroTrust.MDCAIntegrated) {
                    Add-RemediationAction -Issue "MDCA not integrated" -Action "Create CloudAppSecurity policy" -PolicyType "CloudAppSecurity" -Required $false -Recommendation "Configure Microsoft Defender for Cloud Apps integration with Conditional Access"
                }
                else {
                    Write-Host "✓ Microsoft Defender for Cloud Apps integration is already properly configured." -ForegroundColor Green
                }
                
                if (-not $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) {
                    Add-RemediationAction -Issue "Global Secure Access not configured" -Action "Create GlobalSecureAccess policy" -PolicyType "GlobalSecureAccess" -Required $false -Recommendation "Set up Global Secure Access policies for Zero Trust Network Access"
                }
                else {
                    Write-Host "✓ Global Secure Access is already properly configured." -ForegroundColor Green
                }
            }
            
            # Display remediation actions
            if ($remediationActions.Count -gt 0) {
                Write-Host "`nProposed remediation actions:" -ForegroundColor Cyan
                
                foreach ($action in $remediationActions) {
                    $prioritySymbol = if ($action.Required) { "!" } else { "?" }
                    Write-Host " [$prioritySymbol] $($action.Issue): $($action.Action)" -ForegroundColor $(if ($action.Required) { "Yellow" } else { "Gray" })
                }
                
                # Get confirmation for remediation
                if (-not $Force) {
                    $confirmation = Read-Host "`nDo you want to proceed with remediation? (Y/N)"
                    if ($confirmation -ne "Y") {
                        Write-Host "Remediation cancelled." -ForegroundColor Red
                        return
                    }
                }
                
                # Apply remediation actions
                Write-Host "`nApplying remediation actions..." -ForegroundColor Cyan
                
                $createdPolicies = @()
                foreach ($action in $remediationActions) {
                    Write-Host "Remediating: $($action.Issue)..." -ForegroundColor Yellow
                    
                    $policyTypeParams = @{
                        PolicyType = $action.PolicyType
                        State = $policyState
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        DeployPolicy = $true
                        PassThru = $true
                    }
                    
                    if ($PSCmdlet.ShouldProcess("Entra ID", "Create $($action.PolicyType) policy to remediate: $($action.Issue)")) {
                        try {
                            $policy = New-CABestPracticePolicy @policyTypeParams
                            $createdPolicies += $policy
                            Write-Host "  ✓ Successfully created $($action.PolicyType) policy." -ForegroundColor Green
                        }
                        catch {
                            Write-Error "  ✗ Failed to create $($action.PolicyType) policy: $_"
                        }
                    }
                }
                
                # Display summary
                Write-Host "`nRemediation Summary:" -ForegroundColor Cyan
                Write-Host "Total issues found: $($remediationActions.Count)" -ForegroundColor White
                Write-Host "Successfully remediated: $($createdPolicies.Count)" -ForegroundColor Green
                Write-Host "Failed: $($remediationActions.Count - $createdPolicies.Count)" -ForegroundColor $(if ($remediationActions.Count - $createdPolicies.Count -gt 0) { "Red" } else { "Green" })
                
                # Return remediation results
                return [PSCustomObject]@{
                    TotalIssues = $remediationActions.Count
                    Remediated = $createdPolicies.Count
                    Failed = $remediationActions.Count - $createdPolicies.Count
                    CreatedPolicies = $createdPolicies
                    RemediationActions = $remediationActions
                }
            }
            else {
                Write-Host "`nNo remediation actions required. All selected policies are already properly configured." -ForegroundColor Green
                return [PSCustomObject]@{
                    TotalIssues = 0
                    Remediated = 0
                    Failed = 0
                    CreatedPolicies = @()
                    RemediationActions = @()
                }
            }
        }
        catch {
            Write-Error "Failed to remediate Conditional Access compliance issues: $_"
            throw
        }
    }
}

function Set-CAEmergencyAccess {
    <#
    .SYNOPSIS
        Configures emergency access exclusions for Conditional Access policies.
    .DESCRIPTION
        Identifies existing emergency access accounts and adds them to exclusion lists
        in Conditional Access policies to ensure administrator access during emergencies.
    .PARAMETER PolicyIds
        Specific policy IDs to update with emergency access exclusions. If not specified, all enabled policies are updated.
    .PARAMETER EmergencyUsers
        Specific users to mark as emergency access accounts. If not specified, accounts with "emergency" in the display name or UPN are used.
    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet doesn't make any changes.
    .PARAMETER Force
        If specified, any confirmations are suppressed.
    .EXAMPLE
        Set-CAEmergencyAccess
        Updates all enabled Conditional Access policies with emergency access exclusions.
    .EXAMPLE
        Set-CAEmergencyAccess -PolicyIds "00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111"
        Updates specific policies with emergency access exclusions.
    .NOTES
        Emergency access accounts should be configured according to Microsoft recommendations.
        See https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access for details.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$PolicyIds,
        
        [Parameter(Mandatory = $false)]
        [string[]]$EmergencyUsers,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # Check if required permissions are available
        $requiredPermission = "Policy.ReadWrite.ConditionalAccess"
        $context = Get-MgContext
        if ($context.Scopes -notcontains $requiredPermission) {
            throw "The current connection does not have the required permission: $requiredPermission. Please reconnect with the appropriate scope."
        }
        
        # Function to identify emergency access accounts
        function Get-EmergencyAccessAccounts {
            param (
                [string[]]$SpecifiedUsers
            )
            
            $emergencyAccounts = @()
            
            # Use specified users if provided
            if ($SpecifiedUsers -and $SpecifiedUsers.Count -gt 0) {
                foreach ($user in $SpecifiedUsers) {
                    try {
                        if ($user -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                            # It's already an ID
                            $userId = $user
                            $userObj = Get-MgUser -UserId $userId -ErrorAction SilentlyContinue
                            if ($userObj) {
                                $emergencyAccounts += [PSCustomObject]@{
                                    Id = $userId
                                    DisplayName = $userObj.DisplayName
                                    UserPrincipalName = $userObj.UserPrincipalName
                                }
                            }
                        }
                        else {
                            # Try to find by UPN or display name
                            $userObj = Get-MgUser -Filter "userPrincipalName eq '$user' or displayName eq '$user'" -ErrorAction SilentlyContinue
                            if ($userObj) {
                                $emergencyAccounts += [PSCustomObject]@{
                                    Id = $userObj.Id
                                    DisplayName = $userObj.DisplayName
                                    UserPrincipalName = $userObj.UserPrincipalName
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Could not find user: $user. $_"
                    }
                }
            }
            else {
                # Find users with "emergency" in the display name or UPN
                $users = Get-MgUser -Filter "startswith(displayName, 'emergency') or contains(displayName, 'emergency') or startswith(userPrincipalName, 'emergency') or contains(userPrincipalName, 'emergency')" -ErrorAction SilentlyContinue
                foreach ($user in $users) {
                    $emergencyAccounts += [PSCustomObject]@{
                        Id = $user.Id
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                    }
                }
                
                # Find users with "break glass" in the display name or UPN
                $users = Get-MgUser -Filter "contains(displayName, 'break glass') or contains(userPrincipalName, 'breakglass')" -ErrorAction SilentlyContinue
                foreach ($user in $users) {
                    $emergencyAccounts += [PSCustomObject]@{
                        Id = $user.Id
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                    }
                }
            }
            
            return $emergencyAccounts
        }
    }
    
    process {
        try {
            # Get emergency access accounts
            $emergencyAccounts = Get-EmergencyAccessAccounts -SpecifiedUsers $EmergencyUsers
            
            if ($emergencyAccounts.Count -eq 0) {
                Write-Warning "No emergency access accounts found. Please create dedicated emergency access accounts or specify them using the -EmergencyUsers parameter."
                return
            }
            
            Write-Host "Found $($emergencyAccounts.Count) emergency access accounts:" -ForegroundColor Cyan
            foreach ($account in $emergencyAccounts) {
                Write-Host "  - $($account.DisplayName) ($($account.UserPrincipalName))" -ForegroundColor White
            }
            
            # Get policies to update
            $policies = @()
            if ($PolicyIds -and $PolicyIds.Count -gt 0) {
                foreach ($id in $PolicyIds) {
                    $policy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $id -ErrorAction SilentlyContinue
                    if ($policy) {
                        $policies += $policy
                    }
                    else {
                        Write-Warning "Policy with ID $id not found."
                    }
                }
            }
            else {
                $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
            }
            
            if ($policies.Count -eq 0) {
                Write-Warning "No policies found to update."
                return
            }
            
            Write-Host "Found $($policies.Count) policies to update." -ForegroundColor Cyan
            
            # Get confirmation for update
            if (-not $Force) {
                $confirmation = Read-Host "`nDo you want to add emergency access exclusions to $($policies.Count) policies? (Y/N)"
                if ($confirmation -ne "Y") {
                    Write-Host "Update cancelled." -ForegroundColor Red
                    return
                }
            }
            
            # Update policies
            $updatedPolicies = @()
            $skippedPolicies = @()
            $emergencyUserIds = $emergencyAccounts.Id
            
            foreach ($policy in $policies) {
                Write-Host "Processing policy: $($policy.DisplayName)..." -ForegroundColor Yellow
                
                # Clone users condition to avoid modifying the original
                $usersCondition = $policy.Conditions.Users
                
                # Check if any emergency account is already in exclusions
                $existingExclusions = @()
                $needsUpdate = $true
                
                if ($usersCondition.ExcludeUsers) {
                    # Find the intersection of emergency users and excluded users
                    $existingExclusions = $emergencyUserIds | Where-Object { $usersCondition.ExcludeUsers -contains $_ }
                    
                    if ($existingExclusions.Count -eq $emergencyUserIds.Count) {
                        Write-Host "  ✓ All emergency access accounts are already excluded." -ForegroundColor Green
                        $needsUpdate = $false
                        $skippedPolicies += $policy
                    }
                }
                
                if ($needsUpdate) {
                    # Add emergency users to exclusions
                    $updatedExcludeUsers = if ($usersCondition.ExcludeUsers) { 
                        $usersCondition.ExcludeUsers 
                    } else { 
                        @() 
                    }
                    
                    # Add any missing emergency users
                    foreach ($userId in $emergencyUserIds) {
                        if ($updatedExcludeUsers -notcontains $userId) {
                            $updatedExcludeUsers += $userId
                        }
                    }
                    
                    # Prepare update payload
                    $updateParams = @{
                        Conditions = @{
                            Users = @{
                                ExcludeUsers = $updatedExcludeUsers
                            }
                        }
                    }
                    
                    # Update the policy
                    if ($PSCmdlet.ShouldProcess("Entra ID", "Update policy '$($policy.DisplayName)' with emergency access exclusions")) {
                        try {
                            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $updateParams
                            Write-Host "  ✓ Successfully updated policy with emergency access exclusions." -ForegroundColor Green
                            $updatedPolicies += $policy
                        }
                        catch {
                            Write-Error "  ✗ Failed to update policy: $_"
                        }
                    }
                }
            }
            
            # Display summary
            Write-Host "`nUpdate Summary:" -ForegroundColor Cyan
            Write-Host "Emergency accounts found: $($emergencyAccounts.Count)" -ForegroundColor White
            Write-Host "Policies processed: $($policies.Count)" -ForegroundColor White
            Write-Host "Policies updated: $($updatedPolicies.Count)" -ForegroundColor Green
            Write-Host "Policies already configured: $($skippedPolicies.Count)" -ForegroundColor Gray
            
            # Return update results
            return [PSCustomObject]@{
                EmergencyAccounts = $emergencyAccounts
                TotalPolicies = $policies.Count
                UpdatedPolicies = $updatedPolicies
                SkippedPolicies = $skippedPolicies
            }
        }
        catch {
            Write-Error "Failed to configure emergency access exclusions: $_"
            throw
        }
    }
}

function Set-CAStaggeredRollout {
    <#
    .SYNOPSIS
        Configures a staged rollout plan for Conditional Access policies.
    .DESCRIPTION
        Creates a series of policies with increasing scope and security controls
        to enable a phased rollout of Conditional Access across the organization.
        This minimizes user disruption and helps validate the impact of changes.
    .PARAMETER PolicyType
        The type of policy to deploy. Valid values include MFA, DeviceCompliance, etc.
    .PARAMETER StagingGroups
        An array of group IDs for each stage of the rollout. Minimum 2 groups.
    .PARAMETER StagingDays
        The number of days between each stage. Default is 7.
    .PARAMETER FinalState
        The final state of the policies after all stages. Default is "enabled".
    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet doesn't make any changes.
    .PARAMETER Force
        If specified, any confirmations are suppressed.
    .EXAMPLE
        $pilotGroup = (Get-MgGroup -Filter "displayName eq 'Pilot Users'").Id
        $phase1Group = (Get-MgGroup -Filter "displayName eq 'Sales'").Id
        $phase2Group = (Get-MgGroup -Filter "displayName eq 'Marketing'").Id
        Set-CAStaggeredRollout -PolicyType UserMFA -StagingGroups $pilotGroup, $phase1Group, $phase2Group
    .NOTES
        The staged rollout first deploys policies in report-only mode, then
        gradually transitions them to enforcement mode.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('UserMFA', 'DeviceCompliance', 'TokenBinding', 'SignInRisk', 'UserRisk', 'MAMPolicy')]
        [string]$PolicyType,
        
        [Parameter(Mandatory = $true)]
        [ValidateCount(2, 10)]
        [string[]]$StagingGroups,
        
        [Parameter(Mandatory = $false)]
        [int]$StagingDays = 7,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'enabledForReportingButNotEnforced')]
        [string]$FinalState = 'enabled',
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # Check if required permissions are available
        $requiredPermission = "Policy.ReadWrite.ConditionalAccess"
        $context = Get-MgContext
        if ($context.Scopes -notcontains $requiredPermission) {
            throw "The current connection does not have the required permission: $requiredPermission. Please reconnect with the appropriate scope."
        }
        
        # Validate staging groups
        $validGroups = @()
        foreach ($groupId in $StagingGroups) {
            $group = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue
            if ($group) {
                $validGroups += [PSCustomObject]@{
                    Id = $groupId
                    DisplayName = $group.DisplayName
                }
            }
            else {
                Write-Warning "Group with ID $groupId not found. Skipping."
            }
        }
        
        if ($validGroups.Count -lt 2) {
            throw "At least 2 valid staging groups are required for a staged rollout."
        }
        
        # Configure readable policy names
        $policyBaseName = switch ($PolicyType) {
            'UserMFA' { "MFA Rollout" }
            'DeviceCompliance' { "Device Compliance Rollout" }
            'TokenBinding' { "Session Controls Rollout" }
            'SignInRisk' { "Sign-in Risk Protection Rollout" }
            'UserRisk' { "User Risk Protection Rollout" }
            'MAMPolicy' { "Mobile App Management Rollout" }
        }
    }
    
    process {
        try {
            # Display rollout plan
            $currentDate = Get-Date
            
            Write-Host "Staged Rollout Plan for $policyBaseName" -ForegroundColor Cyan
            Write-Host "===========================================`n" -ForegroundColor Cyan
            
            # Phase 1: Initial Report-Only Policy for All Groups
            $phase1Date = $currentDate.AddDays(1).ToString("yyyy-MM-dd")
            Write-Host "Phase 1 ($phase1Date):" -ForegroundColor Yellow
            Write-Host "  - Create report-only policy for all stage groups" -ForegroundColor White
            Write-Host "  - Policy will be in 'enabledForReportingButNotEnforced' state" -ForegroundColor White
            
            # Phase 2: First Group Enforcement
            $phase2Date = $currentDate.AddDays($StagingDays).ToString("yyyy-MM-dd")
            Write-Host "`nPhase 2 ($phase2Date):" -ForegroundColor Yellow
            Write-Host "  - Create enforced policy for first group: $($validGroups[0].DisplayName)" -ForegroundColor White
            Write-Host "  - Policy will be in 'enabled' state" -ForegroundColor White
            
            # Remaining Phases: Gradual Rollout
            for ($i = 1; $i -lt $validGroups.Count; $i++) {
                $phaseDate = $currentDate.AddDays($StagingDays * ($i + 1)).ToString("yyyy-MM-dd")
                Write-Host "`nPhase $($i + 2) ($phaseDate):" -ForegroundColor Yellow
                Write-Host "  - Add group to enforced policy: $($validGroups[$i].DisplayName)" -ForegroundColor White
            }
            
            # Final Phase: Full Deployment
            $finalDate = $currentDate.AddDays($StagingDays * ($validGroups.Count + 1)).ToString("yyyy-MM-dd")
            Write-Host "`nFinal Phase ($finalDate):" -ForegroundColor Yellow
            Write-Host "  - Create organization-wide policy" -ForegroundColor White
            Write-Host "  - Policy will be in '$FinalState' state" -ForegroundColor White
            
            # Get confirmation
            if (-not $Force) {
                $confirmation = Read-Host "`nDo you want to create this staged rollout plan? (Y/N)"
                if ($confirmation -ne "Y") {
                    Write-Host "Staged rollout cancelled." -ForegroundColor Red
                    return
                }
            }
            
            # Create policies
            $createdPolicies = @()
            
            # Phase 1: Report-Only Policy
            Write-Host "`nCreating Phase 1 policy (Report-Only)..." -ForegroundColor Yellow
            
            $reportOnlyGroups = $validGroups.Id
            $reportOnlyName = "$policyBaseName - Report Only (Phase 1)"
            
            $reportOnlyParams = @{
                PolicyType = $PolicyType
                PolicyName = $reportOnlyName
                State = "enabledForReportingButNotEnforced"
                IncludeGroups = $reportOnlyGroups
                DeployPolicy = $true
                PassThru = $true
                Force = $true
            }
            
            if ($PSCmdlet.ShouldProcess("Entra ID", "Create Phase 1 report-only policy: $reportOnlyName")) {
                try {
                    $reportOnlyPolicy = New-CABestPracticePolicy @reportOnlyParams
                    $createdPolicies += [PSCustomObject]@{
                        Phase = 1
                        Name = $reportOnlyName
                        State = "enabledForReportingButNotEnforced"
                        Groups = $validGroups | Where-Object { $reportOnlyGroups -contains $_.Id }
                        Policy = $reportOnlyPolicy
                    }
                    Write-Host "  ✓ Successfully created report-only policy." -ForegroundColor Green
                }
                catch {
                    Write-Error "  ✗ Failed to create report-only policy: $_"
                }
            }
            
            # Phase 2: First Group Enforcement
            Write-Host "`nCreating Phase 2 policy (First Group Enforcement)..." -ForegroundColor Yellow
            
            $phase2Name = "$policyBaseName - $($validGroups[0].DisplayName) (Phase 2)"
            
            $phase2Params = @{
                PolicyType = $PolicyType
                PolicyName = $phase2Name
                State = "enabled"
                IncludeGroups = @($validGroups[0].Id)
                DeployPolicy = $true
                PassThru = $true
                Force = $true
            }
            
            if ($PSCmdlet.ShouldProcess("Entra ID", "Create Phase 2 policy: $phase2Name")) {
                try {
                    $phase2Policy = New-CABestPracticePolicy @phase2Params
                    $createdPolicies += [PSCustomObject]@{
                        Phase = 2
                        Name = $phase2Name
                        State = "enabled"
                        Groups = @($validGroups[0])
                        Policy = $phase2Policy
                    }
                    Write-Host "  ✓ Successfully created first group policy." -ForegroundColor Green
                }
                catch {
                    Write-Error "  ✗ Failed to create first group policy: $_"
                }
            }
            
            # Create placeholder policies for remaining phases
            for ($i = 1; $i -lt $validGroups.Count; $i++) {
                $phaseNumber = $i + 2
                Write-Host "`nCreating Phase $phaseNumber policy placeholder..." -ForegroundColor Yellow
                
                $phaseName = "$policyBaseName - Future Phase $phaseNumber (Placeholder)"
                
                $phaseParams = @{
                    PolicyType = $PolicyType
                    PolicyName = $phaseName
                    State = "disabled"
                    IncludeGroups = $validGroups[0..($i)].Id
                    DeployPolicy = $true
                    PassThru = $true
                    Force = $true
                }
                
                if ($PSCmdlet.ShouldProcess("Entra ID", "Create Phase $phaseNumber placeholder policy: $phaseName")) {
                    try {
                        $phasePolicy = New-CABestPracticePolicy @phaseParams
                        $createdPolicies += [PSCustomObject]@{
                            Phase = $phaseNumber
                            Name = $phaseName
                            State = "disabled"
                            Groups = $validGroups[0..($i)]
                            Policy = $phasePolicy
                        }
                        Write-Host "  ✓ Successfully created Phase $phaseNumber placeholder policy." -ForegroundColor Green
                    }
                    catch {
                        Write-Error "  ✗ Failed to create Phase $phaseNumber placeholder policy: $_"
                    }
                }
            }
            
            # Final policy (placeholder)
            Write-Host "`nCreating final organization-wide policy placeholder..." -ForegroundColor Yellow
            
            $finalName = "$policyBaseName - Organization-Wide (Final Phase)"
            
            $finalParams = @{
                PolicyType = $PolicyType
                PolicyName = $finalName
                State = "disabled"
                DeployPolicy = $true
                PassThru = $true
                Force = $true
            }
            
            if ($PSCmdlet.ShouldProcess("Entra ID", "Create final organization-wide policy: $finalName")) {
                try {
                    $finalPolicy = New-CABestPracticePolicy @finalParams
                    $createdPolicies += [PSCustomObject]@{
                        Phase = $validGroups.Count + 2
                        Name = $finalName
                        State = "disabled"
                        Groups = "All Users"
                        Policy = $finalPolicy
                    }
                    Write-Host "  ✓ Successfully created final organization-wide policy placeholder." -ForegroundColor Green
                }
                catch {
                    Write-Error "  ✗ Failed to create final organization-wide policy placeholder: $_"
                }
            }
            
            # Display summary
            Write-Host "`nStaged Rollout Created Successfully!" -ForegroundColor Green
            Write-Host "Total Phases: $($validGroups.Count + 2)" -ForegroundColor White
            Write-Host "Policies Created: $($createdPolicies.Count)" -ForegroundColor White
            
            Write-Host "`nImportant Next Steps:" -ForegroundColor Yellow
            Write-Host "1. Monitor the Report-Only policy (Phase 1) to assess potential impact." -ForegroundColor White
            Write-Host "2. On $phase2Date, verify the first group policy (Phase 2) is working as expected." -ForegroundColor White
            Write-Host "3. Enable subsequent phase policies according to the rollout schedule." -ForegroundColor White
            Write-Host "4. Before enabling the final organization-wide policy, ensure all previous phases were successful." -ForegroundColor White
            
            # Return the created policies
            return $createdPolicies
        }
        catch {
            Write-Error "Failed to create staged rollout plan: $_"
            throw
        }
    }
}
