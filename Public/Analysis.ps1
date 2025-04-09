# Advanced analysis functions for Conditional Access Analyzer
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
    .EXAMPLE
        Get-CAPoliciesSummary
    .EXAMPLE
        Get-CAPoliciesSummary -IncludeDisabled -IncludeNamedLocations
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
            
            # Create enhanced policy objects
            $enhancedPolicies = @()
            foreach ($policy in $policies) {
                # Convert policy to enhanced object
                $enhancedPolicy = [PSCustomObject]@{
                    Id = $policy.Id
                    DisplayName = $policy.DisplayName
                    State = $policy.State
                    CreatedDateTime = $policy.CreatedDateTime
                    ModifiedDateTime = $policy.ModifiedDateTime
                    AppliesTo = @{
                        Users = @{
                            IncludeUsers = @()
                            ExcludeUsers = @()
                            IncludeGroups = @()
                            ExcludeGroups = @()
                            IncludeRoles = @()
                            ExcludeRoles = @()
                            Summary = ""
                        }
                        Applications = @{
                            IncludeApplications = @()
                            ExcludeApplications = @()
                            IncludeUserActions = @()
                            Summary = ""
                        }
                        Conditions = @{
                            Platforms = if ($policy.Conditions.Platforms) {
                                @{
                                    IncludePlatforms = $policy.Conditions.Platforms.IncludePlatforms
                                    ExcludePlatforms = $policy.Conditions.Platforms.ExcludePlatforms
                                    Summary = ""
                                }
                            } else { $null }
                            Locations = if ($policy.Conditions.Locations) {
                                @{
                                    IncludeLocations = @()
                                    ExcludeLocations = @()
                                    Summary = ""
                                }
                            } else { $null }
                            DeviceStates = if ($policy.Conditions.DeviceStates) {
                                @{
                                    IncludeDeviceStates = $policy.Conditions.DeviceStates.IncludeDeviceStates
                                    ExcludeDeviceStates = $policy.Conditions.DeviceStates.ExcludeDeviceStates
                                    Summary = ""
                                }
                            } else { $null }
                            ClientAppTypes = $policy.Conditions.ClientAppTypes
                            SignInRisk = if ($policy.Conditions.SignInRisk) {
                                @{
                                    RiskLevels = $policy.Conditions.SignInRisk.RiskLevels
                                    Summary = ""
                                }
                            } else { $null }
                            UserRiskLevels = $policy.Conditions.UserRiskLevels
                        }
                    }
                    AccessControls = @{
                        GrantControls = if ($policy.GrantControls) {
                            @{
                                Operator = $policy.GrantControls.Operator
                                BuiltInControls = $policy.GrantControls.BuiltInControls
                                CustomAuthenticationFactors = $policy.GrantControls.CustomAuthenticationFactors
                                TermsOfUse = $policy.GrantControls.TermsOfUse
                                Summary = ""
                            }
                        } else { $null }
                        SessionControls = if ($policy.SessionControls) {
                            @{
                                ApplicationEnforcedRestrictions = $policy.SessionControls.ApplicationEnforcedRestrictions
                                CloudAppSecurity = $policy.SessionControls.CloudAppSecurity
                                SignInFrequency = $policy.SessionControls.SignInFrequency
                                PersistentBrowser = $policy.SessionControls.PersistentBrowser
                                Summary = ""
                            }
                        } else { $null }
                    }
                    Analysis = @{
                        PolicyType = ""
                        RequiresMFA = $false
                        RequiresCompliantDevice = $false
                        RequiresApprovedApp = $false
                        RequiresHybridJoin = $false
                        UsesSignInRisk = $false
                        UsesUserRisk = $false
                        HasSessionControls = $false
                        TargetsAdmins = $false
                        HasExclusions = $false
                        ComplexityScore = 0
                        CoverageScore = 0
                        SecurityImpact = "Medium" # Low, Medium, High, Critical
                    }
                }
                
                # Process user conditions
                if ($policy.Conditions.Users) {
                    # Include users
                    foreach ($userId in $policy.Conditions.Users.IncludeUsers) {
                        $enhancedPolicy.AppliesTo.Users.IncludeUsers += @{
                            Id = $userId
                            DisplayName = Get-DirectoryObjectName -Id $userId -Type 'User'
                        }
                    }
                    
                    # Exclude users
                    foreach ($userId in $policy.Conditions.Users.ExcludeUsers) {
                        $enhancedPolicy.AppliesTo.Users.ExcludeUsers += @{
                            Id = $userId
                            DisplayName = Get-DirectoryObjectName -Id $userId -Type 'User'
                        }
                    }
                    
                    # Include groups
                    foreach ($groupId in $policy.Conditions.Users.IncludeGroups) {
                        $enhancedPolicy.AppliesTo.Users.IncludeGroups += @{
                            Id = $groupId
                            DisplayName = Get-DirectoryObjectName -Id $groupId -Type 'Group'
                        }
                    }
                    
                    # Exclude groups
                    foreach ($groupId in $policy.Conditions.Users.ExcludeGroups) {
                        $enhancedPolicy.AppliesTo.Users.ExcludeGroups += @{
                            Id = $groupId
                            DisplayName = Get-DirectoryObjectName -Id $groupId -Type 'Group'
                        }
                    }
                    
                    # Include roles
                    foreach ($roleId in $policy.Conditions.Users.IncludeRoles) {
                        $enhancedPolicy.AppliesTo.Users.IncludeRoles += @{
                            Id = $roleId
                            DisplayName = Get-DirectoryObjectName -Id $roleId -Type 'Role'
                        }
                    }
                    
                    # Exclude roles
                    foreach ($roleId in $policy.Conditions.Users.ExcludeRoles) {
                        $enhancedPolicy.AppliesTo.Users.ExcludeRoles += @{
                            Id = $roleId
                            DisplayName = Get-DirectoryObjectName -Id $roleId -Type 'Role'
                        }
                    }
                    
                    # Generate user summary
                    $userSummary = ""
                    if ($policy.Conditions.Users.IncludeUsers -contains "All") {
                        $userSummary = "All users"
                        
                        # Check for exclusions
                        $exclusions = @()
                        if ($policy.Conditions.Users.ExcludeUsers.Count -gt 0) {
                            $exclusions += "$($policy.Conditions.Users.ExcludeUsers.Count) user(s)"
                        }
                        if ($policy.Conditions.Users.ExcludeGroups.Count -gt 0) {
                            $exclusions += "$($policy.Conditions.Users.ExcludeGroups.Count) group(s)"
                        }
                        if ($policy.Conditions.Users.ExcludeRoles.Count -gt 0) {
                            $exclusions += "$($policy.Conditions.Users.ExcludeRoles.Count) role(s)"
                        }
                        
                        if ($exclusions.Count -gt 0) {
                            $userSummary += " (excluding $($exclusions -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    elseif ($policy.Conditions.Users.IncludeUsers.Count -gt 0 -or 
                            $policy.Conditions.Users.IncludeGroups.Count -gt 0 -or 
                            $policy.Conditions.Users.IncludeRoles.Count -gt 0) {
                        
                        $inclusions = @()
                        if ($policy.Conditions.Users.IncludeUsers.Count -gt 0) {
                            $inclusions += "$($policy.Conditions.Users.IncludeUsers.Count) user(s)"
                        }
                        if ($policy.Conditions.Users.IncludeGroups.Count -gt 0) {
                            $inclusions += "$($policy.Conditions.Users.IncludeGroups.Count) group(s)"
                        }
                        if ($policy.Conditions.Users.IncludeRoles.Count -gt 0) {
                            $inclusions += "$($policy.Conditions.Users.IncludeRoles.Count) role(s)"
                            $enhancedPolicy.Analysis.TargetsAdmins = $true
                        }
                        
                        $userSummary = "Specific $($inclusions -join ", ")"
                        
                        # Check for exclusions
                        $exclusions = @()
                        if ($policy.Conditions.Users.ExcludeUsers.Count -gt 0) {
                            $exclusions += "$($policy.Conditions.Users.ExcludeUsers.Count) user(s)"
                        }
                        if ($policy.Conditions.Users.ExcludeGroups.Count -gt 0) {
                            $exclusions += "$($policy.Conditions.Users.ExcludeGroups.Count) group(s)"
                        }
                        if ($policy.Conditions.Users.ExcludeRoles.Count -gt 0) {
                            $exclusions += "$($policy.Conditions.Users.ExcludeRoles.Count) role(s)"
                        }
                        
                        if ($exclusions.Count -gt 0) {
                            $userSummary += " (excluding $($exclusions -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    else {
                        $userSummary = "No users specified"
                    }
                    
                    $enhancedPolicy.AppliesTo.Users.Summary = $userSummary
                }
                
                # Process application conditions
                if ($policy.Conditions.Applications) {
                    # Include applications
                    foreach ($appId in $policy.Conditions.Applications.IncludeApplications) {
                        $enhancedPolicy.AppliesTo.Applications.IncludeApplications += @{
                            Id = $appId
                            DisplayName = Get-DirectoryObjectName -Id $appId -Type 'Application'
                        }
                    }
                    
                    # Exclude applications
                    foreach ($appId in $policy.Conditions.Applications.ExcludeApplications) {
                        $enhancedPolicy.AppliesTo.Applications.ExcludeApplications += @{
                            Id = $appId
                            DisplayName = Get-DirectoryObjectName -Id $appId -Type 'Application'
                        }
                    }
                    
                    # Include user actions
                    if ($policy.Conditions.Applications.IncludeUserActions) {
                        $enhancedPolicy.AppliesTo.Applications.IncludeUserActions = $policy.Conditions.Applications.IncludeUserActions
                    }
                    
                    # Generate application summary
                    $appSummary = ""
                    if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
                        $appSummary = "All applications"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Applications.ExcludeApplications.Count -gt 0) {
                            $appSummary += " (excluding $($policy.Conditions.Applications.ExcludeApplications.Count) app(s))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    elseif ($policy.Conditions.Applications.IncludeApplications -contains "Office365") {
                        $appSummary = "Microsoft 365 applications"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Applications.ExcludeApplications.Count -gt 0) {
                            $appSummary += " (excluding $($policy.Conditions.Applications.ExcludeApplications.Count) app(s))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    elseif ($policy.Conditions.Applications.IncludeApplications.Count -gt 0) {
                        $appSummary = "$($policy.Conditions.Applications.IncludeApplications.Count) specific application(s)"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Applications.ExcludeApplications.Count -gt 0) {
                            $appSummary += " (excluding $($policy.Conditions.Applications.ExcludeApplications.Count) app(s))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    elseif ($policy.Conditions.Applications.IncludeUserActions.Count -gt 0) {
                        $appSummary = "User actions: $($policy.Conditions.Applications.IncludeUserActions -join ", ")"
                    }
                    else {
                        $appSummary = "No applications specified"
                    }
                    
                    $enhancedPolicy.AppliesTo.Applications.Summary = $appSummary
                }
                
                # Process platform conditions
                if ($policy.Conditions.Platforms) {
                    $platformSummary = ""
                    
                    if ($policy.Conditions.Platforms.IncludePlatforms -contains "all") {
                        $platformSummary = "All platforms"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Platforms.ExcludePlatforms.Count -gt 0) {
                            $platformSummary += " (excluding $($policy.Conditions.Platforms.ExcludePlatforms -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    elseif ($policy.Conditions.Platforms.IncludePlatforms.Count -gt 0) {
                        $platformSummary = "Platforms: $($policy.Conditions.Platforms.IncludePlatforms -join ", ")"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Platforms.ExcludePlatforms.Count -gt 0) {
                            $platformSummary += " (excluding $($policy.Conditions.Platforms.ExcludePlatforms -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    else {
                        $platformSummary = "No platforms specified"
                    }
                    
                    $enhancedPolicy.AppliesTo.Conditions.Platforms.Summary = $platformSummary
                }
                
                # Process location conditions
                if ($policy.Conditions.Locations) {
                    # Include locations
                    foreach ($locationId in $policy.Conditions.Locations.IncludeLocations) {
                        $locationName = $locationId
                        
                        if ($locationId -eq "All") {
                            $locationName = "All locations"
                        }
                        elseif ($locationId -eq "AllTrusted") {
                            $locationName = "All trusted locations"
                        }
                        elseif ($namedLocations.ContainsKey($locationId)) {
                            $locationName = $namedLocations[$locationId].DisplayName
                        }
                        
                        $enhancedPolicy.AppliesTo.Conditions.Locations.IncludeLocations += @{
                            Id = $locationId
                            DisplayName = $locationName
                        }
                    }
                    
                    # Exclude locations
                    foreach ($locationId in $policy.Conditions.Locations.ExcludeLocations) {
                        $locationName = $locationId
                        
                        if ($locationId -eq "All") {
                            $locationName = "All locations"
                        }
                        elseif ($locationId -eq "AllTrusted") {
                            $locationName = "All trusted locations"
                        }
                        elseif ($namedLocations.ContainsKey($locationId)) {
                            $locationName = $namedLocations[$locationId].DisplayName
                        }
                        
                        $enhancedPolicy.AppliesTo.Conditions.Locations.ExcludeLocations += @{
                            Id = $locationId
                            DisplayName = $locationName
                        }
                    }
                    
                    # Generate location summary
                    $locationSummary = ""
                    
                    if ($policy.Conditions.Locations.IncludeLocations -contains "All") {
                        $locationSummary = "All locations"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Locations.ExcludeLocations.Count -gt 0) {
                            $locationNames = @()
                            foreach ($locId in $policy.Conditions.Locations.ExcludeLocations) {
                                if ($locId -eq "AllTrusted") {
                                    $locationNames += "All trusted locations"
                                }
                                elseif ($namedLocations.ContainsKey($locId)) {
                                    $locationNames += $namedLocations[$locId].DisplayName
                                }
                                else {
                                    $locationNames += $locId
                                }
                            }
                            
                            $locationSummary += " (excluding $($locationNames -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    elseif ($policy.Conditions.Locations.IncludeLocations -contains "AllTrusted") {
                        $locationSummary = "All trusted locations"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Locations.ExcludeLocations.Count -gt 0) {
                            $locationNames = @()
                            foreach ($locId in $policy.Conditions.Locations.ExcludeLocations) {
                                if ($namedLocations.ContainsKey($locId)) {
                                    $locationNames += $namedLocations[$locId].DisplayName
                                }
                                else {
                                    $locationNames += $locId
                                }
                            }
                            
                            $locationSummary += " (excluding $($locationNames -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    elseif ($policy.Conditions.Locations.IncludeLocations.Count -gt 0) {
                        $locationNames = @()
                        foreach ($locId in $policy.Conditions.Locations.IncludeLocations) {
                            if ($namedLocations.ContainsKey($locId)) {
                                $locationNames += $namedLocations[$locId].DisplayName
                            }
                            else {
                                $locationNames += $locId
                            }
                        }
                        
                        $locationSummary = "Locations: $($locationNames -join ", ")"
                        
                        # Check for exclusions
                        if ($policy.Conditions.Locations.ExcludeLocations.Count -gt 0) {
                            $excludeNames = @()
                            foreach ($locId in $policy.Conditions.Locations.ExcludeLocations) {
                                if ($namedLocations.ContainsKey($locId)) {
                                    $excludeNames += $namedLocations[$locId].DisplayName
                                }
                                else {
                                    $excludeNames += $locId
                                }
                            }
                            
                            $locationSummary += " (excluding $($excludeNames -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    else {
                        $locationSummary = "No locations specified"
                    }
                    
                    $enhancedPolicy.AppliesTo.Conditions.Locations.Summary = $locationSummary
                }
                
                # Process device state conditions
                if ($policy.Conditions.DeviceStates) {
                    $deviceStateSummary = ""
                    
                    if ($policy.Conditions.DeviceStates.IncludeDeviceStates.Count -gt 0) {
                        $deviceStateSummary = "Device states: $($policy.Conditions.DeviceStates.IncludeDeviceStates -join ", ")"
                        
                        # Check for exclusions
                        if ($policy.Conditions.DeviceStates.ExcludeDeviceStates.Count -gt 0) {
                            $deviceStateSummary += " (excluding $($policy.Conditions.DeviceStates.ExcludeDeviceStates -join ", "))"
                            $enhancedPolicy.Analysis.HasExclusions = $true
                        }
                    }
                    else {
                        $deviceStateSummary = "No device states specified"
                    }
                    
                    $enhancedPolicy.AppliesTo.Conditions.DeviceStates.Summary = $deviceStateSummary
                }
                
                # Process sign-in risk conditions
                if ($policy.Conditions.SignInRisk) {
                    $signInRiskSummary = "Sign-in risk levels: $($policy.Conditions.SignInRisk.RiskLevels -join ", ")"
                    $enhancedPolicy.AppliesTo.Conditions.SignInRisk.Summary = $signInRiskSummary
                    $enhancedPolicy.Analysis.UsesSignInRisk = $true
                }
                
                # Process user risk conditions
                if ($policy.Conditions.UserRiskLevels -and $policy.Conditions.UserRiskLevels.Count -gt 0) {
                    $userRiskSummary = "User risk levels: $($policy.Conditions.UserRiskLevels -join ", ")"
                    # Ensure there's a property to store the summary
                    $enhancedPolicy.AppliesTo.Conditions | Add-Member -NotePropertyName "UserRiskLevelsSummary" -NotePropertyValue $userRiskSummary -Force
                    $enhancedPolicy.Analysis.UsesUserRisk = $true
                }
                
                # Process grant controls
                if ($policy.GrantControls) {
                    $grantSummary = ""
                    
                    if ($policy.GrantControls.BuiltInControls -and $policy.GrantControls.BuiltInControls.Count -gt 0) {
                        $grantSummary = "Controls: $($policy.GrantControls.BuiltInControls -join ", ")"
                        
                        # Set analysis flags
                        if ($policy.GrantControls.BuiltInControls -contains "mfa") {
                            $enhancedPolicy.Analysis.RequiresMFA = $true
                        }
                        if ($policy.GrantControls.BuiltInControls -contains "compliantDevice") {
                            $enhancedPolicy.Analysis.RequiresCompliantDevice = $true
                        }
                        if ($policy.GrantControls.BuiltInControls -contains "domainJoinedDevice") {
                            $enhancedPolicy.Analysis.RequiresHybridJoin = $true
                        }
                        if ($policy.GrantControls.BuiltInControls -contains "approvedApplication") {
                            $enhancedPolicy.Analysis.RequiresApprovedApp = $true
                        }
                        
                        $grantSummary += " ($($policy.GrantControls.Operator))"
                    }
                    
                    if ($policy.GrantControls.TermsOfUse) {
                        $grantSummary += ", Terms of Use"
                    }
                    
                    if ($policy.GrantControls.CustomAuthenticationFactors -and $policy.GrantControls.CustomAuthenticationFactors.Count -gt 0) {
                        $grantSummary += ", Custom: $($policy.GrantControls.CustomAuthenticationFactors -join ", ")"
                    }
                    
                    $enhancedPolicy.AccessControls.GrantControls.Summary = $grantSummary
                }
                
                # Process session controls
                if ($policy.SessionControls) {
                    $sessionSummary = ""
                    $enhancedPolicy.Analysis.HasSessionControls = $true
                    
                    if ($policy.SessionControls.ApplicationEnforcedRestrictions -and $policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
                        $sessionSummary += "App enforced restrictions, "
                    }
                    
                    if ($policy.SessionControls.CloudAppSecurity -and $policy.SessionControls.CloudAppSecurity.IsEnabled) {
                        $sessionSummary += "Cloud App Security ($($policy.SessionControls.CloudAppSecurity.CloudAppSecurityType)), "
                    }
                    
                    if ($policy.SessionControls.SignInFrequency -and $policy.SessionControls.SignInFrequency.IsEnabled) {
                        $sessionSummary += "Sign-in frequency ($($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)), "
                    }
                    
                    if ($policy.SessionControls.PersistentBrowser -and $policy.SessionControls.PersistentBrowser.IsEnabled) {
                        $sessionSummary += "Persistent browser ($($policy.SessionControls.PersistentBrowser.Mode)), "
                    }
                    
                    # Remove trailing comma and space
                    if ($sessionSummary.EndsWith(", ")) {
                        $sessionSummary = $sessionSummary.Substring(0, $sessionSummary.Length - 2)
                    }
                    
                    $enhancedPolicy.AccessControls.SessionControls.Summary = $sessionSummary
                }
                
                # Determine policy type
                if ($enhancedPolicy.Analysis.TargetsAdmins -and $enhancedPolicy.Analysis.RequiresMFA) {
                    $enhancedPolicy.Analysis.PolicyType = "Admin MFA"
                    $enhancedPolicy.Analysis.SecurityImpact = "Critical"
                }
                elseif ($enhancedPolicy.Analysis.RequiresMFA -and $policy.Conditions.Applications.IncludeApplications -contains "All") {
                    $enhancedPolicy.Analysis.PolicyType = "Global MFA"
                    $enhancedPolicy.Analysis.SecurityImpact = "High"
                }
                elseif ($enhancedPolicy.Analysis.RequiresMFA -and $policy.Conditions.Applications.IncludeApplications -contains "Office365") {
                    $enhancedPolicy.Analysis.PolicyType = "Office 365 MFA"
                    $enhancedPolicy.Analysis.SecurityImpact = "High"
                }
                elseif ($enhancedPolicy.Analysis.RequiresCompliantDevice -or $enhancedPolicy.Analysis.RequiresHybridJoin) {
                    $enhancedPolicy.Analysis.PolicyType = "Device Compliance"
                    $enhancedPolicy.Analysis.SecurityImpact = "High"
                }
                elseif ($enhancedPolicy.Analysis.UsesSignInRisk -or $enhancedPolicy.Analysis.UsesUserRisk) {
                    $enhancedPolicy.Analysis.PolicyType = "Risk-Based"
                    $enhancedPolicy.Analysis.SecurityImpact = "High"
                }
                elseif ($enhancedPolicy.Analysis.RequiresApprovedApp) {
                    $enhancedPolicy.Analysis.PolicyType = "App Control"
                    $enhancedPolicy.Analysis.SecurityImpact = "Medium"
                }
                elseif ($enhancedPolicy.Analysis.HasSessionControls) {
                    $enhancedPolicy.Analysis.PolicyType = "Session Control"
                    $enhancedPolicy.Analysis.SecurityImpact = "Medium"
                }
                else {
                    $enhancedPolicy.Analysis.PolicyType = "Other"
                    $enhancedPolicy.Analysis.SecurityImpact = "Low"
                }
                
                # Calculate complexity score (0-100)
                $complexityScore = 0
                
                # User complexity (max 20)
                if ($policy.Conditions.Users.IncludeUsers -contains "All") {
                    $complexityScore += 5
                }
                else {
                    $complexityScore += [Math]::Min(20, ($policy.Conditions.Users.IncludeUsers.Count + 
                                                        $policy.Conditions.Users.IncludeGroups.Count + 
                                                        $policy.Conditions.Users.IncludeRoles.Count) * 2)
                }
                
                # Exclusion complexity (max 10)
                $complexityScore += [Math]::Min(10, ($policy.Conditions.Users.ExcludeUsers.Count + 
                                                    $policy.Conditions.Users.ExcludeGroups.Count + 
                                                    $policy.Conditions.Users.ExcludeRoles.Count +
                                                    $policy.Conditions.Applications.ExcludeApplications.Count) * 2)
                
                # Condition complexity (max 20)
                if ($policy.Conditions.Platforms -and $policy.Conditions.Platforms.IncludePlatforms.Count -gt 0) {
                    $complexityScore += 5
                }
                
                if ($policy.Conditions.Locations -and $policy.Conditions.Locations.IncludeLocations.Count -gt 0) {
                    $complexityScore += 5
                }
                
                if ($policy.Conditions.ClientAppTypes -and $policy.Conditions.ClientAppTypes.Count -gt 0) {
                    $complexityScore += 5
                }
                
                if ($policy.Conditions.DeviceStates -and 
                    ($policy.Conditions.DeviceStates.IncludeDeviceStates.Count -gt 0 -or 
                     $policy.Conditions.DeviceStates.ExcludeDeviceStates.Count -gt 0)) {
                    $complexityScore += 5
                }
                
                # Control complexity (max 30)
                if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls.Count -gt 0) {
                    $complexityScore += $policy.GrantControls.BuiltInControls.Count * 5
                }
                
                if ($policy.SessionControls) {
                    if ($policy.SessionControls.ApplicationEnforcedRestrictions -and $policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
                        $complexityScore += 5
                    }
                    
                    if ($policy.SessionControls.CloudAppSecurity -and $policy.SessionControls.CloudAppSecurity.IsEnabled) {
                        $complexityScore += 10
                    }
                    
                    if ($policy.SessionControls.SignInFrequency -and $policy.SessionControls.SignInFrequency.IsEnabled) {
                        $complexityScore += 5
                    }
                    
                    if ($policy.SessionControls.PersistentBrowser -and $policy.SessionControls.PersistentBrowser.IsEnabled) {
                        $complexityScore += 5
                    }
                }
                
                # Risk complexity (max 20)
                if ($policy.Conditions.SignInRisk -and $policy.Conditions.SignInRisk.RiskLevels.Count -gt 0) {
                    $complexityScore += 10
                }
                
                if ($policy.Conditions.UserRiskLevels -and $policy.Conditions.UserRiskLevels.Count -gt 0) {
                    $complexityScore += 10
                }
                
                # Cap at 100
                $enhancedPolicy.Analysis.ComplexityScore = [Math]::Min(100, $complexityScore)
                
                # Calculate coverage score (0-100)
                $coverageScore = 0
                
                # User coverage (max 30)
                if ($policy.Conditions.Users.IncludeUsers -contains "All") {
                    $coverageScore += 30
                }
                elseif ($policy.Conditions.Users.IncludeRoles.Count -gt 0) {
                    $coverageScore += 20
                }
                elseif ($policy.Conditions.Users.IncludeGroups.Count -gt 0) {
                    $coverageScore += 15
                }
                elseif ($policy.Conditions.Users.IncludeUsers.Count -gt 0) {
                    $coverageScore += 10
                }
                
                # Application coverage (max 30)
                if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
                    $coverageScore += 30
                }
                elseif ($policy.Conditions.Applications.IncludeApplications -contains "Office365") {
                    $coverageScore += 25
                }
                elseif ($policy.Conditions.Applications.IncludeApplications.Count -gt 0) {
                    $coverageScore += [Math]::Min(20, $policy.Conditions.Applications.IncludeApplications.Count)
                }
                
                # Security control coverage (max 40)
                if ($enhancedPolicy.Analysis.RequiresMFA) {
                    $coverageScore += 10
                }
                
                if ($enhancedPolicy.Analysis.RequiresCompliantDevice) {
                    $coverageScore += 10
                }
                
                if ($enhancedPolicy.Analysis.HasSessionControls) {
                    $coverageScore += 10
                }
                
                if ($enhancedPolicy.Analysis.UsesSignInRisk -or $enhancedPolicy.Analysis.UsesUserRisk) {
                    $coverageScore += 10
                }
                
                $enhancedPolicy.Analysis.CoverageScore = [Math]::Min(100, $coverageScore)
                
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

# Other advanced analysis functions would follow here as separate functions
