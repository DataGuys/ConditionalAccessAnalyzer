# DataProcessing.ps1 - Contains functions for processing Conditional Access policy data

function Convert-PolicyToObject {
    <#
    .SYNOPSIS
        Converts raw Graph API policy data to structured objects.
    .DESCRIPTION
        Processes raw Conditional Access policy data from Graph API and 
        converts it to structured objects for easier analysis.
    .PARAMETER Policies
        The raw policy data from Graph API.
    .EXAMPLE
        $policies = Get-MgIdentityConditionalAccessPolicy
        $processedPolicies = Convert-PolicyToObject -Policies $policies
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Policies
    )
    
    process {
        $processedPolicies = @()
        
        foreach ($policy in $Policies) {
            try {
                $caPolicy = [CAPolicy]::new($policy)
                $processedPolicies += $caPolicy
            }
            catch {
                Write-Error "Failed to process policy $($policy.DisplayName): $_"
            }
        }
        
        return $processedPolicies
    }
}

function Get-PolicyStatistics {
    <#
    .SYNOPSIS
        Generates statistics from a collection of policies.
    .DESCRIPTION
        Calculates various statistics from a collection of Conditional Access policies,
        including counts of enabled vs. disabled policies, policies with specific requirements, etc.
    .PARAMETER Policies
        The collection of processed policy objects.
    .EXAMPLE
        $policyStats = Get-PolicyStatistics -Policies $processedPolicies
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [CAPolicy[]]$Policies
    )
    
    process {
        $totalPolicies = $Policies.Count
        $enabledPolicies = ($Policies | Where-Object { $_.State -eq "enabled" }).Count
        $disabledPolicies = ($Policies | Where-Object { $_.State -eq "disabled" }).Count
        $reportOnlyPolicies = ($Policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }).Count
        
        $mfaPolicies = ($Policies | Where-Object { $_.RequiresMFA() }).Count
        $deviceCompliancePolicies = ($Policies | Where-Object { $_.RequiresCompliantDevice() }).Count
        $hybridJoinPolicies = ($Policies | Where-Object { $_.RequiresHybridJoin() }).Count
        
        $adminTargetingPolicies = ($Policies | Where-Object { $_.TargetsAdminRoles(@("62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d")) }).Count
        $allUserPolicies = ($Policies | Where-Object { $_.AppliesToAllUsers() }).Count
        $broadAppPolicies = ($Policies | Where-Object { $_.HasBroadAppCoverage() }).Count
        
        $signInRiskPolicies = ($Policies | Where-Object { $_.UsesSignInRisk() }).Count
        $userRiskPolicies = ($Policies | Where-Object { $_.UsesUserRisk() }).Count
        $cloudAppSecurityPolicies = ($Policies | Where-Object { $_.HasCloudAppSecurity() }).Count
        
        return [PSCustomObject]@{
            TotalPolicies = $totalPolicies
            EnabledPolicies = $enabledPolicies
            DisabledPolicies = $disabledPolicies
            ReportOnlyPolicies = $reportOnlyPolicies
            MFAPolicies = $mfaPolicies
            DeviceCompliancePolicies = $deviceCompliancePolicies
            HybridJoinPolicies = $hybridJoinPolicies
            AdminTargetingPolicies = $adminTargetingPolicies
            AllUserPolicies = $allUserPolicies
            BroadAppPolicies = $broadAppPolicies
            SignInRiskPolicies = $signInRiskPolicies
            UserRiskPolicies = $userRiskPolicies
            CloudAppSecurityPolicies = $cloudAppSecurityPolicies
        }
    }
}

function Get-AdminRoles {
    <#
    .SYNOPSIS
        Retrieves admin role definitions from Microsoft Graph.
    .DESCRIPTION
        Gets a list of all administrative roles from Microsoft Graph API,
        with options to filter to only active directory or privileged roles.
    .PARAMETER ActiveDirectoryOnly
        If specified, only returns Active Directory-related admin roles.
    .PARAMETER PrivilegedOnly
        If specified, only returns high-privileged admin roles.
    .EXAMPLE
        $adminRoles = Get-AdminRoles -PrivilegedOnly
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$ActiveDirectoryOnly,
        
        [Parameter(Mandatory = $false)]
        [switch]$PrivilegedOnly
    )
    
    process {
        try {
            $roleTemplates = Get-MgDirectoryRoleTemplate
            
            if ($ActiveDirectoryOnly) {
                $adRoleNames = @(
                    "Global Administrator",
                    "Privileged Role Administrator",
                    "User Administrator",
                    "Directory Readers",
                    "Directory Writers",
                    "Exchange Administrator",
                    "Helpdesk Administrator",
                    "Authentication Administrator",
                    "Password Administrator",
                    "Security Administrator",
                    "Groups Administrator"
                )
                
                $roleTemplates = $roleTemplates | Where-Object { $_.DisplayName -in $adRoleNames }
            }
            
            if ($PrivilegedOnly) {
                $privilegedRoleNames = @(
                    "Global Administrator",
                    "Privileged Role Administrator",
                    "Security Administrator",
                    "User Administrator",
                    "SharePoint Administrator",
                    "Exchange Administrator",
                    "Conditional Access Administrator",
                    "Application Administrator",
                    "Authentication Policy Administrator"
                )
                
                $roleTemplates = $roleTemplates | Where-Object { $_.DisplayName -in $privilegedRoleNames }
            }
            
            return $roleTemplates
        }
        catch {
            Write-Error "Failed to retrieve admin roles: $_"
            throw
        }
    }
}

function Get-NamedLocations {
    <#
    .SYNOPSIS
        Retrieves named locations from Microsoft Graph.
    .DESCRIPTION
        Gets a list of all named locations from Microsoft Graph API
        and transforms them into a lookup hashtable for easy reference.
    .EXAMPLE
        $namedLocations = Get-NamedLocations
    #>
    [CmdletBinding()]
    param ()
    
    process {
        try {
            $locations = Get-MgIdentityConditionalAccessNamedLocation
            $locationLookup = @{}
            
            foreach ($location in $locations) {
                $locationLookup[$location.Id] = [PSCustomObject]@{
                    Id = $location.Id
                    DisplayName = $location.DisplayName
                    Type = if ($location.AdditionalProperties.ipRanges) { "IP" } else { "Country" }
                    Details = if ($location.AdditionalProperties.ipRanges) {
                        $location.AdditionalProperties.ipRanges
                    }
                    else {
                        $location.AdditionalProperties.countriesAndRegions
                    }
                    IsTrusted = $location.AdditionalProperties.isTrusted
                }
            }
            
            return $locationLookup
        }
        catch {
            Write-Error "Failed to retrieve named locations: $_"
            throw
        }
    }
}

function Get-ApplicationNames {
    <#
    .SYNOPSIS
        Resolves application IDs to display names.
    .DESCRIPTION
        Retrieves and caches application information from Microsoft Graph API
        to convert application IDs to display names for better readability.
    .PARAMETER ApplicationIds
        The list of application IDs to resolve.
    .EXAMPLE
        $appNames = Get-ApplicationNames -ApplicationIds $appIds
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ApplicationIds
    )
    
    begin {
        # Use cached data to avoid repeated Graph calls
        if (-not $Script:ApplicationCache) {
            $Script:ApplicationCache = @{}
        }
    }
    
    process {
        $result = @{}
        $idsToFetch = @()
        
        # Check which IDs need to be fetched from Graph
        foreach ($id in $ApplicationIds) {
            # Handle special application IDs
            if ($id -eq "All") {
                $result[$id] = "All applications"
                continue
            }
            
            if ($id -eq "Office365") {
                $result[$id] = "Microsoft 365"
                continue
            }
            
            if ($id -eq "None") {
                $result[$id] = "No applications"
                continue
            }
            
            # Check cache first
            if ($Script:ApplicationCache.ContainsKey($id)) {
                $result[$id] = $Script:ApplicationCache[$id]
            }
            else {
                $idsToFetch += $id
            }
        }
        
        # Fetch unknown application IDs from Graph
        if ($idsToFetch.Count -gt 0) {
            try {
                foreach ($id in $idsToFetch) {
                    $app = Get-MgServicePrincipal -ServicePrincipalId $id -ErrorAction SilentlyContinue
                    
                    if ($app) {
                        $result[$id] = $app.DisplayName
                        $Script:ApplicationCache[$id] = $app.DisplayName
                    }
                    else {
                        $result[$id] = $id
                        $Script:ApplicationCache[$id] = $id
                    }
                }
            }
            catch {
                Write-Warning "Failed to resolve some application IDs: $_"
            }
        }
        
        return $result
    }
}
