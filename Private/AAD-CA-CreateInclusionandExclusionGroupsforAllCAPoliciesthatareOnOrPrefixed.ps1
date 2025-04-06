Import-Module Microsoft.Graph.Applications
Import-Module Microsoft.Graph.Identity.DirectoryManagement
# Disconnect any active Graph sessions
Disconnect-MgGraph -ErrorAction SilentlyContinue

# Connect to Microsoft Graph with minimal required scopes
Connect-MgGraph -Scopes "Policy.Read.All", "Group.ReadWrite.All", "Directory.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess"

# Fetch all Conditional Access policies that start with 'KKWC-'
$caPolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -like "GDUB -*"}

function Get-TargetAppRegistrations {
    $allApps = Get-MgServicePrincipal
    $allApps | Where-Object { $_.DisplayName -like '*Citrix*' -or $_.DisplayName -like '*AVD*' } | Out-GridView -Title "Select Service Principals to Exclude" -OutputMode Multiple
}

function Get-OrCreateGroup {
    param (
        [string]$GroupName
    )

    $group = Get-MgGroup -Filter "displayName eq '$GroupName'"
    if (-not $group) {
        $group = New-MgGroup -DisplayName $GroupName -MailNickname "NotSet" -AdditionalProperties @{"securityEnabled"=$true; "mailEnabled"=$false}
        Write-Host -ForegroundColor Green "Created $GroupName"
    } else {
        Write-Host -ForegroundColor Yellow "$GroupName already exists"
    }
    return $group
}

function Add-ToGroup {
    param (
        [string]$GroupId,
        [string]$UserId,
        [string]$Role # Member or Owner
    )

    $existingEntities = if ($Role -eq "Owner") { Get-MgGroupOwner -GroupId $GroupId } else { Get-MgGroupMember -GroupId $GroupId }
    if (-not ($existingEntities | Where-Object { $_.Id -eq $UserId })) {
        if ($Role -eq "Owner") {
            New-MgGroupOwner -GroupId $GroupId -DirectoryObjectId $UserId
        } else {
            New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $UserId
        }
    }
}

$ownerUPN = Read-Host "Please enter the UPN of the owner"
$owner = Get-MgUser -UserId $ownerUPN

$inclusionMemberUPN = Read-Host "Please enter the UPN of a member to add to the inclusion groups (leave blank to skip)"
$inclusionMember = if (-not [string]::IsNullOrWhiteSpace($inclusionMemberUPN)) { Get-MgUser -UserId $inclusionMemberUPN } else { $null }

$exclusionMemberUPN = Read-Host "Please enter the UPN of a member (Original Tenant Admin Account) to add to the exclusion groups (leave blank to skip)"
$exclusionMember = if (-not [string]::IsNullOrWhiteSpace($exclusionMemberUPN)) { Get-MgUser -UserId $exclusionMemberUPN } else { $null }

$targetApps = Get-TargetAppRegistrations
$appExclusions = $targetApps.appid

#Create Breakglass Group Function
$breakglassGroupName = "Breakglass Security Group"
$breakglassGroup = Get-OrCreateGroup -GroupName $breakglassGroupName
Add-ToGroup -GroupId $breakglassGroup.Id -UserId $owner.Id -Role "Owner"

# Process Inclusion Groups for CA Policies
foreach ($policy in $caPolicies) {
    # Generate Inclusion Group Name
    $inclusionGroupName = "$($policy.DisplayName) - Inclusion Group"
    
    # Check or Create the Inclusion Group
    $existingInclusionGroup = Get-OrCreateGroup -GroupName $inclusionGroupName
    
    # Add Owners and Members to the Inclusion Group
    Add-ToGroup -GroupId $existingInclusionGroup.Id -UserId $owner.Id -Role "Owner"
    if ($inclusionMember) {
        Add-ToGroup -GroupId $existingInclusionGroup.Id -UserId $inclusionMember.Id -Role "Member"
    }

    # Logic for Inclusion Group assignment
    $inclusionGroup = Get-MgGroup -Filter "displayName eq '$inclusionGroupName'"
    if ($inclusionGroup) {
        $existingInclusionMembers = Get-MgGroupMember -GroupId $inclusionGroup.Id
        if (-not ($existingInclusionMembers | Where-Object { $_.Id -eq $inclusionMember.Id })) {
            New-MgGroupMember -GroupId $inclusionGroup.Id -DirectoryObjectId $inclusionMember.Id
            Write-Host -ForegroundColor Magenta "Added $inclusionMemberUPN to the inclusion group for $($policy.DisplayName)"
        }
        $updatedPolicy = @{
            "id" = $policy.Id
            "conditions" = @{
                "users" = @{}
            }
        }
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $updatedPolicy
        Write-Host -foregroundcolor Magenta "Cleared All USers on CA policy $($policy.DisplayName)"

        $updatedPolicy = @{
            "id" = $policy.Id
            "conditions" = @{
                "users" = @{
                    "IncludeGroups" = $policy.Conditions.Users.IncludeGroups + $inclusionGroup.Id
                }
            }
        }

        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $updatedPolicy
        Write-Host -foregroundcolor green "Assigned inclusion group to CA policy $($policy.DisplayName)"
    }
}

# Process Exclusion Groups for CA Policies
foreach ($policy in $caPolicies) {
    # Generate Exclusion Group Name
    $exclusionGroupName = "$($policy.DisplayName) - Exclusion Group"
    
    # Check or Create the Exclusion Group
    $existingExclusionGroup = Get-OrCreateGroup -GroupName $exclusionGroupName
    
    # Add Owners and Members to the Exclusion Group
    Add-ToGroup -GroupId $existingExclusionGroup.Id -UserId $owner.Id -Role "Owner"
    if ($exclusionMember) {
        Add-ToGroup -GroupId $existingExclusionGroup.Id -UserId $exclusionMember.Id -Role "Member"
    }

    # Logic for Exclusion Group assignment
    $exclusionGroup = Get-MgGroup -Filter "displayName eq '$exclusionGroupName'"
    if ($exclusionGroup) {
        $existingExclusionMembers = Get-MgGroupMember -GroupId $exclusionGroup.Id
        if (-not ($existingExclusionMembers | Where-Object { $_.Id -eq $exclusionMember.Id })) {
            New-MgGroupMember -GroupId $exclusionGroup.Id -DirectoryObjectId $exclusionMember.Id
            Write-Host -ForegroundColor Green "Added $exclusionMemberUPN to the exclusion group for $($policy.DisplayName)"
        }

        $updatedPolicy = @{
            "id" = $policy.Id
            "conditions" = @{
                "users" = @{
                    "excludeGroups" = $policy.Conditions.Users.ExcludeGroups + $exclusionGroup.Id
                }
            }
        }

        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $updatedPolicy
        Write-Host -ForegroundColor Green "Assigned exclusion group to CA policy $($policy.DisplayName)"
    }
        # Logic for Breakglass Group assignment
        $updatedPolicy = @{
            "id" = $policy.Id
            "conditions" = @{
                "users" = @{
                    "excludeGroups" = $policy.Conditions.Users.ExcludeGroups + $breakglassGroup.Id
                }
            }
        }
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $updatedPolicy
        Write-Host -ForegroundColor Cyan "Assigned Breakglass group to CA policy $($policy.DisplayName) as an exclusion"
    
        # Logic for Cloud App Exclusions
        $currentPolicy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
        $policyUpdate = @{
            Conditions = @{
                Applications = @{
                    ExcludeApplications = if ($currentPolicy.Conditions.Applications) {
                                            $currentPolicy.Conditions.Applications.Exclude + $appExclusions
                                            } else { 
                                            $appExclusions 
                                            }
                }
            }
        }
        try {
            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $policyUpdate -ErrorAction Stop
            Write-Host -ForegroundColor DarkGreen "Added app exclusions to CA policy $($policy.DisplayName)"
        } catch {
            Write-Host "Failed to update CA policy $($policy.DisplayName). Error: $($_.Exception.Message)" -ForegroundColor Red
        }
}

Write-Host -ForegroundColor Green "CA Policy Include and Exclude Script Complete, Please validate changes are reflected in the portal"