Install-Module AzureAD
# Import the module
Import-Module AzureAD

# Connect to Azure AD
Connect-AzureAD

# Get all Azure AD roles
$roles = Get-AzureADDirectoryRole

# Create an empty hashtable to hold results
$userRoles = @{}

# Loop through each role and get members
foreach ($role in $roles) {
    $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId

    foreach ($member in $members) {
        if (-not $userRoles.ContainsKey($member.ObjectId)) {
            $userRoles[$member.ObjectId] = @{
                'UserName' = $member.DisplayName
                'Roles'    = @()
            }
        }
        
        $userRoles[$member.ObjectId].Roles += $role.DisplayName
    }
}

# Convert hashtable to array of objects for export
$results = $userRoles.Values | ForEach-Object {
    [PSCustomObject]@{
        'UserName' = $_.UserName
        'Roles'    = ($_.Roles -join ', ')
    }
}

# Export results to CSV
$results | Export-Csv -Path 'AzureADRolesByUser.csv' -NoTypeInformation



# Create App Registration without identifierUri
$appName = "NamedLocationApp"
$app = New-AzureADApplication -DisplayName $appName
# No need to search for the app we just created
$graphApp = Get-AzureADServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
$AppObjectID = $app.ObjectId  # Store the ObjectId for later use

#Directory Roles List
$RolesList = 'AdministrativeUnit.Read.All',
'Application.Read.All',
'AuditLog.Read.All',
'Directory.Read.All',
'Group.Read.All',
'Policy.Read.All',
'PrivilegedAccess.Read.AzureAD',
'Reports.Read.All',
'RoleManagement.Read.Directory',
'User.Read.All',
'UserAuthenticationMethod.Read.All'

# Create a collection of required permissions
$requiredResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$requiredResourceAccess.ResourceAppId = $graphApp.AppId
$requiredResourceAccess.ResourceAccess = @()

# Add all roles from RolesList
foreach ($roleName in $RolesList) {
    $permission = $graphApp.AppRoles | Where-Object { $_.Value -eq $roleName } | Select-Object -First 1
    if ($permission) {
        $resourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess"
        $resourceAccess.Id = $permission.Id
        $resourceAccess.Type = "Role"
        $requiredResourceAccess.ResourceAccess += $resourceAccess
    } else {
        Write-Warning "Permission $roleName not found"
    }
}
# Variables
# Set all permissions at once
Set-AzureADApplication -ObjectId $app.ObjectId -RequiredResourceAccess @($requiredResourceAccess)
$AppObjectID = (Get-AzureADApplication -SearchString "NamedLocationApp").ObjectId
$AppObjectID = (Get-AzureADApplication -SearchString "NamedLocationApp").ObjectId
# Variables
# Fetch the service principal of the app
$servicePrincipal = Get-AzureADServicePrincipal -ObjectId $app.AppId
# Grant admin consent
$servicePrincipal.Oauth2Permissions | ForEach-Object {
    Set-AzureADOAuth2PermissionGrant -ObjectId $_.Id -ConsentType AllPrincipals -PrincipalId $servicePrincipal.ObjectId -Scope $_.Scope
}

Write-Output "Admin consent granted for all permissions"

# Set the expiry for the secret
$endDate = Get-Date -Date "2032-12-31T00:00:00Z"

# Create the client secret
$secret = New-AzureADApplicationPasswordCredential -ObjectId $AppObjectID -EndDate $endDate

# Print the secret (make sure to store this securely)
$secret.Value

# Print the secret (make sure to store this securely)
$clientSecret = $secret.Value

# Variables
$resourceURL = "https://graph.microsoft.com"
$tokenURL = "https://login.microsoftonline.com/$tenantId/oauth2/token"

# Get an access token
$body = @{
    client_id     = $clientID
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

$response = Invoke-RestMethod -Method Post -Uri $tokenURL -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing
$token = $response.access_token

# Fetch the Named Location data
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$namedLocationsURL = "$resourceURL/v1.0/identity/conditionalAccess/namedLocations"
$namedLocations = Invoke-RestMethod -Method Get -Uri $namedLocationsURL -Headers $headers

# Export the data to CSV
$namedLocations.value | Export-Csv -Path "NamedLocations.csv" -NoTypeInformation

Write-Output "Named Location data exported to NamedLocations.csv"

