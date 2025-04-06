Set-Location $Env:OneDriveCommercial\Documents\Scripts 
#Variables
$ClientTenantID = ""
# Prompt the user for a prefix (Client Code) for the Conditional Access policies
$prefix = Read-Host "Please enter the prefix (Client Code) for the New Conditional Access policies from Templates"

# Required Modules Section
#Check for and Update Graph and Graph.beta modules to latest version
#.\PS-UpdateGraphandBetatoLatestVersions.ps1
#Import the necessary modules. Beta is needed for preview CA policy template deployment
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.beta.Identity.SignIns

#Connection to Graph Section
#Confirm no other sessions are presently active
Disconnect-MgGraph
# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess" -TenantId $ClientTenantID

#Backup all current CA Polices to JSON, Output to userprofile\Documents folder
#Set-Location $Env:OneDriveCommercial\Documents\Scripts
#.\AAD-ExportCAPoliciesToJson.ps1

#Rename all current CA Polices by adding a prefix of OLD to help make sense of what is the new templates. 
#Not impactful from previous runs of this.
#Set-Location $Env:OneDriveCommercial\Documents\Scripts
#.\AAD-RenameAllCurrentCAPolicesWithPrefixOLD.ps1

# Define the policy name map based on descriptions
# Helps us to control the naming of the new templates to make it a bit easier to understand its purpose.
$policyNameMap = @{
    "Require multifactor authentication for privileged administrative accounts to reduce risk of compromise. This policy will target the same roles as security defaults." = "MFA for Privileged Admins";
    "Secure when and how users register for Azure AD multifactor authentication and self-service password reset." = "Secure MFA & SSPR Registration";
    "Block legacy authentication endpoints that can be used to bypass multifactor authentication." = "Block Legacy Auth";
    "Require multifactor authentication for all user accounts to reduce risk of compromise." = "MFA for All Users";
    "Require guest users perform multifactor authentication when accessing your company resources." = "MFA for Guests";
    "Require multifactor authentication to protect privileged access to Azure management." = "MFA for Azure Management";
    "Require multifactor authentication if the sign-in risk is detected to be medium or high. (Requires an Azure AD Premium P2 License)" = "MFA for Medium/High Risk Sign-Ins";
    "Require the user to change their password if the user risk is detected to be high. (Requires an Azure AD Premium P2 License)" = "Password Change for High-Risk Users";
    "Require privileged administrators to only access resources when using a compliant or hybrid Azure AD joined device." = "Hybrid/Compliant Device for Admins";
    "Users will be blocked from accessing company resources when the device type is unknown or unsupported." = "Block Unknown/Unsupported Devices";
    "Protect user access on unmanaged devices by preventing browser sessions from remaining signed in after the browser is closed and setting a sign-in frequency to 1 hour." = "Non-Persistent Browser Sessions";
    "To prevent data loss, organizations can restrict access to approved modern auth client apps with Intune app protection policies." = "Intune App Protection";
    "Protect access to company resources by requiring users to use a managed device or perform multifactor authentication." = "MFA or Managed Device";
    "Block or limit access to O365 apps, including SharePoint Online, OneDrive, and Exchange Online content. This policy requires SharePoint admin center configuration." = "Restrictions for O365 Apps";
    "Require phishing-resistant multifactor authentication for privileged administrative accounts to reduce risk of compromise and phishing attacks. This policy requires admins to have at least one phishing resistant authentication method registered." = "Phishing-Resistant MFA for Admins";
    "Use this template to protect sign-ins to admin portals if you are unable to use the ""Require MFA for admins"" template." = "MFA for Microsoft Admin Portals";
    "Configure insider risk as a condition to identify potential risky behavior (Requires an Azure AD premium P2 license). (Preview)" = "Insider Risk Condition"
}

# Fetch and select the desired Conditional Access templates
$templates = Get-MgIdentityConditionalAccessTemplate | Out-GridView -Title "Pick the templates you want to deploy (CTRL + Click for multiple choices)" -PassThru
# Export the selected templates to a CSV for reference
$templates | Export-Csv .\TemplatesDeployed.csv -NoTypeInformation

# Process each template and create a new Conditional Access policy with a renamed title derived from the description
foreach ($template in $templates) {
    $newPolicyName = $policyNameMap[$template.Description]
    if (-not $newPolicyName) {
        Write-Error "No matching name found for $($template.Description). Skipping this template."
        continue
    }
    $displayName = "$prefix - $newPolicyName"

    $bodyParams = @{
        displayName   = $displayName
        state         = "disabled"
        templateId    = $template.Id
    }

    New-MgIdentityConditionalAccessPolicy -BodyParameter $bodyParams
}
