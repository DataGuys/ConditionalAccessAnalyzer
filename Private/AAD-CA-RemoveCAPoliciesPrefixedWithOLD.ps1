$ClientTenantID = "6fafc14e-85a2-4063-afbe-eb00d72d7875"
# Connect to Microsoft Graph
Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess' -TenantId $ClientTenantID

Add-Type -AssemblyName System.Windows.Forms

function Remove-OldConditionalAccessPolicies {

    # Confirmation using MessageBox
    $messageBoxText = "Do you want to proceed with removal of all CA policies prefixed with 'OLD-'?"
    $caption = "Confirm Removal"
    $button = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $icon = [System.Windows.Forms.MessageBoxIcon]::Warning

    $result = [System.Windows.Forms.MessageBox]::Show($messageBoxText, $caption, $button, $icon)

    if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host -ForegroundColor Yellow "Operation aborted by user."
        return
    }

    # Connect to Microsoft Graph
    Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'

    # Get all Conditional Access policies
    $allCAPolicies = Get-MgIdentityConditionalAccessPolicy

    # Filter policies prefixed with "OLD-"
    $oldCAPolicies = $allCAPolicies | Where-Object { $_.DisplayName -like "OLD-*" }

    # Loop through each old policy and remove it
    foreach ($policy in $oldCAPolicies) {
        try {
            Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -Confirm:$false
            Write-Host -ForegroundColor Green "Successfully removed policy: $($policy.DisplayName)"
        } catch {
            Write-Host -ForegroundColor Red "Error removing policy: $($policy.DisplayName). Error: $_"
        }
    }
}

# Invoke the function
Remove-OldConditionalAccessPolicies