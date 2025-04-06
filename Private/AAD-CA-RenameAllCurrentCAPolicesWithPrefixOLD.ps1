Add-Type -AssemblyName System.Windows.Forms
Set-Location $env:OneDriveCommercial\Documents\Scripts 
function Rename-CurrentPoliciesToOld {
   
    # Retrieve the current tenant ID and domain
    $tenantInfo = Get-MgOrganization
    $tenantId = $tenantInfo.Id
    $tenantDomain = $tenantInfo.VerifiedDomain | Where-Object { $_.IsDefault -eq $true } | Select-Object -ExpandProperty Name

    Write-Host "Connected to Tenant ID: $tenantId" -ForegroundColor Cyan
    Write-Host "Connected to Tenant Domain: $tenantDomain" -ForegroundColor Cyan

    # Confirmation using MessageBox
    $messageBoxText = "You are connected to $tenantDomain ($tenantId).`nDo you want to proceed with renaming current CA policies to prefix with 'OLD-'?"
    $caption = "Confirm Rename"
    $button = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $icon = [System.Windows.Forms.MessageBoxIcon]::Warning

    $result = [System.Windows.Forms.MessageBox]::Show($messageBoxText, $caption, $button, $icon)

    if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host -ForegroundColor Yellow "Operation aborted by user."
        return
    }

    # Get all Conditional Access policies
    $policies = Get-MgIdentityConditionalAccessPolicy
    $policies | Export-Csv .\CurrentPolicies.csv -NoTypeInformation

    foreach ($policy in $policies) {
        # Check if the policy name already has the "OLD-" prefix
        if (-not $policy.DisplayName.StartsWith("OLD-")) {
            # Rename the policy
            $newName = "OLD-" + $policy.DisplayName
            $bodyParams = @{
                DisplayName = $newName
            }
            # Update the policy with the new name
            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter $bodyParams
            Write-Host "Renamed $($policy.DisplayName) to $newName." -ForegroundColor Green
        } else {
            Write-Host "$($policy.DisplayName) already has the 'OLD-' prefix. Skipping..." -ForegroundColor Yellow
        }
    }

    Write-Host "OLD CA Policy Rename Function Completed." -ForegroundColor Cyan
}

# Invoke the function
Rename-CurrentPoliciesToOld
