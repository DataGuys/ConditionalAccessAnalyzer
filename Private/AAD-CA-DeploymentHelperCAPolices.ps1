Set-Location $env:OneDriveCommercial\Documents\Scripts
#Import the necessary modules. Beta is needed for preview CA policy template deployment
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.beta.Identity.SignIns

#Connection to Graph Section
#Confirm no other sessions are presently active
Disconnect-MgGraph
# Connect to Microsoft Graph with required scopes
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess" -TenantId $ClientTenantID

# Get the current script directory
$currentDir = "C:\Users\ghall\OneDrive - Helient Systems LLC\Documents\Scripts"


# Add Windows Forms assembly
Add-Type -AssemblyName System.Windows.Forms

# Initialize the main form
$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object System.Drawing.Size(600, 400)
$form.Text = 'AAD Script Runner'

# Initialize Buttons and add Click events
$scriptNames = @(
    "AAD-ExportCAPoliciesToJson.ps1",
    "AAD-RenameAllCurrentCAPolicesWithPrefixOLD.ps1",
    "AAD-DeployCATemplates.ps1",
    "AAD-CreateInclusionandExclusionGroupsforAllCAPoliciesthatareOnOrPrefixed.ps1",
    "AAD-RemoveCAPoliciesPrefixedWithOLD.ps1"
)

$xLocation = 20
$yLocation = 30
$buttonWidth = 550
$buttonHeight = 40
$buttons = @()

function GenerateClickAction([string]$scriptNameToRun) {
    $fullPath = Join-Path -Path $currentDir -ChildPath $scriptNameToRun
    Write-Host "Debug: Full path is $fullPath"  # Debug line for debugging
    $scriptBlock = {
        param (
            [object]$buttonSender,
            [string]$capturedFullPath
        )
        $buttonSender.Enabled = $false
        if (Test-Path $capturedFullPath -PathType Leaf) {
            & $capturedFullPath
        } else {
            Write-Host "Script at path $capturedFullPath not found."
        }
        $nextIndex = $buttons.IndexOf($buttonSender) + 1
        if ($nextIndex -lt $buttons.Count) {
            $buttons[$nextIndex].Enabled = $true
        }
    }
    return $scriptBlock.GetNewClosure()
}




foreach ($scriptName in $scriptNames) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $scriptName
    $button.Width = 200
    $button.Height = 30

    $scriptBlock = GenerateClickAction $scriptName
    $button.Add_Click({
        $buttonSender = $args[0]
        $scriptBlock.Invoke($buttonSender, $fullPath)
    })

    $form.Controls.Add($button)
    $buttons.Add($button)
}


# Enable the first button
$buttons[0].Enabled = $true

# Quit Button
$quitButton = New-Object System.Windows.Forms.Button
$quitButton.Location = New-Object System.Drawing.Point($xLocation, $yLocation)
$quitButton.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
$quitButton.Text = 'Quit'
$quitButton.Add_Click({
    $form.Close()
})
$form.Controls.Add($quitButton)

# Show the Form
$form.ShowDialog()

