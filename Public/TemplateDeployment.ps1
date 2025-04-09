function Get-CATemplateList {
    <#
    .SYNOPSIS
        Gets a list of available Conditional Access templates.
    .DESCRIPTION
        Retrieves the list of Conditional Access templates available for deployment
        from Microsoft Entra ID, with detailed descriptions of each template.
    .PARAMETER IncludeDetails
        If specified, includes additional details about each template.
    .EXAMPLE
        Get-CATemplateList
        Gets a basic list of available templates.
    .EXAMPLE
        Get-CATemplateList -IncludeDetails
        Gets a detailed list of available templates.
    .NOTES
        This function requires Microsoft.Graph.Beta.Identity.SignIns module for accessing template data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # Check for Microsoft.Graph.Beta module
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Beta.Identity.SignIns)) {
            try {
                Write-Host "Installing Microsoft.Graph.Beta.Identity.SignIns module..." -ForegroundColor Yellow
                Install-Module -Name Microsoft.Graph.Beta.Identity.SignIns -Scope CurrentUser -Force -AllowClobber
                Import-Module -Name Microsoft.Graph.Beta.Identity.SignIns -Force
            }
            catch {
                throw "Failed to install Microsoft.Graph.Beta.Identity.SignIns module. Error: $_"
            }
        }
        
        # Import module if not already imported
        if (-not (Get-Command -Name Get-MgBetaIdentityConditionalAccessTemplate -ErrorAction SilentlyContinue)) {
            try {
                Import-Module -Name Microsoft.Graph.Beta.Identity.SignIns -Force
            }
            catch {
                throw "Failed to import Microsoft.Graph.Beta.Identity.SignIns module. Error: $_"
            }
        }
    }
    
    process {
        try {
            # Get templates
            $templates = Get-MgBetaIdentityConditionalAccessTemplate
            
            if (-not $templates -or $templates.Count -eq 0) {
                Write-Warning "No Conditional Access templates found."
                return @()
            }
            
            # Process templates
            $templateList = @()
            
            foreach ($template in $templates) {
                $templateInfo = [PSCustomObject]@{
                    Id = $template.Id
                    Description = $template.Description
                }
                
                if ($IncludeDetails) {
                    # Add additional details
                    if ($template.Details) {
                        if ($template.Details.DisplayName) {
                            $templateInfo | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $template.Details.DisplayName
                        }
                        
                        if ($template.Details.State) {
                            $templateInfo | Add-Member -MemberType NoteProperty -Name "DefaultState" -Value $template.Details.State
                        }
                    }
                    
                    # Add feature categorization based on description
                    $category = "Other"
                    if ($template.Description -match "MFA") {
                        $category = "MFA"
                    }
                    elseif ($template.Description -match "risk") {
                        $category = "Risk-Based Access"
                    }
                    elseif ($template.Description -match "device") {
                        $category = "Device Compliance"
                    }
                    elseif ($template.Description -match "legacy") {
                        $category = "Legacy Authentication"
                    }
                    elseif ($template.Description -match "session") {
                        $category = "Session Controls"
                    }
                    
                    $templateInfo | Add-Member -MemberType NoteProperty -Name "Category" -Value $category
                }
                
                $templateList += $templateInfo
            }
            
            return $templateList
        }
        catch {
            Write-Error "Failed to retrieve Conditional Access templates: $_"
            throw
        }
    }
}

function Deploy-CATemplate {
    <#
    .SYNOPSIS
        Deploys Conditional Access templates.
    .DESCRIPTION
        Deploys one or more Conditional Access templates as policies in Microsoft Entra ID.
        Templates can be selected by ID or description, and customized with a prefix and state.
    .PARAMETER TemplateIds
        The IDs of the templates to deploy. If not specified, all templates are deployed.
    .PARAMETER TemplateDescriptions
        The descriptions of the templates to deploy. If not specified, all templates are deployed.
    .PARAMETER Prefix
        A prefix to add to the beginning of the policy display names.
    .PARAMETER State
        The state of the deployed policies. Valid values are "enabled", "disabled", or "enabledForReportingButNotEnforced".
    .PARAMETER ExcludeGroups
        The IDs of groups to exclude from the deployed policies.
    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet doesn't make any changes.
    .PARAMETER Force
        If specified, any confirmations are suppressed.
    .EXAMPLE
        Deploy-CATemplate -Prefix "ACME" -State "disabled"
        Deploys all templates with the prefix "ACME" in disabled state.
    .EXAMPLE
        Deploy-CATemplate -TemplateDescriptions "*MFA*", "*risk*" -Prefix "ACME" -State "enabledForReportingButNotEnforced"
        Deploys templates with descriptions containing "MFA" or "risk" in report-only mode.
    .NOTES
        This function requires an active connection to Microsoft Graph with the appropriate permissions.
        Use Connect-CAAnalyzer before running this function.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$TemplateIds,
        
        [Parameter(Mandatory = $false)]
        [string[]]$TemplateDescriptions,
        
        [Parameter(Mandatory = $false)]
        [string]$Prefix = "",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnforced')]
        [string]$State = 'disabled',
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeGroups,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # Check for Microsoft.Graph.Beta module
        if (-not (Get-Module -
