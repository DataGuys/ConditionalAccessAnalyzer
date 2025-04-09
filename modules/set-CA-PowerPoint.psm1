function Set-CA-PowerPoint {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Array]$CAPolicies,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [Array]$BenchmarkPolicies,
        
        [Parameter(Mandatory = $false)]
        [switch]$ComparisonMode
    )

    try {
        # Check if PowerPoint is installed
        try {
            $null = New-Object -ComObject PowerPoint.Application
            Write-Verbose "PowerPoint is installed."
        }
        catch {
            throw "PowerPoint is not installed on this system. Cannot generate presentation."
        }

        # Load required assemblies for PowerPoint automation
        Add-Type -AssemblyName Office
        
        # Create PowerPoint application instance
        $powerPoint = New-Object -ComObject PowerPoint.Application
        $powerPoint.Visible = [Microsoft.Office.Core.MsoTriState]::msoTrue
        
        # Create a new presentation
        $presentation = $powerPoint.Presentations.Add()
        
        # Get template path
        $templatePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath "templates\CATemplate.potx"
        
        # Apply template if exists
        if (Test-Path -Path $templatePath) {
            $presentation.ApplyTemplate($templatePath)
        }
        
        # Add title slide
        $titleSlide = $presentation.Slides.Add(1, 1) # 1 = position, 1 = layout (title slide)
        $titleSlide.Shapes.Title.TextFrame.TextRange.Text = "Conditional Access Policies Analysis"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $titleSlide.Shapes.Item(2).TextFrame.TextRange.Text = "Generated: $timestamp`nTenant: $((Get-MgContext).TenantId)"
        
        # Add summary slide
        $summarySlide = $presentation.Slides.Add(2, 2) # 2 = position, 2 = layout (title and content)
        $summarySlide.Shapes.Title.TextFrame.TextRange.Text = "Summary"
        
        $summaryText = "Total Policies: $($CAPolicies.Count)`n"
        $summaryText += "Enabled Policies: $($CAPolicies.Where{$_.State -eq 'enabled'}.Count)`n"
        $summaryText += "Disabled Policies: $($CAPolicies.Where{$_.State -eq 'disabled'}.Count)`n"
        $summaryText += "Report Only Policies: $($CAPolicies.Where{$_.State -eq 'enabledForReportingButNotEnforced'}.Count)`n"
        
        if ($ComparisonMode -and $BenchmarkPolicies) {
            $summaryText += "`nComparison with Benchmark:`n"
            $summaryText += "Benchmark Policies: $($BenchmarkPolicies.Count)`n"
            $summaryText += "New Policies: $($CAPolicies.Where{$_.DisplayName -notin $BenchmarkPolicies.DisplayName}.Count)`n"
            $summaryText += "Missing Policies: $($BenchmarkPolicies.Where{$_.DisplayName -notin $CAPolicies.DisplayName}.Count)`n"
        }
        
        $summarySlide.Shapes.Item(2).TextFrame.TextRange.Text = $summaryText
        
        # Add policy slides for each policy
        $slidePosition = 3
        foreach ($policy in $CAPolicies) {
            # Create a new slide for each policy
            $policySlide = $presentation.Slides.Add($slidePosition, 2) # position, layout (title and content)
            $policySlide.Shapes.Title.TextFrame.TextRange.Text = $policy.DisplayName
            
            # Format policy details
            $policyDetails = "ID: $($policy.Id)`n"
            $policyDetails += "State: $($policy.State)`n"
            $policyDetails += "`nConditions:`n"
            
            # Users
            $policyDetails += "  • Users: "
            if ($policy.Conditions.Users.IncludeUsers -contains "All") {
                $policyDetails += "All users"
            }
            elseif ($policy.Conditions.Users.IncludeUsers.Count -gt 0) {
                $policyDetails += "Included: $($policy.Conditions.Users.IncludeUsers.Count) users/groups"
            }
            if ($policy.Conditions.Users.ExcludeUsers.Count -gt 0) {
                $policyDetails += ", Excluded: $($policy.Conditions.Users.ExcludeUsers.Count) users/groups"
            }
            $policyDetails += "`n"
            
            # Applications
            $policyDetails += "  • Applications: "
            if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
                $policyDetails += "All applications"
            }
            elseif ($policy.Conditions.Applications.IncludeApplications.Count -gt 0) {
                $policyDetails += "Included: $($policy.Conditions.Applications.IncludeApplications.Count) apps"
            }
            if ($policy.Conditions.Applications.ExcludeApplications.Count -gt 0) {
                $policyDetails += ", Excluded: $($policy.Conditions.Applications.ExcludeApplications.Count) apps"
            }
            $policyDetails += "`n"
            
            # Locations
            if ($policy.Conditions.Locations.PSObject.Properties.Name -contains "IncludeLocations") {
                $policyDetails += "  • Locations: "
                if ($policy.Conditions.Locations.IncludeLocations -contains "All") {
                    $policyDetails += "All locations"
                }
                elseif ($policy.Conditions.Locations.IncludeLocations.Count -gt 0) {
                    $policyDetails += "Included: $($policy.Conditions.Locations.IncludeLocations.Count) locations"
                }
                if ($policy.Conditions.Locations.ExcludeLocations.Count -gt 0) {
                    $policyDetails += ", Excluded: $($policy.Conditions.Locations.ExcludeLocations.Count) locations"
                }
                $policyDetails += "`n"
            }
            
            # Grant Controls
            $policyDetails += "`nGrant Controls: "
            if ($policy.GrantControls.Operator -eq "OR") {
                $policyDetails += "Require one of the selected controls`n"
            }
            else {
                $policyDetails += "Require all selected controls`n"
            }
            
            if ($policy.GrantControls.BuiltInControls) {
                $policyDetails += "  • " + ($policy.GrantControls.BuiltInControls -join "`n  • ") + "`n"
            }
            
            # Session Controls
            if ($policy.SessionControls) {
                $policyDetails += "`nSession Controls:`n"
                if ($policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
                    $policyDetails += "  • App enforced restrictions: Enabled`n"
                }
                if ($policy.SessionControls.CloudAppSecurity.IsEnabled) {
                    $policyDetails += "  • Cloud App Security: Enabled`n"
                }
                if ($policy.SessionControls.SignInFrequency.IsEnabled) {
                    $policyDetails += "  • Sign-in frequency: $($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)`n"
                }
                if ($policy.SessionControls.PersistentBrowser.IsEnabled) {
                    $policyDetails += "  • Persistent browser session: $($policy.SessionControls.PersistentBrowser.Mode)`n"
                }
            }
            
            # If in comparison mode, add comparison information
            if ($ComparisonMode -and $BenchmarkPolicies) {
                $matchingPolicy = $BenchmarkPolicies | Where-Object { $_.DisplayName -eq $policy.DisplayName }
                if ($matchingPolicy) {
                    $policyDetails += "`nComparison: Policy exists in benchmark"
                    
                    # Compare state
                    if ($matchingPolicy.State -ne $policy.State) {
                        $policyDetails += "`n  • State changed: $($matchingPolicy.State) -> $($policy.State)"
                    }
                    
                    # Compare other properties as needed
                }
                else {
                    $policyDetails += "`nComparison: New policy (not in benchmark)"
                }
            }
            
            $policySlide.Shapes.Item(2).TextFrame.TextRange.Text = $policyDetails
            $slidePosition++
        }
        
        # If in comparison mode, add slides for missing policies
        if ($ComparisonMode -and $BenchmarkPolicies) {
            $missingPolicies = $BenchmarkPolicies | Where-Object { $_.DisplayName -notin $CAPolicies.DisplayName }
            
            foreach ($policy in $missingPolicies) {
                $missingSlide = $presentation.Slides.Add($slidePosition, 2) # position, layout (title and content)
                $missingSlide.Shapes.Title.TextFrame.TextRange.Text = "[MISSING] $($policy.DisplayName)"
                
                # Format policy details
                $policyDetails = "ID: $($policy.Id)`n"
                $policyDetails += "State: $($policy.State)`n"
                $policyDetails += "`nThis policy existed in the benchmark but is no longer present.`n"
                $policyDetails += "`nBenchmark policy details:`n"
                
                # Add basic policy information
                $policyDetails += "Users: $($policy.Conditions.Users.IncludeUsers.Count) included, $($policy.Conditions.Users.ExcludeUsers.Count) excluded`n"
                $policyDetails += "Applications: $($policy.Conditions.Applications.IncludeApplications.Count) included, $($policy.Conditions.Applications.ExcludeApplications.Count) excluded`n"
                
                $missingSlide.Shapes.Item(2).TextFrame.TextRange.Text = $policyDetails
                $slidePosition++
            }
        }
        
        # Add recommendations slide
        $recSlide = $presentation.Slides.Add($slidePosition, 2) # position, layout (title and content)
        $recSlide.Shapes.Title.TextFrame.TextRange.Text = "Recommendations"
        
        $recommendations = "Based on analysis of your Conditional Access policies:`n`n"
        
        # Generate recommendations
        if ($CAPolicies.Where{$_.State -eq 'disabled'}.Count -gt 0) {
            $recommendations += "• You have $($CAPolicies.Where{$_.State -eq 'disabled'}.Count) disabled policies. Consider cleaning up unused policies.`n"
        }
        
        if ($CAPolicies.Where{$_.State -eq 'enabledForReportingButNotEnforced'}.Count -gt 0) {
            $recommendations += "• You have $($CAPolicies.Where{$_.State -eq 'enabledForReportingButNotEnforced'}.Count) policies in report-only mode. Review these for possible enforcement.`n"
        }
        
        if ($CAPolicies.Where{$_.Conditions.Users.ExcludeUsers -contains "GuestsOrExternalUsers"}.Count -eq 0) {
            $recommendations += "• Consider adding specific policies for guest and external users.`n"
        }
        
        $defaultAppCount = ($CAPolicies.Where{$_.Conditions.Applications.IncludeApplications -contains "All"}).Count
        if ($defaultAppCount -eq 0) {
            $recommendations += "• No policies apply to all applications. Consider adding a baseline policy.`n"
        }
        
        $mfaPolicies = ($CAPolicies.Where{$_.GrantControls.BuiltInControls -contains "mfa" -and $_.State -eq 'enabled'}).Count
        if ($mfaPolicies -eq 0) {
            $recommendations += "• No enabled policies require MFA. Consider implementing MFA for sensitive applications.`n"
        }
        
        $recSlide.Shapes.Item(2).TextFrame.TextRange.Text = $recommendations
        
        # Save the presentation
        $presentation.SaveAs($Path)
        Write-Host "PowerPoint presentation saved to: $Path" -ForegroundColor Green
        
        # Close PowerPoint if requested
        if (-not $powerPoint.Visible) {
            $presentation.Close()
            $powerPoint.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($presentation) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($powerPoint) | Out-Null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        
        return $true
    }
    catch {
        Write-Error "Error creating PowerPoint presentation: $_"
        return $false
    }
}

Export-ModuleMember -Function Set-CA-PowerPoint
