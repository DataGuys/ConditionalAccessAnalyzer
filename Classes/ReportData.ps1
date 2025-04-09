# Complete the ConvertTo-JsonReport function
function ConvertTo-JsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Results
    )
    
    # Create enhanced report structure
    $report = @{
        ReportInfo = @{
            Title = "Conditional Access Compliance Report"
            GeneratedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TenantId = $Results.TenantId
            TenantName = $Results.TenantName
            ComplianceScore = $Results.ComplianceScore
        }
        Summary = @{
            IdentityProtection = @{
                Status = if ($Results.Checks.AdminMFA.AdminMFARequired -and $Results.Checks.UserMFA.BroadUserMFARequired) { "PASS" } else { "FAIL" }
                Score = [math]::Round(([int]$Results.Checks.AdminMFA.AdminMFARequired + [int]$Results.Checks.UserMFA.BroadUserMFARequired) / 2 * 100)
            }
            DeviceTrust = @{
                Status = if ($Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) { "PASS" } else { "FAIL" }
                Score = [math]::Round([int]$Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired * 100)
            }
            SessionSecurity = @{
                Status = if ($Results.Checks.TokenBinding.TokenSessionBindingConfigured) { "PASS" } else { "FAIL" }
                Score = [math]::Round([int]$Results.Checks.TokenBinding.TokenSessionBindingConfigured * 100)
            }
            RiskBasedAccess = @{
                Status = if ($Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -and $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) { "PASS" } else { "FAIL" }
                Score = [math]::Round(([int]$Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured + [int]$Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) / 2 * 100)
            }
            DataProtection = @{
                Status = if ($Results.Checks.MAMPolicies.MAMPoliciesConfigured) { "PASS" } else { "FAIL" }
                Score = [math]::Round([int]$Results.Checks.MAMPolicies.MAMPoliciesConfigured * 100)
            }
            NetworkSecurity = @{
                Status = if ($Results.Checks.ZeroTrust.MDCAIntegrated -and $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) { "PASS" } else { "FAIL" }
                Score = [math]::Round(([int]$Results.Checks.ZeroTrust.MDCAIntegrated + [int]$Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) / 2 * 100)
            }
        }
        Checks = @{
            AdminMFA = @{
                Name = "Admin MFA Required"
                Status = if ($Results.Checks.AdminMFA.AdminMFARequired) { "PASS" } else { "FAIL" }
                Category = "Identity Protection"
                Severity = "Critical"
                Recommendation = $Results.Checks.AdminMFA.Recommendation
                Details = $Results.Checks.AdminMFA
            }
            UserMFA = @{
                Name = "User MFA Required"
                Status = if ($Results.Checks.UserMFA.BroadUserMFARequired) { "PASS" } else { "FAIL" }
                Category = "Identity Protection"
                Severity = "High"
                Recommendation = $Results.Checks.UserMFA.Recommendation
                Details = $Results.Checks.UserMFA
            }
            DeviceCompliance = @{
                Name = "Device Compliance Required"
                Status = if ($Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) { "PASS" } else { "FAIL" }
                Category = "Device Trust"
                Severity = "High"
                Recommendation = $Results.Checks.DeviceCompliance.Recommendation
                Details = $Results.Checks.DeviceCompliance
            }
            TokenBinding = @{
                Name = "Token Session Binding"
                Status = if ($Results.Checks.TokenBinding.TokenSessionBindingConfigured) { "PASS" } else { "FAIL" }
                Category = "Session Security"
                Severity = "Medium"
                Recommendation = $Results.Checks.TokenBinding.Recommendation
                Details = $Results.Checks.TokenBinding
            }
            RiskPolicies = @{
                Name = "Risk-Based Policies"
                Status = if ($Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -and $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) { "PASS" } else { "FAIL" }
                Category = "Risk-Based Access"
                Severity = "High"
                Recommendation = $Results.Checks.RiskPolicies.Recommendation
                SubChecks = @{
                    SignInRiskPolicies = @{
                        Name = "Sign-In Risk Policies"
                        Status = if ($Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured) { "PASS" } else { "FAIL" }
                    }
                    UserRiskPolicies = @{
                        Name = "User Risk Policies"
                        Status = if ($Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) { "PASS" } else { "FAIL" }
                    }
                }
                Details = $Results.Checks.RiskPolicies
            }
            MAMPolicies = @{
                Name = "Mobile Application Management"
                Status = if ($Results.Checks.MAMPolicies.MAMPoliciesConfigured) { "PASS" } else { "FAIL" }
                Category = "Data Protection"
                Severity = "Medium"
                Recommendation = $Results.Checks.MAMPolicies.Recommendation
                Details = $Results.Checks.MAMPolicies
            }
            ZeroTrust = @{
                Name = "Zero Trust Network Access"
                Status = if ($Results.Checks.ZeroTrust.MDCAIntegrated -and $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) { "PASS" } else { "FAIL" }
                Category = "Network Security"
                Severity = "High"
                Recommendation = $Results.Checks.ZeroTrust.Recommendation
                SubChecks = @{
                    MDCAIntegration = @{
                        Name = "MDCA Integration"
                        Status = if ($Results.Checks.ZeroTrust.MDCAIntegrated) { "PASS" } else { "FAIL" }
                    }
                    GlobalSecureAccess = @{
                        Name = "Global Secure Access"
                        Status = if ($Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) { "PASS" } else { "FAIL" }
                    }
                }
                Details = $Results.Checks.ZeroTrust
            }
        }
        Recommendations = @(
            # Add high priority recommendations first
            if (-not $Results.Checks.AdminMFA.AdminMFARequired) {
                @{
                    Priority = "Critical"
                    Category = "Identity Protection"
                    Title = "Admin MFA Enforcement"
                    Description = $Results.Checks.AdminMFA.Recommendation
                }
            }
            
            if (-not $Results.Checks.UserMFA.BroadUserMFARequired) {
                @{
                    Priority = "High"
                    Category = "Identity Protection"
                    Title = "User MFA Enforcement"
                    Description = $Results.Checks.UserMFA.Recommendation
                }
            }
            
            if (-not $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) {
                @{
                    Priority = "High"
                    Category = "Device Trust"
                    Title = "Device Compliance"
                    Description = $Results.Checks.DeviceCompliance.Recommendation
                }
            }
            
            if (-not $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -or -not $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) {
                @{
                    Priority = "High"
                    Category = "Risk-Based Access"
                    Title = "Risk-Based Access"
                    Description = $Results.Checks.RiskPolicies.Recommendation
                }
            }
            
            if (-not $Results.Checks.ZeroTrust.MDCAIntegrated -or -not $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) {
                @{
                    Priority = "High"
                    Category = "Network Security"
                    Title = "Zero Trust Network Access"
                    Description = $Results.Checks.ZeroTrust.Recommendation
                }
            }
            
            # Add medium priority recommendations
            if (-not $Results.Checks.TokenBinding.TokenSessionBindingConfigured) {
                @{
                    Priority = "Medium"
                    Category = "Session Security"
                    Title = "Token Session Binding"
                    Description = $Results.Checks.TokenBinding.Recommendation
                }
            }
            
            if (-not $Results.Checks.MAMPolicies.MAMPoliciesConfigured) {
                @{
                    Priority = "Medium"
                    Category = "Data Protection"
                    Title = "Mobile Application Management"
                    Description = $Results.Checks.MAMPolicies.Recommendation
                }
            }
        )
    }
    
    # Convert to JSON and return
    return ConvertTo-Json -InputObject $report -Depth 10
}

# Excel report generation function
function Export-ExcelReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRecommendations
    )
    
    # Check if ImportExcel module is available
    if (-not (Get-Module -Name ImportExcel -ListAvailable)) {
        try {
            Write-Host "ImportExcel module not found. Attempting to install..." -ForegroundColor Yellow
            Install-Module -Name ImportExcel -Scope CurrentUser -Force
        }
        catch {
            Write-Error "Failed to install ImportExcel module. Please install it manually with 'Install-Module -Name ImportExcel'."
            Write-Error "Falling back to CSV format."
            $csvContent = Generate-CsvReport -Results $Results
            Set-Content -Path $Path.Replace(".xlsx", ".csv") -Value $csvContent -Encoding UTF8
            return
        }
    }
    
    # Import the module
    Import-Module ImportExcel
    
    # Create a new Excel package
    $excelPackage = New-Object OfficeOpenXml.ExcelPackage
    
    # Summary worksheet
    $summarySheet = $excelPackage.Workbook.Worksheets.Add("Summary")
    
    # Add title
    $summarySheet.Cells["A1"].Value = "Conditional Access Compliance Report"
    $summarySheet.Cells["A1:H1"].Merge = $true
    $summarySheet.Cells["A1"].Style.Font.Size = 16
    $summarySheet.Cells["A1"].Style.Font.Bold = $true
    
    # Add tenant info
    $summarySheet.Cells["A3"].Value = "Tenant Name:"
    $summarySheet.Cells["B3"].Value = $Results.TenantName
    $summarySheet.Cells["A4"].Value = "Tenant ID:"
    $summarySheet.Cells["B4"].Value = $Results.TenantId
    $summarySheet.Cells["A5"].Value = "Report Date:"
    $summarySheet.Cells["B5"].Value = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add compliance score
    $summarySheet.Cells["A7"].Value = "Compliance Score:"
    $summarySheet.Cells["B7"].Value = "$($Results.ComplianceScore)%"
    $summarySheet.Cells["B7"].Style.Font.Bold = $true
    $summarySheet.Cells["B7"].Style.Font.Size = 14
    
    # Apply color to score based on value
    if ($Results.ComplianceScore -ge 90) {
        $summarySheet.Cells["B7"].Style.Font.Color.SetColor([System.Drawing.Color]::Green)
    }
    elseif ($Results.ComplianceScore -ge 80) {
        $summarySheet.Cells["B7"].Style.Font.Color.SetColor([System.Drawing.Color]::DarkGreen)
    }
    elseif ($Results.ComplianceScore -ge 70) {
        $summarySheet.Cells["B7"].Style.Font.Color.SetColor([System.Drawing.Color]::Orange)
    }
    elseif ($Results.ComplianceScore -ge 60) {
        $summarySheet.Cells["B7"].Style.Font.Color.SetColor([System.Drawing.Color]::DarkOrange)
    }
    else {
        $summarySheet.Cells["B7"].Style.Font.Color.SetColor([System.Drawing.Color]::Red)
    }
    
    # Summary table headers
    $summarySheet.Cells["A10"].Value = "Security Pillar"
    $summarySheet.Cells["B10"].Value = "Status"
    $summarySheet.Cells["C10"].Value = "Score"
    
    # Format headers
    $summarySheet.Cells["A10:C10"].Style.Font.Bold = $true
    $summarySheet.Cells["A10:C10"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $summarySheet.Cells["A10:C10"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
    
    # Add security pillars
    $pillars = @(
        @{
            Name = "Identity Protection"
            Status = if ($Results.Checks.AdminMFA.AdminMFARequired -and $Results.Checks.UserMFA.BroadUserMFARequired) { "PASS" } else { "FAIL" }
            Score = [math]::Round(([int]$Results.Checks.AdminMFA.AdminMFARequired + [int]$Results.Checks.UserMFA.BroadUserMFARequired) / 2 * 100)
        },
        @{
            Name = "Device Trust"
            Status = if ($Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) { "PASS" } else { "FAIL" }
            Score = [math]::Round([int]$Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired * 100)
        },
        @{
            Name = "Session Security"
            Status = if ($Results.Checks.TokenBinding.TokenSessionBindingConfigured) { "PASS" } else { "FAIL" }
            Score = [math]::Round([int]$Results.Checks.TokenBinding.TokenSessionBindingConfigured * 100)
        },
        @{
            Name = "Risk-Based Access"
            Status = if ($Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -and $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) { "PASS" } else { "FAIL" }
            Score = [math]::Round(([int]$Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured + [int]$Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) / 2 * 100)
        },
        @{
            Name = "Data Protection"
            Status = if ($Results.Checks.MAMPolicies.MAMPoliciesConfigured) { "PASS" } else { "FAIL" }
            Score = [math]::Round([int]$Results.Checks.MAMPolicies.MAMPoliciesConfigured * 100)
        },
        @{
            Name = "Network Security"
            Status = if ($Results.Checks.ZeroTrust.MDCAIntegrated -and $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) { "PASS" } else { "FAIL" }
            Score = [math]::Round(([int]$Results.Checks.ZeroTrust.MDCAIntegrated + [int]$Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) / 2 * 100)
        }
    )
    
    # Add pillar data
    for ($i = 0; $i -lt $pillars.Count; $i++) {
        $row = 11 + $i
        $summarySheet.Cells["A$row"].Value = $pillars[$i].Name
        $summarySheet.Cells["B$row"].Value = $pillars[$i].Status
        $summarySheet.Cells["C$row"].Value = "$($pillars[$i].Score)%"
        
        # Apply color based on status
        if ($pillars[$i].Status -eq "PASS") {
            $summarySheet.Cells["B$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Green)
        }
        else {
            $summarySheet.Cells["B$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Red)
        }
        
        # Apply color based on score
        if ($pillars[$i].Score -ge 90) {
            $summarySheet.Cells["C$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Green)
        }
        elseif ($pillars[$i].Score -ge 80) {
            $summarySheet.Cells["C$row"].Style.Font.Color.SetColor([System.Drawing.Color]::DarkGreen)
        }
        elseif ($pillars[$i].Score -ge 70) {
            $summarySheet.Cells["C$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Orange)
        }
        elseif ($pillars[$i].Score -ge 60) {
            $summarySheet.Cells["C$row"].Style.Font.Color.SetColor([System.Drawing.Color]::DarkOrange)
        }
        else {
            $summarySheet.Cells["C$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Red)
        }
    }
    
    # Results worksheet
    $resultsSheet = $excelPackage.Workbook.Worksheets.Add("Detailed Results")
    
    # Results table headers
    $resultsSheet.Cells["A1"].Value = "Check Name"
    $resultsSheet.Cells["B1"].Value = "Status"
    $resultsSheet.Cells["C1"].Value = "Category"
    $resultsSheet.Cells["D1"].Value = "Severity"
    $resultsSheet.Cells["E1"].Value = "Recommendation"
    
    # Format headers
    $resultsSheet.Cells["A1:E1"].Style.Font.Bold = $true
    $resultsSheet.Cells["A1:E1"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $resultsSheet.Cells["A1:E1"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
    
    # Prepare check results
    $checks = @(
        @{
            Name = "Admin MFA Required"
            Status = if ($Results.Checks.AdminMFA.AdminMFARequired) { "PASS" } else { "FAIL" }
            Category = "Identity Protection"
            Severity = "Critical"
            Recommendation = $Results.Checks.AdminMFA.Recommendation
        },
        @{
            Name = "User MFA Required"
            Status = if ($Results.Checks.UserMFA.BroadUserMFARequired) { "PASS" } else { "FAIL" }
            Category = "Identity Protection"
            Severity = "High"
            Recommendation = $Results.Checks.UserMFA.Recommendation
        },
        @{
            Name = "Device Compliance Required"
            Status = if ($Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) { "PASS" } else { "FAIL" }
            Category = "Device Trust"
            Severity = "High"
            Recommendation = $Results.Checks.DeviceCompliance.Recommendation
        },
        @{
            Name = "Token Session Binding"
            Status = if ($Results.Checks.TokenBinding.TokenSessionBindingConfigured) { "PASS" } else { "FAIL" }
            Category = "Session Security"
            Severity = "Medium"
            Recommendation = $Results.Checks.TokenBinding.Recommendation
        },
        @{
            Name = "Sign-In Risk Policies"
            Status = if ($Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured) { "PASS" } else { "FAIL" }
            Category = "Risk-Based Access"
            Severity = "High"
            Recommendation = $Results.Checks.RiskPolicies.Recommendation
        },
        @{
            Name = "User Risk Policies"
            Status = if ($Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) { "PASS" } else { "FAIL" }
            Category = "Risk-Based Access"
            Severity = "High"
            Recommendation = $Results.Checks.RiskPolicies.Recommendation
        },
        @{
            Name = "Mobile Application Management"
            Status = if ($Results.Checks.MAMPolicies.MAMPoliciesConfigured) { "PASS" } else { "FAIL" }
            Category = "Data Protection"
            Severity = "Medium"
            Recommendation = $Results.Checks.MAMPolicies.Recommendation
        },
        @{
            Name = "MDCA Integration"
            Status = if ($Results.Checks.ZeroTrust.MDCAIntegrated) { "PASS" } else { "FAIL" }
            Category = "Network Security"
            Severity = "High"
            Recommendation = $Results.Checks.ZeroTrust.Recommendation
        },
        @{
            Name = "Global Secure Access"
            Status = if ($Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) { "PASS" } else { "FAIL" }
            Category = "Network Security"
            Severity = "High"
            Recommendation = $Results.Checks.ZeroTrust.Recommendation
        }
    )
    
    # Add check data
    for ($i = 0; $i -lt $checks.Count; $i++) {
        $row = 2 + $i
        $resultsSheet.Cells["A$row"].Value = $checks[$i].Name
        $resultsSheet.Cells["B$row"].Value = $checks[$i].Status
        $resultsSheet.Cells["C$row"].Value = $checks[$i].Category
        $resultsSheet.Cells["D$row"].Value = $checks[$i].Severity
        $resultsSheet.Cells["E$row"].Value = $checks[$i].Recommendation
        
        # Apply color based on status
        if ($checks[$i].Status -eq "PASS") {
            $resultsSheet.Cells["B$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Green)
        }
        else {
            $resultsSheet.Cells["B$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Red)
        }
        
        # Apply color based on severity
        $severityColor = switch ($checks[$i].Severity) {
            "Critical" { [System.Drawing.Color]::DarkRed }
            "High" { [System.Drawing.Color]::Red }
            "Medium" { [System.Drawing.Color]::Orange }
            "Low" { [System.Drawing.Color]::Green }
            default { [System.Drawing.Color]::Black }
        }
        $resultsSheet.Cells["D$row"].Style.Font.Color.SetColor($severityColor)
    }
    
    # Add recommendations worksheet if requested
    if ($IncludeRecommendations) {
        $recsSheet = $excelPackage.Workbook.Worksheets.Add("Recommendations")
        
        # Recommendations table headers
        $recsSheet.Cells["A1"].Value = "Priority"
        $recsSheet.Cells["B1"].Value = "Category"
        $recsSheet.Cells["C1"].Value = "Title"
        $recsSheet.Cells["D1"].Value = "Description"
        $recsSheet.Cells["E1"].Value = "Remediation"
        
        # Format headers
        $recsSheet.Cells["A1:E1"].Style.Font.Bold = $true
        $recsSheet.Cells["A1:E1"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $recsSheet.Cells["A1:E1"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
        
        # Prepare recommendations
        $recommendations = @()
        
        # Add high priority recommendations first
        if (-not $Results.Checks.AdminMFA.AdminMFARequired) {
            $recommendations += @{
                Priority = "Critical"
                Category = "Identity Protection"
                Title = "Admin MFA Enforcement"
                Description = $Results.Checks.AdminMFA.Recommendation
                Remediation = "New-CABestPracticePolicy -PolicyType AdminMFA"
            }
        }
        
        if (-not $Results.Checks.UserMFA.BroadUserMFARequired) {
            $recommendations += @{
                Priority = "High"
                Category = "Identity Protection"
                Title = "User MFA Enforcement"
                Description = $Results.Checks.UserMFA.Recommendation
                Remediation = "New-CABestPracticePolicy -PolicyType UserMFA"
            }
        }
        
        if (-not $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) {
            $recommendations += @{
                Priority = "High"
                Category = "Device Trust"
                Title = "Device Compliance"
                Description = $Results.Checks.DeviceCompliance.Recommendation
                Remediation = "New-CABestPracticePolicy -PolicyType DeviceCompliance"
            }
        }
        
        if (-not $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured) {
            $recommendations += @{
                Priority = "High"
                Category = "Risk-Based Access"
                Title = "Sign-In Risk Policies"
                Description = "Configure CA policy based on sign-in risk to protect against suspicious sign-in attempts."
                Remediation = "New-CABestPracticePolicy -PolicyType SignInRisk"
            }
        }
        
        if (-not $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) {
            $recommendations += @{
                Priority = "High"
                Category = "Risk-Based Access"
                Title = "User Risk Policies"
                Description = "Configure CA policy based on user risk to protect compromised accounts."
                Remediation = "New-CABestPracticePolicy -PolicyType UserRisk"
            }
        }
        
        if (-not $Results.Checks.ZeroTrust.MDCAIntegrated) {
            $recommendations += @{
                Priority = "High"
                Category = "Network Security"
                Title = "MDCA Integration"
                Description = "Configure Microsoft Defender for Cloud Apps integration with Conditional Access."
                Remediation = "New-CABestPracticePolicy -PolicyType CloudAppSecurity"
            }
        }
        
        if (-not $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) {
            $recommendations += @{
                Priority = "High"
                Category = "Network Security"
                Title = "Global Secure Access"
                Description = "Set up Global Secure Access policies for Zero Trust Network Access."
                Remediation = "New-CABestPracticePolicy -PolicyType GlobalSecureAccess"
            }
        }
        
        # Add medium priority recommendations
        if (-not $Results.Checks.TokenBinding.TokenSessionBindingConfigured) {
            $recommendations += @{
                Priority = "Medium"
                Category = "Session Security"
                Title = "Token Session Binding"
                Description = $Results.Checks.TokenBinding.Recommendation
                Remediation = "New-CABestPracticePolicy -PolicyType TokenBinding"
            }
        }
        
        if (-not $Results.Checks.MAMPolicies.MAMPoliciesConfigured) {
            $recommendations += @{
                Priority = "Medium"
                Category = "Data Protection"
                Title = "Mobile Application Management"
                Description = $Results.Checks.MAMPolicies.Recommendation
                Remediation = "New-CABestPracticePolicy -PolicyType MAMPolicy"
            }
        }
        
        # Add recommendation data
        for ($i = 0; $i -lt $recommendations.Count; $i++) {
            $row = 2 + $i
            $recsSheet.Cells["A$row"].Value = $recommendations[$i].Priority
            $recsSheet.Cells["B$row"].Value = $recommendations[$i].Category
            $recsSheet.Cells["C$row"].Value = $recommendations[$i].Title
            $recsSheet.Cells["D$row"].Value = $recommendations[$i].Description
            $recsSheet.Cells["E$row"].Value = $recommendations[$i].Remediation
            
            # Apply color based on priority
            $priorityColor = switch ($recommendations[$i].Priority) {
                "Critical" { [System.Drawing.Color]::DarkRed }
                "High" { [System.Drawing.Color]::Red }
                "Medium" { [System.Drawing.Color]::Orange }
                "Low" { [System.Drawing.Color]::Green }
                default { [System.Drawing.Color]::Black }
            }
            $recsSheet.Cells["A$row"].Style.Font.Color.SetColor($priorityColor)
        }
    }
    
    # Policies worksheet
    $policiesSheet = $excelPackage.Workbook.Worksheets.Add("Policies")
    
    # Policies table headers
    $policiesSheet.Cells["A1"].Value = "Name"
    $policiesSheet.Cells["B1"].Value = "State"
    $policiesSheet.Cells["C1"].Value = "Type"
    $policiesSheet.Cells["D1"].Value = "Created"
    $policiesSheet.Cells["E1"].Value = "Modified"
    
    # Format headers
    $policiesSheet.Cells["A1:E1"].Style.Font.Bold = $true
    $policiesSheet.Cells["A1:E1"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $policiesSheet.Cells["A1:E1"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
    
    # Get all policies
    $policies = Get-MgIdentityConditionalAccessPolicy
    
    # Add policy data
    for ($i = 0; $i -lt $policies.Count; $i++) {
        $row = 2 + $i
        $policy = $policies[$i]
        
        # Determine policy type
        $policyType = "Other"
        
        if ($policy.Conditions.Users.IncludeRoles -and $policy.GrantControls.BuiltInControls -contains "mfa") {
            $policyType = "Admin MFA"
        }
        elseif ($policy.GrantControls.BuiltInControls -contains "mfa" -and $policy.Conditions.Applications.IncludeApplications -contains "All") {
            $policyType = "Global MFA"
        }
        elseif ($policy.GrantControls.BuiltInControls -contains "mfa" -and $policy.Conditions.Applications.IncludeApplications -contains "Office365") {
            $policyType = "Office 365 MFA"
        }
        elseif ($policy.GrantControls.BuiltInControls -contains "compliantDevice" -or $policy.GrantControls.BuiltInControls -contains "domainJoinedDevice") {
            $policyType = "Device Compliance"
        }
        elseif ($policy.Conditions.SignInRisk -or $policy.Conditions.UserRiskLevels) {
            $policyType = "Risk-Based"
        }
        elseif ($policy.GrantControls.BuiltInControls -contains "approvedApplication") {
            $policyType = "App Control"
        }
        elseif ($policy.SessionControls) {
            $policyType = "Session Control"
        }
        
        $policiesSheet.Cells["A$row"].Value = $policy.DisplayName
        $policiesSheet.Cells["B$row"].Value = $policy.State
        $policiesSheet.Cells["C$row"].Value = $policyType
        $policiesSheet.Cells["D$row"].Value = $policy.CreatedDateTime
        $policiesSheet.Cells["E$row"].Value = $policy.ModifiedDateTime
        
        # Apply color based on state
        if ($policy.State -eq "enabled") {
            $policiesSheet.Cells["B$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Green)
        }
        else {
            $policiesSheet.Cells["B$row"].Style.Font.Color.SetColor([System.Drawing.Color]::Red)
        }
    }
    
    # Auto-fit columns
    $summarySheet.Cells.AutoFitColumns()
    $resultsSheet.Cells.AutoFitColumns()
    if ($IncludeRecommendations) {
        $recsSheet.Cells.AutoFitColumns()
    }
    $policiesSheet.Cells.AutoFitColumns()
    
    # Save the Excel package
    $excelPackage.SaveAs((New-Object System.IO.FileInfo($Path)))
    $excelPackage.Dispose()
}

function ConvertTo-ComplianceDashboardHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Results,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$BenchmarkResults,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$HistoricalResults,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRemediation,
        
        [Parameter(Mandatory = $false)]
        [string]$CompanyName,
        
        [Parameter(Mandatory = $false)]
        [string]$BrandingLogo
    )
    
    # Define score color function
    $getScoreColor = {
        param($score)
        if ($score -ge 90) { return "#107C10" } # Green
        elseif ($score -ge 75) { return "#FF8C00" } # Orange
        elseif ($score -ge 60) { return "#FFC83D" } # Yellow
        else { return "#E81123" } # Red
    }
    
    # Set company name if not provided
    if (-not $CompanyName) {
        $CompanyName = $Results.TenantName
    }
    
    # Determine score level
    $scoreLevel = switch ($Results.ComplianceScore) {
        {$_ -ge 90} { "Excellent" }
        {$_ -ge 80} { "Good" }
        {$_ -ge 70} { "Fair" }
        {$_ -ge 60} { "Poor" }
        default { "Critical" }
    }
    
    $scoreColor = & $getScoreColor $Results.ComplianceScore
    
    # Prepare recommendations
    $recommendations = @()
    
    if (-not $Results.Checks.AdminMFA.AdminMFARequired) {
        $recommendations += [PSCustomObject]@{
            Priority = "Critical"
            Category = "Identity Protection"
            Title = "Admin MFA Enforcement"
            Description = $Results.Checks.AdminMFA.Recommendation
        }
    }
    
    if (-not $Results.Checks.UserMFA.BroadUserMFARequired) {
        $recommendations += [PSCustomObject]@{
            Priority = "High"
            Category = "Identity Protection"
            Title = "User MFA Enforcement"
            Description = $Results.Checks.UserMFA.Recommendation
        }
    }
    
    if (-not $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) {
        $recommendations += [PSCustomObject]@{
            Priority = "High"
            Category = "Device Trust"
            Title = "Device Compliance"
            Description = $Results.Checks.DeviceCompliance.Recommendation
        }
    }
    
    if (-not $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -or
        -not $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "High"
            Category = "Risk-Based Access"
            Title = "Risk-Based Access"
            Description = $Results.Checks.RiskPolicies.Recommendation
        }
    }
    
    if (-not $Results.Checks.TokenBinding.TokenSessionBindingConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "Medium"
            Category = "Session Security"
            Title = "Token Session Binding"
            Description = $Results.Checks.TokenBinding.Recommendation
        }
    }
    
    if (-not $Results.Checks.MAMPolicies.MAMPoliciesConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "Medium"
            Category = "Data Protection"
            Title = "Mobile Application Management"
            Description = $Results.Checks.MAMPolicies.Recommendation
        }
    }
    
    if (-not $Results.Checks.ZeroTrust.MDCAIntegrated -or
        -not $Results.Checks.ZeroTrust.GlobalSecureAccessConfigured) {
        $recommendations += [PSCustomObject]@{
            Priority = "Medium"
            Category = "Network Security"
            Title = "Zero Trust Network Access"
            Description = $Results.Checks.ZeroTrust.Recommendation
        }
    }
    
    # Start building HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conditional Access Compliance Dashboard - $CompanyName</title>
    <style>
        :root {
            --primary-color: #0078D4;
            --secondary-color: #50E6FF;
            --success-color: #107C10;
            --warning-color: #FF8C00;
            --danger-color: #E81123;
            --light-color: #F3F2F1;
            --dark-color: #201F1E;
            --font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: var(--font-family);
            line-height: 1.6;
            color: var(--dark-color);
            background-color: #F9F9F9;
            margin: 0;
            padding: 0;
        }
        
        .container {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
        }
        
        h1, h2, h3, h4, h5, h6 {
            font-weight: 600;
            line-height: 1.3;
            margin-bottom: 15px;
            color: var(--primary-color);
        }
        
        h1 {
            font-size: 2.5rem;
            color: white;
            margin-bottom: 5px;
        }
        
        h2 {
            font-size: 1.8rem;
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 10px;
            margin-top: 40px;
        }
        
        h3 {
            font-size: 1.4rem;
            margin-top: 30px;
        }
        
        p {
            margin-bottom: 15px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .score-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .score-circle {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background-color: #f2f2f2;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            margin-bottom: 20px;
            position: relative;
        }
        
        .score-circle::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: conic-gradient($scoreColor 0% calc($($Results.ComplianceScore) * 1%), #f2f2f2 calc($($Results.ComplianceScore) * 1%) 100%);
            mask: radial-gradient(transparent 65%, black 66%);
            -webkit-mask: radial-gradient(transparent 65%, black 66%);
        }
        
        .score-circle-inner {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background-color: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            z-index: 1;
        }
        
        .score-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: $scoreColor;
        }
        
        .score-label {
            font-size: 1rem;
            color: #666;
        }
        
        .score-title {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .score-summary {
            font-size: 1rem;
            color: #666;
        }
        
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background-color: var(--primary-color);
            color: white;
            padding: 15px 20px;
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        .card-body {
            padding: 20px;
        }
        
        .security-checks {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .check-item {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 15px;
            display: flex;
            flex-direction: column;
        }
        
        .check-title {
            font-weight: bold;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .check-status {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .status-pass {
            background-color: #ecf7ec;
            color: var(--success-color);
        }
        
        .status-fail {
            background-color: #fdeaea;
            color: var(--danger-color);
        }
        
        .check-description {
            margin-bottom: 10px;
            color: #666;
        }
        
        .recommendations {
            margin-top: 40px;
        }
        
        .recommendation-item {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }
        
        .priority-critical {
            border-left-color: var(--danger-color);
        }
        
        .priority-high {
            border-left-color: var(--warning-color);
        }
        
        .priority-medium {
            border-left-color: #FFC83D;
        }
        
        .recommendation-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .recommendation-title {
            font-weight: bold;
        }
        
        .recommendation-priority {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        
        .priority-badge-critical {
            background-color: #fdeaea;
            color: var(--danger-color);
        }
        
        .priority-badge-high {
            background-color: #fff5e6;
            color: var(--warning-color);
        }
        
        .priority-badge-medium {
            background-color: #fffaeb;
            color: #9C6500;
        }
        
        .recommendation-category {
            font-size: 0.9rem;
            color: #666;
            margin-bottom: 10px;
        }
        
        .recommendation-description {
            color: #333;
        }
        
        .footer {
            background-color: var(--light-color);
            padding: 20px;
            text-align: center;
            margin-top: 50px;
            color: #666;
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid transparent;
            border-bottom: none;
            margin-bottom: -1px;
            background-color: transparent;
            font-weight: 600;
        }
        
        .tab.active {
            border-color: #ddd;
            border-radius: 5px 5px 0 0;
            background-color: white;
            color: var(--primary-color);
        }
        
        .tab-content {
            display: none;
            padding: 20px 0;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .security-checks {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Conditional Access Compliance Dashboard</h1>
            <p>Tenant: $($Results.TenantName) | Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
    </header>
    
    <div class="container">
        <div class="dashboard">
            <div class="score-card">
                <div class="score-circle">
                    <div class="score-circle-inner">
                        <div class="score-value">$($Results.ComplianceScore)%</div>
                        <div class="score-label">$scoreLevel</div>
                    </div>
                </div>
                <div class="score-title">Overall Compliance</div>
                <div class="score-summary">Based on Zero Trust principles</div>
            </div>
"@

    # Add score cards for security pillars
    $securityPillars = @(
        @{
            Name = "Identity Protection"
            Score = [math]::Round(([int]$Results.Checks.AdminMFA.AdminMFARequired + [int]$Results.Checks.UserMFA.BroadUserMFARequired) / 2 * 100)
        },
        @{
            Name = "Device Trust"
            Score = [math]::Round([int]$Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired * 100)
        },
        @{
            Name = "Risk-Based Access"
            Score = [math]::Round(([int]$Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured + [int]$Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) / 2 * 100)
        },
        @{
            Name = "Session Security"
            Score = [math]::Round([int]$Results.Checks.TokenBinding.TokenSessionBindingConfigured * 100)
        }
    )

    foreach ($pillar in $securityPillars) {
        $pillarColor = & $getScoreColor $pillar.Score
        
        $html += @"
            <div class="score-card">
                <div class="score-circle">
                    <div class="score-circle-inner">
                        <div class="score-value" style="color: $pillarColor;">$($pillar.Score)%</div>
                    </div>
                </div>
                <div class="score-title">$($pillar.Name)</div>
            </div>
"@
    }

    $html += @"
        </div>
        
        <div class="card">
            <div class="card-header">Security Checks</div>
            <div class="card-body">
                <div class="security-checks">
"@

    # Add security checks
    $securityChecks = @(
        @{
            Title = "Admin MFA Required"
            Status = $Results.Checks.AdminMFA.AdminMFARequired
            Description = "Multi-factor authentication for administrative roles"
            Recommendation = $Results.Checks.AdminMFA.Recommendation
        },
        @{
            Title = "User MFA Required"
            Status = $Results.Checks.UserMFA.BroadUserMFARequired
            Description = "Multi-factor authentication for all users"
            Recommendation = $Results.Checks.UserMFA.Recommendation
        },
        @{
            Title = "Device Compliance Required"
            Status = $Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired
            Description = "Device compliance verification for resource access"
            Recommendation = $Results.Checks.DeviceCompliance.Recommendation
        },
        @{
            Title = "Sign-in Risk Policy"
            Status = $Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured
            Description = "Policies that respond to suspicious sign-in attempts"
            Recommendation = "Configure CA policy based on sign-in risk"
        },
        @{
            Title = "User Risk Policy"
            Status = $Results.Checks.RiskPolicies.UserRiskPoliciesConfigured
            Description = "Policies that respond to compromised user accounts"
            Recommendation = "Configure CA policy based on user risk"
        },
        @{
            Title = "Token Session Binding"
            Status = $Results.Checks.TokenBinding.TokenSessionBindingConfigured
            Description = "Session controls for authentication token security"
            Recommendation = $Results.Checks.TokenBinding.Recommendation
        }
    )

    foreach ($check in $securityChecks) {
        $statusClass = if ($check.Status) { "status-pass" } else { "status-fail" }
        $statusText = if ($check.Status) { "PASS" } else { "FAIL" }
        
        $html += @"
                    <div class="check-item">
                        <div class="check-title">
                            $($check.Title)
                            <span class="check-status $statusClass">$statusText</span>
                        </div>
                        <div class="check-description">$($check.Description)</div>
                        $(if (-not $check.Status) { "<div class='check-recommendation'>$($check.Recommendation)</div>" })
                    </div>
"@
    }

    $html += @"
                </div>
            </div>
        </div>
"@

    # Add recommendations if they exist
    if ($recommendations.Count -gt 0) {
        $html += @"
        <div class="recommendations">
            <h2>Security Recommendations</h2>
"@

        foreach ($recommendation in $recommendations) {
            $priorityClass = "priority-$($recommendation.Priority.ToLower())"
            $priorityBadgeClass = "priority-badge-$($recommendation.Priority.ToLower())"
            
            $html += @"
            <div class="recommendation-item $priorityClass">
                <div class="recommendation-header">
                    <div class="recommendation-title">$($recommendation.Title)</div>
                    <div class="recommendation-priority $priorityBadgeClass">$($recommendation.Priority)</div>
                </div>
                <div class="recommendation-category">$($recommendation.Category)</div>
                <div class="recommendation-description">$($recommendation.Description)</div>
            </div>
"@
        }

        $html += @"
        </div>
"@
    }

    # Add benchmarks if provided
    if ($BenchmarkResults -and $BenchmarkResults.Count -gt 0) {
        $html += @"
        <h2>Security Benchmark Results</h2>
        
        <div class="tabs">
"@

        for ($i = 0; $i -lt $BenchmarkResults.Count; $i++) {
            $activeClass = if ($i -eq 0) { "active" } else { "" }
            $html += @"
            <div class="tab $activeClass" data-tab="tab-$i">$($BenchmarkResults[$i].BenchmarkName)</div>
"@
        }

        $html += @"
        </div>
"@

        for ($i = 0; $i -lt $BenchmarkResults.Count; $i++) {
            $benchmark = $BenchmarkResults[$i]
            $activeClass = if ($i -eq 0) { "active" } else { "" }
            
            $html += @"
        <div class="tab-content $activeClass" id="tab-$i">
            <div class="card">
                <div class="card-header">$($benchmark.BenchmarkName) Compliance</div>
                <div class="card-body">
                    <p><strong>Overall Score:</strong> $($benchmark.OverallScore)%</p>
                    <p><strong>Compliant Controls:</strong> $($benchmark.CompliantControls) of $($benchmark.TotalControls)</p>
                </div>
            </div>
        </div>
"@
        }
    }

    $html += @"
        <div class="footer">
            <p>Conditional Access Analyzer Report</p>
            <p>Generated on $(Get-Date -Format "yyyy-MM-dd") using Conditional Access Analyzer PowerShell Module</p>
        </div>
    </div>
    
    <script>
        // Tab switching
        document.addEventListener('DOMContentLoaded', function() {
            const tabs = document.querySelectorAll('.tab');
            
            tabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    // Remove active class from all tabs
                    tabs.forEach(t => t.classList.remove('active'));
                    // Add active class to clicked tab
                    this.classList.add('active');
                    
                    // Hide all tab content
                    const tabContents = document.querySelectorAll('.tab-content');
                    tabContents.forEach(content => content.classList.remove('active'));
                    
                    // Show corresponding tab content
                    const tabId = this.getAttribute('data-tab');
                    document.getElementById(tabId).classList.add('active');
                });
            });
        });
    </script>
</body>
</html>
"@

    return $html
}
