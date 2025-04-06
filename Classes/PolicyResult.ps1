class CAPolicy {
    [string]$Id
    [string]$DisplayName
    [string]$State
    [datetime]$CreatedDateTime
    [datetime]$ModifiedDateTime
    [hashtable]$Conditions
    [hashtable]$GrantControls
    [hashtable]$SessionControls
    
    CAPolicy([PSCustomObject]$PolicyObject) {
        $this.Id = $PolicyObject.Id
        $this.DisplayName = $PolicyObject.DisplayName
        $this.State = $PolicyObject.State
        $this.CreatedDateTime = $PolicyObject.CreatedDateTime
        $this.ModifiedDateTime = $PolicyObject.ModifiedDateTime
        $this.Conditions = @{}
        $this.GrantControls = @{}
        $this.SessionControls = @{}
        
        # Map conditions
        if ($PolicyObject.Conditions) {
            # Users
            if ($PolicyObject.Conditions.Users) {
                $this.Conditions.Users = @{
                    IncludeUsers = $PolicyObject.Conditions.Users.IncludeUsers
                    ExcludeUsers = $PolicyObject.Conditions.Users.ExcludeUsers
                    IncludeGroups = $PolicyObject.Conditions.Users.IncludeGroups
                    ExcludeGroups = $PolicyObject.Conditions.Users.ExcludeGroups
                    IncludeRoles = $PolicyObject.Conditions.Users.IncludeRoles
                    ExcludeRoles = $PolicyObject.Conditions.Users.ExcludeRoles
                }
            }
            
            # Applications
            if ($PolicyObject.Conditions.Applications) {
                $this.Conditions.Applications = @{
                    IncludeApplications = $PolicyObject.Conditions.Applications.IncludeApplications
                    ExcludeApplications = $PolicyObject.Conditions.Applications.ExcludeApplications
                    IncludeUserActions = $PolicyObject.Conditions.Applications.IncludeUserActions
                }
            }
            
            # Platforms
            if ($PolicyObject.Conditions.Platforms) {
                $this.Conditions.Platforms = @{
                    IncludePlatforms = $PolicyObject.Conditions.Platforms.IncludePlatforms
                    ExcludePlatforms = $PolicyObject.Conditions.Platforms.ExcludePlatforms
                }
            }
            
            # Locations
            if ($PolicyObject.Conditions.Locations) {
                $this.Conditions.Locations = @{
                    IncludeLocations = $PolicyObject.Conditions.Locations.IncludeLocations
                    ExcludeLocations = $PolicyObject.Conditions.Locations.ExcludeLocations
                }
            }
            
            # Risk levels
            if ($PolicyObject.Conditions.UserRiskLevels) {
                $this.Conditions.UserRiskLevels = $PolicyObject.Conditions.UserRiskLevels
            }
            if ($PolicyObject.Conditions.SignInRisk) {
                $this.Conditions.SignInRiskLevels = $PolicyObject.Conditions.SignInRisk.RiskLevels
            }
        }
        
        # Grant controls
        if ($PolicyObject.GrantControls) {
            $this.GrantControls = @{
                Operator = $PolicyObject.GrantControls.Operator
                BuiltInControls = $PolicyObject.GrantControls.BuiltInControls
                CustomAuthenticationFactors = $PolicyObject.GrantControls.CustomAuthenticationFactors
                TermsOfUse = $PolicyObject.GrantControls.TermsOfUse
            }
        }
        
        # Session controls
        if ($PolicyObject.SessionControls) {
            $this.SessionControls = @{}
            
            if ($PolicyObject.SessionControls.ApplicationEnforcedRestrictions) {
                $this.SessionControls.ApplicationEnforcedRestrictions = @{
                    IsEnabled = $PolicyObject.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                }
            }
            
            if ($PolicyObject.SessionControls.CloudAppSecurity) {
                $this.SessionControls.CloudAppSecurity = @{
                    IsEnabled = $PolicyObject.SessionControls.CloudAppSecurity.IsEnabled
                    CloudAppSecurityType = $PolicyObject.SessionControls.CloudAppSecurity.CloudAppSecurityType
                }
            }
            
            if ($PolicyObject.SessionControls.SignInFrequency) {
                $this.SessionControls.SignInFrequency = @{
                    IsEnabled = $PolicyObject.SessionControls.SignInFrequency.IsEnabled
                    Type = $PolicyObject.SessionControls.SignInFrequency.Type
                    Value = $PolicyObject.SessionControls.SignInFrequency.Value
                }
            }
            
            if ($PolicyObject.SessionControls.PersistentBrowser) {
                $this.SessionControls.PersistentBrowser = @{
                    IsEnabled = $PolicyObject.SessionControls.PersistentBrowser.IsEnabled
                    Mode = $PolicyObject.SessionControls.PersistentBrowser.Mode
                }
            }
        }
    }
    
    # Method to check if policy requires MFA
    [bool] RequiresMFA() {
        return $this.GrantControls.BuiltInControls -contains "mfa"
    }
    
    # Method to check if policy targets admins
    [bool] TargetsAdminRoles([string[]]$AdminRoleIds) {
        if (-not $this.Conditions.Users) {
            return $false
        }
        
        if ($this.Conditions.Users.IncludeRoles) {
            foreach ($role in $this.Conditions.Users.IncludeRoles) {
                if ($AdminRoleIds -contains $role) {
                    return $true
                }
            }
        }
        
        if ($this.Conditions.Users.IncludeUsers -contains "All") {
            # Check if admin roles are explicitly excluded
            if ($this.Conditions.Users.ExcludeRoles) {
                foreach ($role in $AdminRoleIds) {
                    if ($this.Conditions.Users.ExcludeRoles -contains $role) {
                        return $false
                    }
                }
            }
            return $true
        }
        
        return $false
    }
    
    # Method to check if policy applies to all users
    [bool] AppliesToAllUsers() {
        if (-not $this.Conditions.Users) {
            return $false
        }
        
        return $this.Conditions.Users.IncludeUsers -contains "All"
    }
    
    # Method to check if policy applies broadly to applications
    [bool] HasBroadAppCoverage() {
        if (-not $this.Conditions.Applications) {
            return $false
        }
        
        return $this.Conditions.Applications.IncludeApplications -contains "All" -or 
               $this.Conditions.Applications.IncludeApplications -contains "Office365"
    }
    
    # Method to check if policy requires compliant devices
    [bool] RequiresCompliantDevice() {
        return $this.GrantControls.BuiltInControls -contains "compliantDevice"
    }
    
    # Method to check if policy requires hybrid Azure AD joined devices
    [bool] RequiresHybridJoin() {
        return $this.GrantControls.BuiltInControls -contains "domainJoinedDevice"
    }
    
    # Method to check if policy uses sign-in risk
    [bool] UsesSignInRisk() {
        return $null -ne $this.Conditions.SignInRiskLevels -and $this.Conditions.SignInRiskLevels.Count -gt 0
    }
    
    # Method to check if policy uses user risk
    [bool] UsesUserRisk() {
        return $null -ne $this.Conditions.UserRiskLevels -and $this.Conditions.UserRiskLevels.Count -gt 0
    }
    
    # Method to check if policy has Cloud App Security controls
    [bool] HasCloudAppSecurity() {
        return $null -ne $this.SessionControls.CloudAppSecurity -and 
               $this.SessionControls.CloudAppSecurity.IsEnabled
    }
    
    # Method to serialize to JSON
    [string] ToJson() {
        return $this | ConvertTo-Json -Depth 10
    }
}

class CAComplianceResult {
    [string]$CheckName
    [bool]$IsCompliant
    [string]$ComplianceStatus
    [string]$Recommendation
    [PSCustomObject[]]$Details
    [int]$Severity # 1=Critical, 2=High, 3=Medium, 4=Low
    [string]$Category # MFA, Device, Risk, etc.
    [string]$BestPracticeReference
    [string]$RemediationScript
    
    CAComplianceResult([string]$CheckName, [bool]$IsCompliant, [string]$Recommendation) {
        $this.CheckName = $CheckName
        $this.IsCompliant = $IsCompliant
        $this.ComplianceStatus = $IsCompliant ? "PASS" : "FAIL"
        $this.Recommendation = $Recommendation
        $this.Severity = 2 # Default to High
        $this.Category = "General"
    }
    
    # Method to add details to the result
    [void] AddDetails([PSCustomObject[]]$Details) {
        $this.Details = $Details
    }
    
    # Method to set severity
    [void] SetSeverity([int]$Severity) {
        $this.Severity = $Severity
    }
    
    # Method to set category
    [void] SetCategory([string]$Category) {
        $this.Category = $Category
    }
    
    # Method to set best practice reference
    [void] SetBestPracticeReference([string]$Reference) {
        $this.BestPracticeReference = $Reference
    }
    
    # Method to set remediation script
    [void] SetRemediationScript([string]$Script) {
        $this.RemediationScript = $Script
    }
    
    # Method to get color based on compliance status
    [string] GetStatusColor() {
        return $this.IsCompliant ? "Green" : 
               ($this.Severity -eq 1 ? "Red" : 
               ($this.Severity -eq 2 ? "DarkRed" : 
               ($this.Severity -eq 3 ? "Yellow" : "Gray")))
    }
    
    # Method to generate HTML representation
    [string] ToHtml() {
        $color = $this.IsCompliant ? "green" : 
                 ($this.Severity -eq 1 ? "red" : 
                 ($this.Severity -eq 2 ? "orangered" : 
                 ($this.Severity -eq 3 ? "orange" : "gray")))
        
        $severityText = $this.Severity -eq 1 ? "Critical" : 
                        ($this.Severity -eq 2 ? "High" : 
                        ($this.Severity -eq 3 ? "Medium" : "Low"))
                        
        $html = @"
<div class="compliance-result">
    <h3>$($this.CheckName) <span class="status-$($this.ComplianceStatus.ToLower())" style="color: $color;">[$($this.ComplianceStatus)]</span></h3>
    <p><strong>Severity:</strong> $severityText</p>
    <p><strong>Category:</strong> $($this.Category)</p>
    <p><strong>Recommendation:</strong> $($this.Recommendation)</p>
"@

        if ($this.BestPracticeReference) {
            $html += @"
    <p><strong>Best Practice Reference:</strong> $($this.BestPracticeReference)</p>
"@
        }

        if ($this.Details -and $this.Details.Count -gt 0) {
            $html += @"
    <div class="details">
        <h4>Details</h4>
        <table border="1">
            <tr>
"@
            # Get all property names
            $properties = $this.Details[0].PSObject.Properties.Name
            
            # Add table headers
            foreach ($prop in $properties) {
                $html += "<th>$prop</th>"
            }
            
            $html += "</tr>"
            
            # Add table rows
            foreach ($detail in $this.Details) {
                $html += "<tr>"
                foreach ($prop in $properties) {
                    $value = $detail.$prop
                    if ($value -is [bool]) {
                        $displayValue = $value ? "Yes" : "No"
                        $color = $value ? "green" : "red"
                        $html += "<td style='color: $color;'>$displayValue</td>"
                    }
                    else {
                        $html += "<td>$value</td>"
                    }
                }
                $html += "</tr>"
            }
            
            $html += @"
        </table>
    </div>
"@
        }
        
        $html += "</div>"
        return $html
    }
}

class CAComplianceReport {
    [string]$TenantId
    [string]$TenantName
    [datetime]$GeneratedDate
    [CAComplianceResult[]]$Results
    [int]$ComplianceScore
    
    CAComplianceReport([string]$TenantId, [string]$TenantName) {
        $this.TenantId = $TenantId
        $this.TenantName = $TenantName
        $this.GeneratedDate = Get-Date
        $this.Results = @()
    }
    
    # Method to add a compliance result
    [void] AddResult([CAComplianceResult]$Result) {
        $this.Results += $Result
    }
    
    # Method to calculate compliance score
    [void] CalculateScore() {
        $totalChecks = $this.Results.Count
        if ($totalChecks -eq 0) {
            $this.ComplianceScore = 0
            return
        }
        
        $passedChecks = ($this.Results | Where-Object { $_.IsCompliant }).Count
        $this.ComplianceScore = [math]::Round(($passedChecks / $totalChecks) * 100)
    }
    
    # Method to get score level
    [string] GetScoreLevel() {
        if ($this.ComplianceScore -ge 90) { return "Excellent" }
        elseif ($this.ComplianceScore -ge 80) { return "Good" }
        elseif ($this.ComplianceScore -ge 70) { return "Fair" }
        elseif ($this.ComplianceScore -ge 60) { return "Poor" }
        else { return "Critical" }
    }
    
    # Method to get score color
    [string] GetScoreColor() {
        if ($this.ComplianceScore -ge 90) { return "Green" }
        elseif ($this.ComplianceScore -ge 80) { return "YellowGreen" }
        elseif ($this.ComplianceScore -ge 70) { return "Gold" }
        elseif ($this.ComplianceScore -ge 60) { return "Orange" }
        else { return "Red" }
    }
    
    # Method to generate HTML report
    [string] ToHtml() {
        $scoreColor = $this.GetScoreColor()
        $scoreLevel = $this.GetScoreLevel()
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Conditional Access Compliance Report - $($this.TenantName)</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #f9f9f9;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #0078D4;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }
        h1, h2, h3, h4 {
            margin: 0;
            font-weight: 600;
        }
        .score-card {
            background-color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
        }
        .score-circle {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background-color: $scoreColor;
            display: flex;
            justify-content: center;
            align-items: center;
            margin-right: 30px;
        }
        .score-number {
            font-size: 48px;
            font-weight: bold;
            color: white;
        }
        .score-details {
            flex: 1;
        }
        .score-level {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
            color: $scoreColor;
        }
        .summary-stats {
            display: flex;
            margin-top: 10px;
        }
        .stat {
            margin-right: 20px;
            text-align: center;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
        }
        .compliance-results {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .compliance-result {
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        .compliance-result:last-child {
            border-bottom: none;
        }
        .status-pass {
            color: green;
        }
        .status-fail {
            color: red;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
        .category-filter {
            margin-bottom: 20px;
        }
        .filter-button {
            padding: 8px 12px;
            margin-right: 5px;
            border: none;
            border-radius: 3px;
            background-color: #f0f0f0;
            cursor: pointer;
        }
        .filter-button.active {
            background-color: #0078D4;
            color: white;
        }
    </style>
    <script>
        function filterByCategory(category) {
            const results = document.querySelectorAll('.compliance-result');
            const buttons = document.querySelectorAll('.filter-button');
            
            // Update active button
            buttons.forEach(btn => {
                if (btn.getAttribute('data-category') === category || (category === 'all' && btn.getAttribute('data-category') === 'all')) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
            
            // Show/hide results
            results.forEach(result => {
                if (category === 'all' || result.getAttribute('data-category') === category) {
                    result.style.display = 'block';
                } else {
                    result.style.display = 'none';
                }
            });
        }
    </script>
</head>
<body>
    <header>
        <div class="container">
            <h1>Conditional Access Compliance Report</h1>
            <p>Generated on $($this.GeneratedDate.ToString("MMM dd, yyyy HH:mm:ss"))</p>
        </div>
    </header>
    
    <div class="container">
        <div class="score-card">
            <div class="score-circle">
                <div class="score-number">$($this.ComplianceScore)%</div>
            </div>
            <div class="score-details">
                <div class="score-level">$scoreLevel</div>
                <p>Tenant: $($this.TenantName)</p>
                <p>Tenant ID: $($this.TenantId)</p>
                <div class="summary-stats">
                    <div class="stat">
                        <div class="stat-number">$($this.Results.Count)</div>
                        <div>Total Checks</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" style="color: green;">$(@($this.Results | Where-Object { $_.IsCompliant }).Count)</div>
                        <div>Passed</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number" style="color: red;">$(@($this.Results | Where-Object { -not $_.IsCompliant }).Count)</div>
                        <div>Failed</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="category-filter">
            <h3>Filter by Category:</h3>
            <button class="filter-button active" data-category="all" onclick="filterByCategory('all')">All</button>
"@

        # Get unique categories and add filter buttons
        $categories = $this.Results | ForEach-Object { $_.Category } | Sort-Object -Unique
        foreach ($category in $categories) {
            $html += @"
            <button class="filter-button" data-category="$category" onclick="filterByCategory('$category')">$category</button>
"@
        }

        $html += @"
        </div>
        
        <div class="compliance-results">
            <h2>Detailed Results</h2>
"@

        # Add all compliance results
        foreach ($result in $this.Results) {
            $html += @"
            <div class="compliance-result" data-category="$($result.Category)">
                $($result.ToHtml())
            </div>
"@
        }

        $html += @"
        </div>
        
        <div class="footer">
            <p>Conditional Access Analyzer - Generated by PowerShell Module</p>
            <p>© $((Get-Date).Year) DataGuys</p>
        </div>
    </div>
</body>
</html>
"@

        return $html
    }
    
    # Method to export to JSON
    [string] ToJson() {
        return $this | ConvertTo-Json -Depth 10
    }
    
    # Method to export to CSV
    [string] ToCsv() {
        $csv = "CheckName,IsCompliant,ComplianceStatus,Severity,Category,Recommendation`n"
        
        foreach ($result in $this.Results) {
            $severityText = $result.Severity -eq 1 ? "Critical" : 
                           ($result.Severity -eq 2 ? "High" : 
                           ($result.Severity -eq 3 ? "Medium" : "Low"))
                           
            $recommendation = $result.Recommendation -replace '"', '""'
            
            $csv += "`"$($result.CheckName)`",`"$($result.IsCompliant)`",`"$($result.ComplianceStatus)`",`"$severityText`",`"$($result.Category)`",`"$recommendation`"`n"
        }
        
        return $csv
    }
}
