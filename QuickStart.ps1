# ConditionalAccessAnalyzer Enhanced QuickStart for Azure Cloud Shell
# This script provides a comprehensive Conditional Access assessment with minimal setup
# Usage: Just copy and paste this entire script into Azure Cloud Shell (PowerShell)

# Script header with version and description
Write-Host @"
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   Conditional Access Analyzer v2.0 - Enhanced QuickStart              ║
║   Zero Trust Security Assessment Tool                                 ║
║                                                                       ║
║   GitHub: https://github.com/DataGuys/ConditionalAccess              ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Function to show progress animation
function Show-ProgressAnimation {
    param (
        [string]$Activity,
        [int]$DurationSeconds = 3
    )
    
    $chars = '|', '/', '-', '\'
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($DurationSeconds)
    
    $i = 0
    while ((Get-Date) -lt $endTime) {
        Write-Host "`r$Activity $($chars[$i % $chars.Length])" -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 100
        $i++
    }
    Write-Host "`r$Activity ✓" -ForegroundColor Green
}

# Introduction with check if running in Azure Cloud Shell
$isCloudShell = $env:ACC_CLOUD -eq 'Azure'
if (-not $isCloudShell) {
    Write-Host "`n⚠️ Note: This script is optimized for Azure Cloud Shell. Some features may not work as expected in other environments." -ForegroundColor Yellow
}

Write-Host "`n📋 Initializing Zero Trust Conditional Access assessment...`n" -ForegroundColor White

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell Version: $($psVersion.Major).$($psVersion.Minor).$($psVersion.Patch)" -ForegroundColor White
if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
    Write-Host "⚠️ Warning: This script requires PowerShell 5.1 or higher." -ForegroundColor Yellow
}

# Step 1: Check for and install required Microsoft Graph modules
Write-Host "`n👉 Step 1: Checking for required Microsoft Graph modules..." -ForegroundColor Cyan

$requiredModules = @(
    @{Name = 'Microsoft.Graph.Authentication'; MinVersion = '1.20.0'},
    @{Name = 'Microsoft.Graph.Identity.SignIns'; MinVersion = '1.20.0'},
    @{Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinVersion = '1.20.0'},
    @{Name = 'Microsoft.Graph.DeviceManagement'; MinVersion = '1.20.0'}
)

$modulesToInstall = @()

foreach ($module in $requiredModules) {
    $installedModule = Get-Module -Name $module.Name -ListAvailable | 
                      Sort-Object Version -Descending | 
                      Select-Object -First 1
    
    if (-not $installedModule) {
        Write-Host "   Module $($module.Name) not found" -ForegroundColor Yellow
        $modulesToInstall += $module.Name
    }
    elseif ([Version]$installedModule.Version -lt [Version]$module.MinVersion) {
        Write-Host "   Module $($module.Name) version $($installedModule.Version) is outdated (minimum required: $($module.MinVersion))" -ForegroundColor Yellow
        $modulesToInstall += $module.Name
    }
    else {
        Write-Host "   ✓ Module $($module.Name) version $($installedModule.Version) is installed" -ForegroundColor Green
    }
}

if ($modulesToInstall.Count -gt 0) {
    Write-Host "`n   Installing required modules..." -ForegroundColor Yellow
    foreach ($module in $modulesToInstall) {
        try {
            Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Host "   ✓ Successfully installed $module" -ForegroundColor Green
        }
        catch {
            Write-Host "   ❌ Failed to install $module. Error: $_" -ForegroundColor Red
            Write-Host "   Please run with administrator privileges or install the module manually." -ForegroundColor Yellow
            exit
        }
    }
}

# Step 2: Direct import of the module from GitHub
Write-Host "`n👉 Step 2: Importing Conditional Access Analyzer module..." -ForegroundColor Cyan
Show-ProgressAnimation -Activity "   Downloading module from GitHub" -DurationSeconds 2

$modulePath = "$env:TEMP\ConditionalAccessAnalyzer.psm1"
try {
    # Create a web client with TLS 1.2 support
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # Download the module directly from GitHub
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile(
        "https://raw.githubusercontent.com/DataGuys/ConditionalAccess/refs/heads/main/ConditionalAccessAnalyzer.psm1",
        $modulePath
    )
    
    # Import the module
    Import-Module $modulePath -Force
    Write-Host "   ✓ Successfully imported ConditionalAccessAnalyzer module" -ForegroundColor Green
}
catch {
    Write-Host "   ❌ Failed to download and import module. Error: $_" -ForegroundColor Red
    
    # Fallback method: Create the module from embedded content
    Write-Host "   Attempting alternative import method..." -ForegroundColor Yellow
    
    try {
        # Add this code to QuickStart.ps1 in the "attempting alternative import method" section
$coreFunctions = @"
function Connect-CAAnalyzer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = \$false)]
        [switch]\$ShowConnectionDetails
    )
    
    try {
        \$requiredScopes = @(
            "Policy.Read.All", "Directory.Read.All", 
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementApps.Read.All"
        )
        
        Connect-MgGraph -Scopes \$requiredScopes -ErrorAction Stop
        
        if (\$ShowConnectionDetails) {
            \$context = Get-MgContext
            Write-Host "Connected to \$(\$context.TenantId) as \$(\$context.Account)" -ForegroundColor Green
        }
        
        return \$true
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: \$_"
        return \$false
    }
}

function Invoke-CAComplianceCheck {
    [CmdletBinding()]
    param()
    
    try {
        # Get policies
        \$policies = Get-MgIdentityConditionalAccessPolicy
        
        # Basic checks
        \$adminMFA = \$false
        \$userMFA = \$false
        \$deviceCompliance = \$false
        \$riskPolicies = \$false
        
        foreach(\$policy in \$policies) {
            # Check for Admin MFA
            if (\$policy.State -eq "enabled" -and 
                \$null -ne \$policy.Conditions.Users.IncludeRoles -and
                \$policy.Conditions.Users.IncludeRoles.Count -gt 0 -and
                \$null -ne \$policy.GrantControls.BuiltInControls -and
                \$policy.GrantControls.BuiltInControls -contains "mfa") {
                \$adminMFA = \$true
            }
            
            # Check for User MFA
            if (\$policy.State -eq "enabled" -and 
                \$policy.Conditions.Users.IncludeUsers -contains "All" -and
                \$null -ne \$policy.GrantControls.BuiltInControls -and
                \$policy.GrantControls.BuiltInControls -contains "mfa") {
                \$userMFA = \$true
            }
            
            # Check for Device Compliance
            if (\$policy.State -eq "enabled" -and
                \$null -ne \$policy.GrantControls.BuiltInControls -and
                \$policy.GrantControls.BuiltInControls -contains "compliantDevice") {
                \$deviceCompliance = \$true
            }
            
            # Check for Risk Policies
            if (\$policy.State -eq "enabled" -and
                (\$null -ne \$policy.Conditions.SignInRisk -or
                 \$null -ne \$policy.Conditions.UserRiskLevels)) {
                \$riskPolicies = \$true
            }
        }
        
        # Calculate score
        \$score = 0
        if (\$adminMFA) { \$score += 25 }
        if (\$userMFA) { \$score += 25 }
        if (\$deviceCompliance) { \$score += 25 }
        if (\$riskPolicies) { \$score += 25 }
        
        # Construct results
        \$results = [PSCustomObject]@{
            TenantId = (Get-MgContext).TenantId
            TenantName = (Get-MgOrganization).DisplayName
            ComplianceScore = \$score
            Checks = @{
                AdminMFA = @{
                    AdminMFARequired = \$adminMFA
                    Recommendation = "Implement MFA for all administrative roles"
                }
                UserMFA = @{
                    BroadUserMFARequired = \$userMFA
                    Recommendation = "Implement MFA for all users"
                }
                DeviceCompliance = @{
                    BroadDeviceComplianceRequired = \$deviceCompliance
                    Recommendation = "Require device compliance for resource access"
                }
                RiskPolicies = @{
                    SignInRiskPoliciesConfigured = \$riskPolicies
                    UserRiskPoliciesConfigured = \$riskPolicies
                    Recommendation = "Configure risk-based Conditional Access policies"
                }
                TokenBinding = @{
                    TokenSessionBindingConfigured = \$false
                    Recommendation = "Configure token session binding with appropriate sign-in frequency"
                }
                MAMPolicies = @{
                    MAMPoliciesConfigured = \$false
                    Recommendation = "Configure Mobile Application Management policies"
                }
                ZeroTrust = @{
                    MDCAIntegrated = \$false
                    GlobalSecureAccessConfigured = \$false
                    Recommendation = "Configure MDCA integration and Zero Trust Network Access"
                }
            }
        }
        
        return \$results
    }
    catch {
        Write-Error "Failed to run compliance check: \$_"
        throw
    }
}

function Export-CAComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = \$false)]
        [PSCustomObject]\$Results,
        
        [Parameter(Mandatory = \$false)]
        [ValidateSet('HTML', 'CSV', 'JSON')]
        [string]\$Format = 'HTML',
        
        [Parameter(Mandatory = \$false)]
        [string]\$Path = "~/CA-Compliance-Report.\$($Format.ToLower())",
        
        [Parameter(Mandatory = \$false)]
        [switch]\$OpenReport
    )
    
    if (-not \$Results) {
        \$Results = Invoke-CAComplianceCheck
    }
    
    # Generate basic report
    \$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Conditional Access Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1, h2 { color: #0078D4; }
        .score { font-size: 2em; font-weight: bold; }
        .pass { color: green; }
        .fail { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Conditional Access Compliance Report</h1>
    <p>Tenant: \$(\$Results.TenantName)</p>
    <p>Generated: \$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <h2>Compliance Score: <span class="score">\$(\$Results.ComplianceScore)%</span></h2>
    
    <h2>Security Checks</h2>
    <table>
        <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Recommendation</th>
        </tr>
        <tr>
            <td>Admin MFA Required</td>
            <td class="\$(\$Results.Checks.AdminMFA.AdminMFARequired ? 'pass' : 'fail')">\$(\$Results.Checks.AdminMFA.AdminMFARequired ? 'PASS' : 'FAIL')</td>
            <td>\$(\$Results.Checks.AdminMFA.Recommendation)</td>
        </tr>
        <tr>
            <td>User MFA Required</td>
            <td class="\$(\$Results.Checks.UserMFA.BroadUserMFARequired ? 'pass' : 'fail')">\$(\$Results.Checks.UserMFA.BroadUserMFARequired ? 'PASS' : 'FAIL')</td>
            <td>\$(\$Results.Checks.UserMFA.Recommendation)</td>
        </tr>
        <tr>
            <td>Device Compliance Required</td>
            <td class="\$(\$Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired ? 'pass' : 'fail')">\$(\$Results.Checks.DeviceCompliance.BroadDeviceComplianceRequired ? 'PASS' : 'FAIL')</td>
            <td>\$(\$Results.Checks.DeviceCompliance.Recommendation)</td>
        </tr>
        <tr>
            <td>Risk-Based Policies</td>
            <td class="\$((\$Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -or \$Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) ? 'pass' : 'fail')">\$((\$Results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -or \$Results.Checks.RiskPolicies.UserRiskPoliciesConfigured) ? 'PASS' : 'FAIL')</td>
            <td>\$(\$Results.Checks.RiskPolicies.Recommendation)</td>
        </tr>
    </table>
</body>
</html>
"@

    # Save report
    Set-Content -Path \$Path -Value \$htmlContent -Force
    Write-Host "Report saved to \$Path" -ForegroundColor Green
    
    # Open report if requested
    if (\$OpenReport) {
        Start-Process \$Path
    }
    
    return \$Path
}
"@

# Add this to your QuickStart.ps1 file in the fallback method section
# Create a module file in temp with the core functions
$tempModulePath = "$env:TEMP\CAAnalyzerCore.psm1"
Set-Content -Path $tempModulePath -Value $coreFunctions -Force
Import-Module $tempModulePath -Force
        Write-Host "   ✓ Successfully used alternative import method" -ForegroundColor Green
    }
    catch {
        Write-Host "   ❌ All import methods failed. Cannot continue." -ForegroundColor Red
        exit
    }
}

# Step 3: Connect to Microsoft Graph
Write-Host "`n👉 Step 3: Connecting to Microsoft Graph..." -ForegroundColor Cyan

$requiredScopes = @(
    "Policy.Read.All",
    "Directory.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.Read.All",
    "IdentityRiskyUser.Read.All"
)

try {
    # Check if already connected with sufficient permissions
    $currentContext = Get-MgContext -ErrorAction SilentlyContinue
    
    $needsConnection = $true
    if ($currentContext) {
        $missingScopes = @()
        foreach ($scope in $requiredScopes) {
            if ($currentContext.Scopes -notcontains $scope) {
                $missingScopes += $scope
            }
        }
        
        if ($missingScopes.Count -eq 0) {
            Write-Host "   ✓ Already connected to Microsoft Graph with required scopes" -ForegroundColor Green
            $needsConnection = $false
        }
        else {
            Write-Host "   Current connection is missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
        }
    }
    
    if ($needsConnection) {
        Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
        Write-Host "   ✓ Successfully connected to Microsoft Graph" -ForegroundColor Green
    }
    
    # Display connection information
    $context = Get-MgContext
    $org = Get-MgOrganization
    
    Write-Host "`n   Connection Information:" -ForegroundColor White
    Write-Host "   - Tenant: $($org.DisplayName)" -ForegroundColor White
    Write-Host "   - Tenant ID: $($context.TenantId)" -ForegroundColor White
    Write-Host "   - Account: $($context.Account)" -ForegroundColor White
}
catch {
    Write-Host "   ❌ Failed to connect to Microsoft Graph. Error: $_" -ForegroundColor Red
    
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have sufficient permissions in your tenant" -ForegroundColor White
    Write-Host "2. Try signing in to the Azure portal first" -ForegroundColor White
    Write-Host "3. If using a MFA-enabled account, complete the authentication prompt" -ForegroundColor White
    
    Write-Host "`nWould you like to retry the connection?" -ForegroundColor Yellow
    $retry = Read-Host "[Y/N]"
    
    if ($retry -eq "Y" -or $retry -eq "y") {
        try {
            Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
            Write-Host "   ✓ Successfully connected to Microsoft Graph" -ForegroundColor Green
        }
        catch {
            Write-Host "   ❌ Connection failed again. Please try running the script later." -ForegroundColor Red
            exit
        }
    }
    else {
        Write-Host "Exiting script." -ForegroundColor Red
        exit
    }
}

# Step 4: Run the Conditional Access compliance check
Write-Host "`n👉 Step 4: Running Conditional Access compliance check..." -ForegroundColor Cyan

try {
    Write-Host "   This may take a minute depending on the number of policies in your tenant..." -ForegroundColor White
    $results = Invoke-CAComplianceCheck
    
    # Display visual indicator of compliance score
    $complianceScore = $results.ComplianceScore
    $scoreColor = if ($complianceScore -ge 80) { "Green" } elseif ($complianceScore -ge 60) { "Yellow" } else { "Red" }
    $scoreIndicator = [string]::Concat([char]9608 * [math]::Round($complianceScore / 5))
    
    Write-Host "`n   Compliance Analysis Complete" -ForegroundColor Green
    Write-Host "`n   ╔══════════════════════════════════════════════════════════╗" -ForegroundColor White
    Write-Host "   ║ Overall Zero Trust Compliance Score                      ║" -ForegroundColor White
    Write-Host "   ╠══════════════════════════════════════════════════════════╣" -ForegroundColor White
    Write-Host "   ║                                                          ║" -ForegroundColor White
    Write-Host "   ║   $($complianceScore)%".PadRight(58) + "║" -ForegroundColor $scoreColor
    Write-Host "   ║   $scoreIndicator".PadRight(58) + "║" -ForegroundColor $scoreColor
    Write-Host "   ║                                                          ║" -ForegroundColor White
    Write-Host "   ╚══════════════════════════════════════════════════════════╝" -ForegroundColor White
    
    # Display detailed compliance by category
    Write-Host "`n   Compliance by Security Area:" -ForegroundColor White
    
    # Identity Protection: AdminMFA + UserMFA
    $identityProtectionScore = [math]::Round(([int]$results.Checks.AdminMFA.AdminMFARequired + [int]$results.Checks.UserMFA.BroadUserMFARequired) / 2 * 100)
    $identityColor = if ($identityProtectionScore -ge 80) { "Green" } elseif ($identityProtectionScore -ge 50) { "Yellow" } else { "Red" }
    Write-Host "   - Identity Protection: " -NoNewline -ForegroundColor White
    Write-Host "$identityProtectionScore%" -ForegroundColor $identityColor
    
    # Device Trust
    $deviceScore = [math]::Round([int]$results.Checks.DeviceCompliance.BroadDeviceComplianceRequired * 100)
    $deviceColor = if ($deviceScore -ge 80) { "Green" } elseif ($deviceScore -ge 50) { "Yellow" } else { "Red" }
    Write-Host "   - Device Trust: " -NoNewline -ForegroundColor White
    Write-Host "$deviceScore%" -ForegroundColor $deviceColor
    
    # Session Security
    $sessionScore = [math]::Round([int]$results.Checks.TokenBinding.TokenSessionBindingConfigured * 100)
    $sessionColor = if ($sessionScore -ge 80) { "Green" } elseif ($sessionScore -ge 50) { "Yellow" } else { "Red" }
    Write-Host "   - Session Security: " -NoNewline -ForegroundColor White
    Write-Host "$sessionScore%" -ForegroundColor $sessionColor
    
    # Risk-Based Access
    $riskScore = [math]::Round(([int]$results.Checks.RiskPolicies.SignInRiskPoliciesConfigured + [int]$results.Checks.RiskPolicies.UserRiskPoliciesConfigured) / 2 * 100)
    $riskColor = if ($riskScore -ge 80) { "Green" } elseif ($riskScore -ge 50) { "Yellow" } else { "Red" }
    Write-Host "   - Risk-Based Access: " -NoNewline -ForegroundColor White
    Write-Host "$riskScore%" -ForegroundColor $riskColor
    
    # Data Protection
    $dataScore = [math]::Round([int]$results.Checks.MAMPolicies.MAMPoliciesConfigured * 100)
    $dataColor = if ($dataScore -ge 80) { "Green" } elseif ($dataScore -ge 50) { "Yellow" } else { "Red" }
    Write-Host "   - Data Protection: " -NoNewline -ForegroundColor White
    Write-Host "$dataScore%" -ForegroundColor $dataColor
    
    # Network Security
    $networkScore = [math]::Round(([int]$results.Checks.ZeroTrust.MDCAIntegrated + [int]$results.Checks.ZeroTrust.GlobalSecureAccessConfigured) / 2 * 100)
    $networkColor = if ($networkScore -ge 80) { "Green" } elseif ($networkScore -ge 50) { "Yellow" } else { "Red" }
    Write-Host "   - Network Security: " -NoNewline -ForegroundColor White
    Write-Host "$networkScore%" -ForegroundColor $networkColor
}
catch {
    Write-Host "   ❌ Failed to run Conditional Access compliance check. Error: $_" -ForegroundColor Red
    
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Verify that you have sufficient permissions" -ForegroundColor White
    Write-Host "2. Check your connection to Microsoft Graph" -ForegroundColor White
    Write-Host "3. Ensure the Microsoft.Graph modules are correctly installed" -ForegroundColor White
    
    exit
}

# Step 5: Generate the HTML report
Write-Host "`n👉 Step 5: Generating HTML report..." -ForegroundColor Cyan

try {
    $reportPath = "~/CA-Compliance-Report.html"
    
    Show-ProgressAnimation -Activity "   Generating report" -DurationSeconds 3
    
    Export-CAComplianceReport -Results $results -Format HTML -Path $reportPath
    
    Write-Host "   ✓ Successfully generated HTML report: $reportPath" -ForegroundColor Green
}
catch {
    Write-Host "   ❌ Failed to generate HTML report. Error: $_" -ForegroundColor Red
    
    # Try to create a simplified text report as fallback
    Write-Host "   Generating simplified text report instead..." -ForegroundColor Yellow
    
    $textReportPath = "~/CA-Compliance-Report.txt"
    
    try {
        $textContent = "# Conditional Access Compliance Report`r`n"
        $textContent += "Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
        $textContent += "Tenant: $($org.DisplayName)`r`n"
        $textContent += "Compliance Score: $($results.ComplianceScore)%`r`n`r`n"
        
        $textContent += "## Compliance Check Results`r`n"
        $textContent += "- Admin MFA Required: $($results.Checks.AdminMFA.AdminMFARequired)`r`n"
        $textContent += "- User MFA Required: $($results.Checks.UserMFA.BroadUserMFARequired)`r`n"
        $textContent += "- Device Compliance Required: $($results.Checks.DeviceCompliance.BroadDeviceComplianceRequired)`r`n"
        $textContent += "- Token Session Binding: $($results.Checks.TokenBinding.TokenSessionBindingConfigured)`r`n"
        $textContent += "- Sign-in Risk Policies: $($results.Checks.RiskPolicies.SignInRiskPoliciesConfigured)`r`n"
        $textContent += "- User Risk Policies: $($results.Checks.RiskPolicies.UserRiskPoliciesConfigured)`r`n"
        $textContent += "- MAM Policies: $($results.Checks.MAMPolicies.MAMPoliciesConfigured)`r`n"
        $textContent += "- MDCA Integration: $($results.Checks.ZeroTrust.MDCAIntegrated)`r`n"
        $textContent += "- Global Secure Access: $($results.Checks.ZeroTrust.GlobalSecureAccessConfigured)`r`n`r`n"
        
        $textContent += "## Recommendations`r`n"
        if (-not $results.Checks.AdminMFA.AdminMFARequired) {
            $textContent += "- Admin MFA: $($results.Checks.AdminMFA.Recommendation)`r`n"
        }
        if (-not $results.Checks.UserMFA.BroadUserMFARequired) {
            $textContent += "- User MFA: $($results.Checks.UserMFA.Recommendation)`r`n"
        }
        if (-not $results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) {
            $textContent += "- Device Compliance: $($results.Checks.DeviceCompliance.Recommendation)`r`n"
        }
        if (-not $results.Checks.TokenBinding.TokenSessionBindingConfigured) {
            $textContent += "- Token Binding: $($results.Checks.TokenBinding.Recommendation)`r`n"
        }
        if (-not $results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -or -not $results.Checks.RiskPolicies.UserRiskPoliciesConfigured) {
            $textContent += "- Risk Policies: $($results.Checks.RiskPolicies.Recommendation)`r`n"
        }
        if (-not $results.Checks.MAMPolicies.MAMPoliciesConfigured) {
            $textContent += "- MAM Policies: $($results.Checks.MAMPolicies.Recommendation)`r`n"
        }
        if (-not $results.Checks.ZeroTrust.MDCAIntegrated -or -not $results.Checks.ZeroTrust.GlobalSecureAccessConfigured) {
            $textContent += "- Zero Trust: $($results.Checks.ZeroTrust.Recommendation)`r`n"
        }
        
        Set-Content -Path $textReportPath -Value $textContent
        Write-Host "   ✓ Successfully generated text report: $textReportPath" -ForegroundColor Green
    }
    catch {
        Write-Host "   ❌ Failed to generate text report. Error: $_" -ForegroundColor Red
    }
}

# Step 6: Display key recommendations
Write-Host "`n👉 Step 6: Key security recommendations..." -ForegroundColor Cyan

$recommendations = @()

if (-not $results.Checks.AdminMFA.AdminMFARequired) {
    $recommendations += [PSCustomObject]@{
        Priority = "Critical"
        Area = "Identity"
        Issue = "Admin MFA not required"
        Recommendation = $results.Checks.AdminMFA.Recommendation
    }
}

if (-not $results.Checks.UserMFA.BroadUserMFARequired) {
    $recommendations += [PSCustomObject]@{
        Priority = "High"
        Area = "Identity"
        Issue = "User MFA not broadly required"
        Recommendation = $results.Checks.UserMFA.Recommendation
    }
}

if (-not $results.Checks.DeviceCompliance.BroadDeviceComplianceRequired) {
    $recommendations += [PSCustomObject]@{
        Priority = "High"
        Area = "Device"
        Issue = "Device compliance not required"
        Recommendation = $results.Checks.DeviceCompliance.Recommendation
    }
}

if (-not $results.Checks.RiskPolicies.SignInRiskPoliciesConfigured) {
    $recommendations += [PSCustomObject]@{
        Priority = "High"
        Area = "Risk"
        Issue = "Sign-in risk policies not configured"
        Recommendation = "Configure CA policy based on sign-in risk to protect against suspicious sign-in attempts"
    }
}

if (-not $results.Checks.RiskPolicies.UserRiskPoliciesConfigured) {
    $recommendations += [PSCustomObject]@{
        Priority = "High"
        Area = "Risk"
        Issue = "User risk policies not configured"
        Recommendation = "Configure CA policy based on user risk to protect compromised accounts"
    }
}

if (-not $results.Checks.ZeroTrust.MDCAIntegrated) {
    $recommendations += [PSCustomObject]@{
        Priority = "Medium"
        Area = "Network"
        Issue = "MDCA not integrated"
        Recommendation = "Configure Microsoft Defender for Cloud Apps integration with Conditional Access"
    }
}

if (-not $results.Checks.TokenBinding.TokenSessionBindingConfigured) {
    $recommendations += [PSCustomObject]@{
        Priority = "Medium"
        Area = "Session"
        Issue = "Token session binding not configured"
        Recommendation = $results.Checks.TokenBinding.Recommendation
    }
}

if (-not $results.Checks.MAMPolicies.MAMPoliciesConfigured) {
    $recommendations += [PSCustomObject]@{
        Priority = "Medium"
        Area = "Data"
        Issue = "Mobile Application Management not configured"
        Recommendation = $results.Checks.MAMPolicies.Recommendation
    }
}

if ($recommendations.Count -gt 0) {
    Write-Host "`n   Security Issues Found:" -ForegroundColor Yellow
    
    foreach ($rec in $recommendations | Sort-Object -Property Priority) {
        $priorityColor = switch ($rec.Priority) {
            "Critical" { "Red" }
            "High" { "Yellow" }
            "Medium" { "White" }
            default { "Gray" }
        }
        
        $prioritySymbol = switch ($rec.Priority) {
            "Critical" { "‼️" }
            "High" { "❗" }
            "Medium" { "⚠️" }
            default { "ℹ️" }
        }
        
        Write-Host "   $prioritySymbol [$($rec.Priority)]".PadRight(15) -NoNewline -ForegroundColor $priorityColor
        Write-Host "$($rec.Area): " -NoNewline -ForegroundColor Cyan
        Write-Host "$($rec.Issue)" -ForegroundColor White
        Write-Host "     → $($rec.Recommendation)" -ForegroundColor Gray
    }
    
    Write-Host "`n   Remediation Command:" -ForegroundColor White
    Write-Host "   Invoke-CAComplianceRemediation -RemediateAll -DeployInReportOnlyMode" -ForegroundColor Yellow
    Write-Host "   Note: Review policies carefully before enforcement" -ForegroundColor Gray
}
else {
    Write-Host "`n   ✅ No critical security issues found. Your Conditional Access policies meet best practices!" -ForegroundColor Green
}

# Step 7: Next steps
Write-Host "`n👉 Step 7: Next steps..." -ForegroundColor Cyan

Write-Host "`n   To view the detailed HTML report:" -ForegroundColor White
Write-Host "   1. Click on the '...' menu in the top-right corner of Cloud Shell" -ForegroundColor White
Write-Host "   2. Select 'Download'" -ForegroundColor White
Write-Host "   3. Enter path: $reportPath" -ForegroundColor Yellow
Write-Host "   4. Download and open the file in your browser" -ForegroundColor White

Write-Host "`n   To use the Conditional Access Analyzer in this session:" -ForegroundColor White
Write-Host "   # Get detailed policy summary:" -ForegroundColor White
Write-Host "   Get-CAPoliciesSummary" -ForegroundColor Yellow

Write-Host "`n   # Create best practice policy templates:" -ForegroundColor White
Write-Host "   New-CABestPracticePolicy -PolicyType UserMFA -DeployPolicy -State 'enabledForReportingButNotEnforced'" -ForegroundColor Yellow

Write-Host "`n   # Run security benchmark assessment:" -ForegroundColor White
Write-Host "   Test-CASecurityBenchmark -BenchmarkName NIST" -ForegroundColor Yellow

Write-Host "`n   # Automated remediation (creates policies in report-only mode):" -ForegroundColor White
Write-Host "   Invoke-CAComplianceRemediation -RemediateAll -DeployInReportOnlyMode" -ForegroundColor Yellow

Write-Host "`n📘 Learn more about Zero Trust and Conditional Access:" -ForegroundColor Cyan
Write-Host "   - Microsoft Zero Trust documentation: https://aka.ms/zerotrust" -ForegroundColor White
Write-Host "   - Conditional Access documentation: https://aka.ms/conditionalaccess" -ForegroundColor White
Write-Host "   - Security best practices: https://aka.ms/cybersecurityreference" -ForegroundColor White

Write-Host "`n✨ Assessment complete! Thank you for using the Conditional Access Analyzer.`n" -ForegroundColor Green
