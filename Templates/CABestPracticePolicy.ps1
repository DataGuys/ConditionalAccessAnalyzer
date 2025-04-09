function New-CABestPracticePolicy {
    <#
    .SYNOPSIS
        Creates Conditional Access policy templates based on security best practices.
    .DESCRIPTION
        Generates and optionally deploys Conditional Access policies that implement
        security best practices for various scenarios. Templates support MFA enforcement,
        device compliance, risk-based access, and other Zero Trust controls.
    .PARAMETER PolicyType
        The type of policy template to create. Available types:
        - AdminMFA: MFA for administrative roles
        - UserMFA: MFA for regular users
        - DeviceCompliance: Device compliance requirements
        - TokenBinding: Token session binding
        - SignInRisk: Sign-in risk-based policy
        - UserRisk: User risk-based policy
        - MAMPolicy: Mobile Application Management policy
        - CloudAppSecurity: Microsoft Defender for Cloud Apps integration
        - GlobalSecureAccess: Zero Trust Network Access controls
        - ZeroTrustBase: Comprehensive Zero Trust baseline (includes multiple policies)
        - NIST80063: NIST SP 800-63 Digital Identity Guidelines compliant policies
    .PARAMETER PolicyName
        Optional custom name for the policy. If not specified, a default name will be used.
    .PARAMETER IncludeUsers
        Specifies which users to include in the policy. Default is "All".
    .PARAMETER ExcludeUsers
        Specifies which users to exclude from the policy.
    .PARAMETER ExcludeGroups
        Specifies which groups to exclude from the policy.
    .PARAMETER SpecificApps
        Specifies which applications to include if not using "All" or "Office365".
    .PARAMETER DeployPolicy
        If specified, the policy is created in Entra ID. Otherwise, the policy object is returned.
    .PARAMETER State
        The state of the new policy. Valid values are "enabled", "disabled", or "enabledForReportingButNotEnforced".
    .PARAMETER PassThru
        If specified, returns the created policy object.
    .PARAMETER Force
        If specified, any confirmations are suppressed.
    .EXAMPLE
        New-CABestPracticePolicy -PolicyType AdminMFA -DeployPolicy
        Creates and deploys an admin MFA policy.
    .EXAMPLE
        New-CABestPracticePolicy -PolicyType ZeroTrustBase -DeployPolicy -State "enabledForReportingButNotEnforced"
        Creates a comprehensive set of Zero Trust baseline policies in report-only mode.
    .EXAMPLE
        New-CABestPracticePolicy -PolicyType UserMFA -PolicyName "MFA for Sales Team" -IncludeUsers (Get-MgGroup -Filter "displayName eq 'Sales'").Id
        Creates an MFA policy template specifically for a sales team.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('AdminMFA', 'UserMFA', 'DeviceCompliance', 'TokenBinding', 'SignInRisk', 
                    'UserRisk', 'MAMPolicy', 'CloudAppSecurity', 'GlobalSecureAccess', 'ZeroTrustBase', 
                    'NIST80063')]
        [string]$PolicyType,
        
        [Parameter(Mandatory = $false)]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $false)]
        [string[]]$IncludeUsers = @("All"),
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeUsers,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeGroups,
        
        [Parameter(Mandatory = $false)]
        [string[]]$SpecificApps,
        
        [Parameter(Mandatory = $false)]
        [switch]$DeployPolicy,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled', 'enabledForReportingButNotEnforced')]
        [string]$State = 'enabled',
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin {
        # Verify connection
        if (-not (Test-CAAnalyzerConnection)) {
            throw "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
        }
        
        # Check if required permissions are available
        $requiredPermission = "Policy.ReadWrite.ConditionalAccess"
        $context = Get-MgContext
        if ($context.Scopes -notcontains $requiredPermission) {
            Write-Warning "The current connection does not have the required permission: $requiredPermission"
            Write-Warning "Only policy templates will be generated, but they cannot be deployed."
            $DeployPolicy = $false
        }
        
        # Create empty exclusions if not specified
        if (-not $ExcludeUsers) {
            $ExcludeUsers = @()
        }
        
        if (-not $ExcludeGroups) {
            $ExcludeGroups = @()
        }
        
        # Helper function to get Admin Role IDs
        function Get-AdminRoleIds {
            $adminRoles = @(
                "Global Administrator",
                "Privileged Role Administrator",
                "User Administrator", 
                "Authentication Administrator",
                "Security Administrator",
                "Helpdesk Administrator",
                "Exchange Administrator",
                "SharePoint Administrator",
                "Teams Administrator",
                "Application Administrator",
                "Cloud Application Administrator"
            )
            
            $roleIds = @()
            foreach ($roleName in $adminRoles) {
                try {
                    $role = Get-MgDirectoryRoleTemplate -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                    if ($role) {
                        $roleIds += $role.Id
                    }
                }
                catch {
                    Write-Verbose "Could not find role: $roleName. $_"
                }
            }
            
            return $roleIds
        }
        
        # Helper function to get emergency access account IDs
        function Get-EmergencyAccessIds {
            $emergencyAccounts = @()
            
            # Get users with "emergency" in the display name
            $users = Get-MgUser -Filter "startswith(displayName, 'emergency') or startswith(userPrincipalName, 'emergency')" -ErrorAction SilentlyContinue
            foreach ($user in $users) {
                $emergencyAccounts += $user.Id
            }
            
            # Add any manually specified emergency accounts
            # This can be customized based on organizational naming conventions
            
            return $emergencyAccounts
        }
        
        # Helper function to create policy parameter object
        function New-PolicyParams {
            param (
                [string]$DisplayName,
                [string]$State,
                [hashtable]$Conditions,
                [hashtable]$GrantControls,
                [hashtable]$SessionControls = $null
            )
            
            $params = @{
                DisplayName = $DisplayName
                State = $State
                Conditions = $Conditions
                GrantControls = $GrantControls
            }
            
            if ($SessionControls) {
                $params['SessionControls'] = $SessionControls
            }
            
            return $params
        }
    }
    
    process {
        try {
            # Generate policy based on type
            switch ($PolicyType) {
                'AdminMFA' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA001: Require MFA for administrators" }
                    
                    # Get admin roles
                    $adminRoleIds = Get-AdminRoleIds
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeRoles = $adminRoleIds
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = @("All")
                        }
                    }
                    
                    # Create grant controls
                    $grantControls = @{
                        Operator = "OR"
                        BuiltInControls = @("mfa")
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls $grantControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create Admin MFA policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created Admin MFA policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'UserMFA' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA002: Require MFA for all users" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("All") }
                        }
                        ClientAppTypes = @("browser", "mobileAppsAndDesktopClients")
                    }
                    
                    # Create grant controls
                    $grantControls = @{
                        Operator = "OR"
                        BuiltInControls = @("mfa")
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls $grantControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create User MFA policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created User MFA policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'DeviceCompliance' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA003: Require device compliance" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("Office365") }
                        }
                        Platforms = @{
                            IncludePlatforms = @("android", "iOS", "windows", "macOS")
                        }
                        ClientAppTypes = @("mobileAppsAndDesktopClients")
                    }
                    
                    # Create grant controls
                    $grantControls = @{
                        Operator = "AND"
                        BuiltInControls = @("compliantDevice")
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls $grantControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create Device Compliance policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created Device Compliance policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'TokenBinding' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA004: Session control - Sign-in frequency" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("All") }
                        }
                    }
                    
                    # Create session controls
                    $sessionControls = @{
                        SignInFrequency = @{
                            IsEnabled = $true
                            Type = "hours"
                            Value = 12
                        }
                        PersistentBrowser = @{
                            IsEnabled = $true
                            Mode = "never"
                        }
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls @{} -SessionControls $sessionControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create Token Session Binding policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created Token Session Binding policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'SignInRisk' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA005: Sign-in risk-based policy" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("All") }
                        }
                        SignInRisk = @{
                            RiskLevels = @("high", "medium")
                        }
                    }
                    
                    # Create grant controls
                    $grantControls = @{
                        Operator = "OR"
                        BuiltInControls = @("mfa")
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls $grantControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create Sign-in Risk policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created Sign-in Risk policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'UserRisk' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA006: User risk-based policy" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("All") }
                        }
                        UserRiskLevels = @("high", "medium")
                    }
                    
                    # Create grant controls
                    $grantControls = @{
                        Operator = "OR"
                        BuiltInControls = @("mfa", "passwordChange")
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls $grantControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create User Risk policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created User Risk policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'MAMPolicy' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA007: Mobile application management" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("Office365") }
                        }
                        Platforms = @{
                            IncludePlatforms = @("android", "iOS")
                        }
                        ClientAppTypes = @("mobileAppsAndDesktopClients")
                    }
                    
                    # Create grant controls
                    $grantControls = @{
                        Operator = "OR"
                        BuiltInControls = @("compliantApplication", "approvedApplication")
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls $grantControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create MAM policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created MAM policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'CloudAppSecurity' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA008: Microsoft Defender for Cloud Apps" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("Office365") }
                        }
                        ClientAppTypes = @("browser")
                    }
                    
                    # Create session controls
                    $sessionControls = @{
                        CloudAppSecurity = @{
                            IsEnabled = $true
                            CloudAppSecurityType = "monitorOnly"
                        }
                    }
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls @{} -SessionControls $sessionControls
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create MDCA policy: $policyName")) {
                            $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                            Write-Host "Created MDCA policy: $policyName" -ForegroundColor Green
                            
                            if ($PassThru) {
                                return $policy
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'GlobalSecureAccess' {
                    # Set policy name
                    $policyName = if ($PolicyName) { $PolicyName } else { "CA009: Global Secure Access" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $conditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("All") }
                        }
                        ClientAppTypes = @("all")
                    }
                    
                    # Create a placeholder policy since actual Global Secure Access policy creation
                    # requires specific APIs for network configuration that are beyond the scope of a template
                    
                    # Create policy parameters
                    $policyParams = New-PolicyParams -DisplayName $policyName -State $State -Conditions $conditions -GrantControls @{}
                    
                    # Add comment
                    $policyParams["Comment"] = "This policy template is a placeholder for Global Secure Access configuration. Full implementation requires specific network access and tunnel configuration."
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        Write-Warning "Global Secure Access policy requires additional configuration beyond what can be created with this template."
                        Write-Warning "Please visit https://learn.microsoft.com/en-us/entra/global-secure-access/concept-about-global-secure-access for more information."
                        
                        if ($Force -or $PSCmdlet.ShouldContinue("Create a placeholder Global Secure Access policy?", "This will only create a basic policy without the full Global Secure Access configuration.")) {
                            if ($PSCmdlet.ShouldProcess("Entra ID", "Create placeholder Global Secure Access policy: $policyName")) {
                                $policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
                                Write-Host "Created placeholder Global Secure Access policy: $policyName" -ForegroundColor Green
                                
                                if ($PassThru) {
                                    return $policy
                                }
                            }
                        }
                    }
                    else {
                        return $policyParams
                    }
                }
                
                'ZeroTrustBase' {
                    Write-Host "Creating Zero Trust baseline policies..." -ForegroundColor Cyan
                    
                    # Create base policies one by one
                    $createdPolicies = @()
                    
                    # Admin MFA
                    Write-Host "  Creating Admin MFA policy..." -ForegroundColor Yellow
                    $adminMfaParams = @{
                        PolicyType = 'AdminMFA'
                        PolicyName = if ($PolicyName) { "$PolicyName - Admin MFA" } else { "CA001: Require MFA for administrators" }
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $adminMfaParams['DeployPolicy'] = $true
                        $adminMfaParams['PassThru'] = $true
                    }
                    
                    try {
                        $adminMfaPolicy = New-CABestPracticePolicy @adminMfaParams
                        if ($adminMfaPolicy) {
                            $createdPolicies += $adminMfaPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create Admin MFA policy: $_"
                    }
                    
                    # User MFA
                    Write-Host "  Creating User MFA policy..." -ForegroundColor Yellow
                    $userMfaParams = @{
                        PolicyType = 'UserMFA'
                        PolicyName = if ($PolicyName) { "$PolicyName - User MFA" } else { "CA002: Require MFA for all users" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $userMfaParams['DeployPolicy'] = $true
                        $userMfaParams['PassThru'] = $true
                    }
                    
                    try {
                        $userMfaPolicy = New-CABestPracticePolicy @userMfaParams
                        if ($userMfaPolicy) {
                            $createdPolicies += $userMfaPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create User MFA policy: $_"
                    }
                    
                    # Device Compliance
                    Write-Host "  Creating Device Compliance policy..." -ForegroundColor Yellow
                    $deviceComplianceParams = @{
                        PolicyType = 'DeviceCompliance'
                        PolicyName = if ($PolicyName) { "$PolicyName - Device Compliance" } else { "CA003: Require device compliance" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $deviceComplianceParams['DeployPolicy'] = $true
                        $deviceComplianceParams['PassThru'] = $true
                    }
                    
                    try {
                        $deviceCompliancePolicy = New-CABestPracticePolicy @deviceComplianceParams
                        if ($deviceCompliancePolicy) {
                            $createdPolicies += $deviceCompliancePolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create Device Compliance policy: $_"
                    }
                    
                    # Sign-in Risk
                    Write-Host "  Creating Sign-in Risk policy..." -ForegroundColor Yellow
                    $signInRiskParams = @{
                        PolicyType = 'SignInRisk'
                        PolicyName = if ($PolicyName) { "$PolicyName - Sign-in Risk" } else { "CA005: Sign-in risk-based policy" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $signInRiskParams['DeployPolicy'] = $true
                        $signInRiskParams['PassThru'] = $true
                    }
                    
                    try {
                        $signInRiskPolicy = New-CABestPracticePolicy @signInRiskParams
                        if ($signInRiskPolicy) {
                            $createdPolicies += $signInRiskPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create Sign-in Risk policy: $_"
                    }
                    
                    # User Risk
                    Write-Host "  Creating User Risk policy..." -ForegroundColor Yellow
                    $userRiskParams = @{
                        PolicyType = 'UserRisk'
                        PolicyName = if ($PolicyName) { "$PolicyName - User Risk" } else { "CA006: User risk-based policy" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $userRiskParams['DeployPolicy'] = $true
                        $userRiskParams['PassThru'] = $true
                    }
                    
                    try {
                        $userRiskPolicy = New-CABestPracticePolicy @userRiskParams
                        if ($userRiskPolicy) {
                            $createdPolicies += $userRiskPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create User Risk policy: $_"
                    }
                    
                    # MAM Policy
                    Write-Host "  Creating MAM policy..." -ForegroundColor Yellow
                    $mamPolicyParams = @{
                        PolicyType = 'MAMPolicy'
                        PolicyName = if ($PolicyName) { "$PolicyName - MAM" } else { "CA007: Mobile application management" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $mamPolicyParams['DeployPolicy'] = $true
                        $mamPolicyParams['PassThru'] = $true
                    }
                    
                    try {
                        $mamPolicy = New-CABestPracticePolicy @mamPolicyParams
                        if ($mamPolicy) {
                            $createdPolicies += $mamPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create MAM policy: $_"
                    }
                    
                    # MDCA
                    Write-Host "  Creating MDCA policy..." -ForegroundColor Yellow
                    $mdcaParams = @{
                        PolicyType = 'CloudAppSecurity'
                        PolicyName = if ($PolicyName) { "$PolicyName - MDCA" } else { "CA008: Microsoft Defender for Cloud Apps" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $mdcaParams['DeployPolicy'] = $true
                        $mdcaParams['PassThru'] = $true
                    }
                    
                    try {
                        $mdcaPolicy = New-CABestPracticePolicy @mdcaParams
                        if ($mdcaPolicy) {
                            $createdPolicies += $mdcaPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create MDCA policy: $_"
                    }
                    
                    # Return all created policies
                    return $createdPolicies
                }
                
                'NIST80063' {
                    Write-Host "Creating NIST SP 800-63 Digital Identity Guidelines compliant policies..." -ForegroundColor Cyan
                    
                    # Create base policies one by one
                    $createdPolicies = @()
                    
                    # Admin MFA policy (AAL2 for privileged users)
                    Write-Host "  Creating AAL2 for administrators..." -ForegroundColor Yellow
                    $adminMfaParams = @{
                        PolicyType = 'AdminMFA'
                        PolicyName = if ($PolicyName) { "$PolicyName - AAL2 for Admins" } else { "NIST800-63: AAL2 for administrators" }
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $adminMfaParams['DeployPolicy'] = $true
                        $adminMfaParams['PassThru'] = $true
                    }
                    
                    try {
                        $adminMfaPolicy = New-CABestPracticePolicy @adminMfaParams
                        if ($adminMfaPolicy) {
                            $createdPolicies += $adminMfaPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create AAL2 for administrators policy: $_"
                    }
                    
                    # User MFA policy (AAL2 for normal users)
                    Write-Host "  Creating AAL2 for all users..." -ForegroundColor Yellow
                    $userMfaParams = @{
                        PolicyType = 'UserMFA'
                        PolicyName = if ($PolicyName) { "$PolicyName - AAL2 for Users" } else { "NIST800-63: AAL2 for all users" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $userMfaParams['DeployPolicy'] = $true
                        $userMfaParams['PassThru'] = $true
                    }
                    
                    try {
                        $userMfaPolicy = New-CABestPracticePolicy @userMfaParams
                        if ($userMfaPolicy) {
                            $createdPolicies += $userMfaPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create AAL2 for users policy: $_"
                    }
                    
                    # Session Timeout policy (CSP) 
                    Write-Host "  Creating session timeout policy..." -ForegroundColor Yellow
                    
                    # Set policy name
                    $sessionPolicyName = if ($PolicyName) { "$PolicyName - Session Timeout" } else { "NIST800-63: Session timeout" }
                    
                    # Get emergency access accounts to exclude
                    $emergencyAccounts = Get-EmergencyAccessIds
                    
                    # Combine with other exclusions
                    $allExcludedUsers = $ExcludeUsers + $emergencyAccounts
                    
                    # Create conditions
                    $sessionConditions = @{
                        Users = @{
                            IncludeUsers = $IncludeUsers
                            ExcludeUsers = $allExcludedUsers
                            ExcludeGroups = $ExcludeGroups
                        }
                        Applications = @{
                            IncludeApplications = if ($SpecificApps) { $SpecificApps } else { @("All") }
                        }
                        ClientAppTypes = @("browser", "mobileAppsAndDesktopClients")
                    }
                    
                    # Create session controls (30 minute session expiration per NIST recommendations)
                    $sessionCtrl = @{
                        SignInFrequency = @{
                            IsEnabled = $true
                            Type = "minutes"
                            Value = 30
                        }
                        PersistentBrowser = @{
                            IsEnabled = $true
                            Mode = "never"
                        }
                    }
                    
                    # Create policy parameters
                    $sessionPolicyParams = New-PolicyParams -DisplayName $sessionPolicyName -State $State -Conditions $sessionConditions -GrantControls @{} -SessionControls $sessionCtrl
                    
                    # Create or deploy policy
                    if ($DeployPolicy) {
                        if ($PSCmdlet.ShouldProcess("Entra ID", "Create session timeout policy: $sessionPolicyName")) {
                            $sessionPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $sessionPolicyParams
                            Write-Host "Created session timeout policy: $sessionPolicyName" -ForegroundColor Green
                            
                            $createdPolicies += $sessionPolicy
                        }
                    }
                    else {
                        $createdPolicies += $sessionPolicyParams
                    }
                    
                    # Risk-based policy (IAL2 implementation) 
                    Write-Host "  Creating risk-based access control policy..." -ForegroundColor Yellow
                    $riskParams = @{
                        PolicyType = 'SignInRisk'
                        PolicyName = if ($PolicyName) { "$PolicyName - Risk Controls" } else { "NIST800-63: Risk-based controls" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $riskParams['DeployPolicy'] = $true
                        $riskParams['PassThru'] = $true
                    }
                    
                    try {
                        $riskPolicy = New-CABestPracticePolicy @riskParams
                        if ($riskPolicy) {
                            $createdPolicies += $riskPolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create risk-based policy: $_"
                    }
                    
                    # Device compliance policy
                    Write-Host "  Creating device assurance policy..." -ForegroundColor Yellow
                    $deviceParams = @{
                        PolicyType = 'DeviceCompliance'
                        PolicyName = if ($PolicyName) { "$PolicyName - Device Assurance" } else { "NIST800-63: Device assurance" }
                        IncludeUsers = $IncludeUsers
                        ExcludeUsers = $ExcludeUsers
                        ExcludeGroups = $ExcludeGroups
                        State = $State
                        Force = $Force
                    }
                    
                    if ($DeployPolicy) {
                        $deviceParams['DeployPolicy'] = $true
                        $deviceParams['PassThru'] = $true
                    }
                    
                    try {
                        $devicePolicy = New-CABestPracticePolicy @deviceParams
                        if ($devicePolicy) {
                            $createdPolicies += $devicePolicy
                        }
                    }
                    catch {
                        Write-Warning "Failed to create device assurance policy: $_"
                    }
                    
                    # Return all created policies
                    return $createdPolicies
                }
            }
        }
        catch {
            Write-Error "Failed to create policy template: $_"
            throw
        }
    }
}
