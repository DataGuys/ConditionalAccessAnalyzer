function Connect-CAAnalyzer {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the required permissions for Conditional Access analysis.
    .DESCRIPTION
        Authenticates to Microsoft Graph with the scopes needed to read Conditional Access policies,
        directory roles, users, and device compliance information. Supports multiple authentication
        methods including interactive, certificate-based, and client credentials.
    .PARAMETER AuthMethod
        The authentication method to use. Valid values: 'Interactive', 'CertificateThumbprint', 
        'CertificatePath', 'ClientSecret', 'ManagedIdentity'.
    .PARAMETER TenantId
        The ID of the tenant to connect to. Required for all auth methods except Interactive.
    .PARAMETER ClientId
        The client ID (application ID) to use. Required for CertificateThumbprint, CertificatePath, 
        and ClientSecret auth methods.
    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate to use for authentication. Required for CertificateThumbprint
        auth method.
    .PARAMETER CertificatePath
        The path to the certificate file to use for authentication. Required for CertificatePath
        auth method.
    .PARAMETER CertificatePassword
        The password for the certificate file. Required for CertificatePath auth method if the
        certificate is password-protected.
    .PARAMETER ClientSecret
        The client secret to use for authentication. Required for ClientSecret auth method.
    .PARAMETER Scopes
        Additional scopes to request beyond the required set.
    .PARAMETER National
        Specifies whether to connect to a national cloud. Valid values: 'Commercial', 'USGov', 
        'USGovDoD', 'China', 'Germany'.
    .PARAMETER RetryCount
        The number of times to retry connection attempts. Default is 3.
    .PARAMETER RetryDelaySeconds
        The number of seconds to wait between retry attempts. Default is 5.
    .PARAMETER ShowConnectionDetails
        If specified, connection details are shown after successful authentication.
    .EXAMPLE
        Connect-CAAnalyzer
        Connects using interactive authentication with the default scopes.
    .EXAMPLE
        Connect-CAAnalyzer -AuthMethod CertificateThumbprint -TenantId "00000000-0000-0000-0000-000000000000" -ClientId "11111111-1111-1111-1111-111111111111" -CertificateThumbprint "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
        Connects using certificate thumbprint authentication.
    .EXAMPLE
        Connect-CAAnalyzer -AuthMethod ManagedIdentity -TenantId "00000000-0000-0000-0000-000000000000"
        Connects using managed identity authentication (for Azure environments).
    .EXAMPLE
        Connect-CAAnalyzer -National USGov
        Connects to the US Government cloud environment using interactive authentication.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Interactive', 'CertificateThumbprint', 'CertificatePath', 'ClientSecret', 'ManagedIdentity')]
        [string]$AuthMethod = 'Interactive',
        
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificateThumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificatePath')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ManagedIdentity')]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificateThumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificatePath')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificateThumbprint')]
        [string]$CertificateThumbprint,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'CertificatePath')]
        [string]$CertificatePath,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'CertificatePath')]
        [SecureString]$CertificatePassword,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [SecureString]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Scopes,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Commercial', 'USGov', 'USGovDoD', 'China', 'Germany')]
        [string]$National = 'Commercial',
        
        [Parameter(Mandatory = $false)]
        [int]$RetryCount = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 5,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowConnectionDetails
    )
    
    begin {
        # Set up logging
        Write-Verbose "Starting Connect-CAAnalyzer function with $AuthMethod authentication method"
        
        # Required scopes for Conditional Access analysis
        $requiredScopes = @(
            "Policy.Read.All",
            "Directory.Read.All",
            "DeviceManagementConfiguration.Read.All",
            "DeviceManagementApps.Read.All",
            "IdentityRiskyUser.Read.All"
        )
        
        # Add NetworkAccessPolicy.Read.All if version is 1.0.0 or higher (supports Global Secure Access)
        $moduleVersion = (Get-Module ConditionalAccessAnalyzer).Version
        if ($moduleVersion -and $moduleVersion -ge [Version]"1.0.0") {
            $requiredScopes += "NetworkAccessPolicy.Read.All"
        }
        
        # Add additional scopes
        if ($Scopes) {
            $requiredScopes += $Scopes
        }
        
        # Remove duplicates
        $requiredScopes = $requiredScopes | Select-Object -Unique
        
        # Check for Microsoft Graph modules
        $requiredModules = @(
            'Microsoft.Graph.Authentication'
            'Microsoft.Graph.Identity.SignIns'
            'Microsoft.Graph.Identity.DirectoryManagement'
            'Microsoft.Graph.DeviceManagement'
        )
        
        $missingModules = @()
        foreach ($module in $requiredModules) {
            if (-not (Get-Module -Name $module -ListAvailable)) {
                $missingModules += $module
            }
        }
        
        if ($missingModules.Count -gt 0) {
            Write-Warning "The following required modules are missing: $($missingModules -join ', ')"
            $installMissing = Read-Host "Do you want to install them now? (Y/N)"
            
            if ($installMissing -eq 'Y') {
                foreach ($module in $missingModules) {
                    try {
                        Write-Host "Installing $module..." -ForegroundColor Yellow
                        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                    }
                    catch {
                        Write-Error "Failed to install $module. Error: $_"
                        throw "Required module installation failed. Please install the missing modules manually and try again."
                    }
                }
            }
            else {
                throw "Required modules are missing. Please install them before continuing."
            }
        }
        
        # Set national cloud environment
        $environment = switch ($National) {
            'USGov' { 'USGov' }
            'USGovDoD' { 'USGovDoD' }
            'China' { 'China' }
            'Germany' { 'Germany' }
            default { 'Global' }
        }
    }
    
    process {
        try {
            # Check if already connected
            $context = Get-MgContext -ErrorAction SilentlyContinue
            if ($context) {
                # Verify required permissions
                $missingScopes = @()
                foreach ($scope in $requiredScopes) {
                    if ($context.Scopes -notcontains $scope) {
                        $missingScopes += $scope
                    }
                }
                
                if ($missingScopes.Count -eq 0) {
                    Write-Host "Already connected to Microsoft Graph with required scopes" -ForegroundColor Green
                    if ($ShowConnectionDetails) {
                        Write-Host "Tenant: $($context.TenantId)" -ForegroundColor White
                        Write-Host "Account: $($context.Account)" -ForegroundColor White
                    }
                    return $true
                }
                else {
                    Write-Warning "Current connection is missing required scopes: $($missingScopes -join ', ')"
                    Write-Warning "Reconnecting with all required scopes..."
                    Disconnect-MgGraph -ErrorAction SilentlyContinue
                }
            }
            
            # Configure parameters for Connect-MgGraph
            $connectParams = @{
                Scopes = $requiredScopes
            }
            
            if ($environment -ne 'Global') {
                $connectParams['Environment'] = $environment
            }
            
            # Configure authentication parameters
            switch ($AuthMethod) {
                'Interactive' {
                    # No additional parameters needed for interactive auth
                }
                'CertificateThumbprint' {
                    $connectParams['TenantId'] = $TenantId
                    $connectParams['ClientId'] = $ClientId
                    $connectParams['CertificateThumbprint'] = $CertificateThumbprint
                }
                'CertificatePath' {
                    $connectParams['TenantId'] = $TenantId
                    $connectParams['ClientId'] = $ClientId
                    $connectParams['CertificatePath'] = $CertificatePath
                    
                    if ($CertificatePassword) {
                        $connectParams['CertificatePassword'] = $CertificatePassword
                    }
                }
                'ClientSecret' {
                    $connectParams['TenantId'] = $TenantId
                    $connectParams['ClientId'] = $ClientId
                    $connectParams['ClientSecret'] = $ClientSecret
                }
                'ManagedIdentity' {
                    $connectParams['Identity'] = $true
                    $connectParams['TenantId'] = $TenantId
                }
            }
            
            # Connect with retry logic
            $maxRetries = $RetryCount
            $retryCount = 0
            $connected = $false
            
            while (-not $connected -and $retryCount -lt $maxRetries) {
                try {
                    $retryCount++
                    Write-Host "Connecting to Microsoft Graph (Attempt $retryCount of $maxRetries)..." -ForegroundColor Yellow
                    
                    # Handle different auth types with appropriate error handling
                    if ($AuthMethod -eq 'Interactive' -and $retryCount -gt 1) {
                        # Try device code flow on retry for interactive auth
                        Write-Host "Trying device code authentication..." -ForegroundColor Yellow
                        Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication -ErrorAction Stop
                    } else {
                        Connect-MgGraph @connectParams -ErrorAction Stop
                    }
                    
                    $connected = $true
                }
                catch {
                    if ($retryCount -ge $maxRetries) {
                        throw
                    }
                    
                    if ($_.Exception.Message -like "*interaction required*" -or $_.Exception.Message -like "*consent*") {
                        Write-Warning "Authentication requires interaction. Please sign in when prompted."
                        Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication
                        $connected = $true
                    }
                    else {
                        Write-Warning "Connection attempt $retryCount failed: $_. Retrying in $RetryDelaySeconds seconds..."
                        Start-Sleep -Seconds $RetryDelaySeconds
                    }
                }
            }
            
            # Test connection with a simple API call
            try {
                $testRequest = Get-MgOrganization -ErrorAction Stop
                Write-Verbose "Connection test successful. Organization ID: $($testRequest.Id)"
                
                # Store connection info in module scope for later use
                $Script:CAAnalyzerConnection = @{
                    Connected = $true
                    TenantId = (Get-MgContext).TenantId
                    ConnectedTime = Get-Date
                    AuthMethod = $AuthMethod
                    Environment = $environment
                }
                
                # Show connection details if requested
                if ($ShowConnectionDetails) {
                    $context = Get-MgContext
                    Write-Host "`nConnection Details:" -ForegroundColor Cyan
                    Write-Host "Tenant ID: $($context.TenantId)" -ForegroundColor White
                    Write-Host "Account: $($context.Account)" -ForegroundColor White
                    Write-Host "Auth Mode: $($context.AuthType)" -ForegroundColor White
                    Write-Host "App Name: $($context.AppName)" -ForegroundColor White
                    Write-Host "Environment: $($context.Environment)" -ForegroundColor White
                    Write-Host "Scopes: $($context.Scopes -join ', ')" -ForegroundColor White
                }
                
                Write-Host "Successfully connected to Microsoft Graph with required scopes for CA analysis" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Error "Connection verified but test API call failed: $_"
                
                if ($_.Exception.Message -like "*Authorization_RequestDenied*") {
                    Write-Host "The account does not have sufficient permissions. Please check your role assignments." -ForegroundColor Yellow
                }
                elseif ($_.Exception.Message -like "*Authorization_IdentityNotFound*") {
                    Write-Host "The account was not found in this tenant. Please verify you're using the correct account." -ForegroundColor Yellow
                }
                else {
                    Write-Host "API access issue. Check that your account has the right permissions." -ForegroundColor Yellow
                }
                
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                $Script:CAAnalyzerConnection = $null
                throw "Connection test failed. Please check your permissions and try again."
            }
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph after $RetryCount attempts: $_"
            
            if ($_.Exception.Message -like "*AADSTS50076*" -or $_.Exception.Message -like "*MFA*") {
                Write-Host "Multi-factor authentication is required. Please complete the MFA prompt." -ForegroundColor Yellow
            }
            elseif ($_.Exception.Message -like "*AADSTS65001*") {
                Write-Host "Your account doesn't have permission to consent to the required scopes. Contact your administrator." -ForegroundColor Yellow
            }
            elseif ($_.Exception.Message -like "*AADSTS50020*") {
                Write-Host "The user account doesn't exist in the tenant. Make sure you're using the correct account for this tenant." -ForegroundColor Yellow
            }
            else {
                Write-Host "Authentication error. Try running Connect-MgGraph manually with -UseDeviceAuthentication switch." -ForegroundColor Yellow
            }
            
            $Script:CAAnalyzerConnection = $null
            return $false
        }
    }
    
    end {
        if (-not $connected) {
            Write-Error "Failed to establish connection to Microsoft Graph."
            return $false
        }
    }
}

function Disconnect-CAAnalyzer {
    <#
    .SYNOPSIS
        Disconnects from Microsoft Graph.
    .DESCRIPTION
        Safely disconnects from Microsoft Graph and clears connection information.
    .EXAMPLE
        Disconnect-CAAnalyzer
    #>
    [CmdletBinding()]
    param()
    
    process {
        try {
            Disconnect-MgGraph -ErrorAction Stop
            $Script:CAAnalyzerConnection = $null
            Write-Host "Successfully disconnected from Microsoft Graph" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Failed to disconnect from Microsoft Graph: $_"
            return $false
        }
    }
}

function Test-AdminMFARequired {
    [CmdletBinding()]
    param()
    
    process {
        $adminRoles = Get-AdminRoles -PrivilegedOnly
        $adminRoleIds = $adminRoles.Id
        
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $adminMfaPolicies = $policies | Where-Object {
            ($_.State -eq "enabled") -and
            (Test-PolicyRequiresMFA -Policy $_) -and
            (Test-PolicyTargetsAdmins -Policy $_ -AdminRoleIds $adminRoleIds)
        }
        
        $isCompliant = $adminMfaPolicies.Count -gt 0
        
        return [PSCustomObject]@{
            AdminMFARequired = $isCompliant
            AdminMFAPolicies = $adminMfaPolicies
            Recommendation = if (-not $isCompliant) {
                "Configure Conditional Access policies requiring MFA for all administrative roles"
            } else {
                $null
            }
        }
    }
}

function Test-CAAnalyzerConnection {
    <#
    .SYNOPSIS
        Tests the current Microsoft Graph connection.
    .DESCRIPTION
        Verifies that the connection to Microsoft Graph is active and has the required permissions.
    .EXAMPLE
        Test-CAAnalyzerConnection
    #>
    [CmdletBinding()]
    param()
    
    process {
        try {
            $context = Get-MgContext -ErrorAction Stop
            
            if (-not $context) {
                Write-Warning "Not connected to Microsoft Graph. Use Connect-CAAnalyzer to connect."
                return $false
            }
            
            # Check if connection has required scopes
            $requiredScopes = @(
                "Policy.Read.All",
                "Directory.Read.All",
                "DeviceManagementConfiguration.Read.All",
                "DeviceManagementApps.Read.All",
                "IdentityRiskyUser.Read.All"
            )
            
            $missingScopes = @()
            foreach ($scope in $requiredScopes) {
                if ($context.Scopes -notcontains $scope) {
                    $missingScopes += $scope
                }
            }
            
            if ($missingScopes.Count -gt 0) {
                Write-Warning "Connected to Microsoft Graph but missing required scopes: $($missingScopes -join ', ')"
                return $false
            }
            
            # Test connection with a simple API call
            Get-MgOrganization -ErrorAction Stop
            
            Write-Host "Microsoft Graph connection is active and has the required permissions" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "Connection test failed: $_"
            return $false
        }
    }
}
