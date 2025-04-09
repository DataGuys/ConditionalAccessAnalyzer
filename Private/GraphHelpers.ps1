# GraphHelpers.ps1 - Helper functions for Microsoft Graph API interactions

function Get-GraphApiVersion {
    <#
    .SYNOPSIS
        Gets the current Microsoft Graph API version in use.
    .DESCRIPTION
        Returns the Microsoft Graph API version that is currently configured.
        Defaults to "v1.0" if not specified.
    .EXAMPLE
        $apiVersion = Get-GraphApiVersion
    #>
    [CmdletBinding()]
    param()
    
    process {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            return $context.ApiVersion
        }
        else {
            return "v1.0"
        }
    }
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Makes a direct request to the Microsoft Graph API.
    .DESCRIPTION
        Wrapper function to send a request to Microsoft Graph API
        with proper error handling and retry logic.
    .PARAMETER Method
        The HTTP method to use for the request (GET, POST, PATCH, DELETE).
    .PARAMETER Uri
        The Microsoft Graph API endpoint URI.
    .PARAMETER Body
        The request body for POST and PATCH requests.
    .PARAMETER Headers
        Additional headers to include in the request.
    .PARAMETER ApiVersion
        The Microsoft Graph API version to use.
    .PARAMETER RetryCount
        The number of times to retry on failure.
    .PARAMETER RetryDelaySeconds
        The number of seconds to wait between retries.
    .EXAMPLE
        $result = Invoke-GraphRequest -Method GET -Uri "/identity/conditionalAccess/policies"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,
        
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Body,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "v1.0",
        
        [Parameter(Mandatory = $false)]
        [int]$RetryCount = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2
    )
    
    process {
        # Ensure URI starts with /
        if (-not $Uri.StartsWith("/")) {
            $Uri = "/$Uri"
        }
        
        # Build full URI
        $fullUri = "https://graph.microsoft.com/$ApiVersion$Uri"
        
        $attempt = 1
        $success = $false
        $result = $null
        
        while (-not $success -and $attempt -le $RetryCount) {
            try {
                $params = @{
                    Method = $Method
                    Uri = $fullUri
                    Authentication = "GraphApplication"
                    ErrorAction = "Stop"
                }
                
                if ($Body) {
                    $params["Body"] = $Body | ConvertTo-Json -Depth 20
                    $params["ContentType"] = "application/json"
                }
                
                if ($Headers) {
                    $params["Headers"] = $Headers
                }
                
                Write-Verbose "Making Graph API request ($attempt of $RetryCount): $Method $Uri"
                $response = Invoke-MgGraphRequest @params
                
                $success = $true
                $result = $response
            }
            catch {
                if ($attempt -ge $RetryCount) {
                    # Final attempt failed, rethrow
                    Write-Error "Graph API request failed after $RetryCount attempts: $_"
                    throw
                }
                else {
                    # Log the failure and retry
                    Write-Warning "Graph API request attempt $attempt failed: $_. Retrying in $RetryDelaySeconds seconds..."
                    Start-Sleep -Seconds $RetryDelaySeconds
                    $attempt++
                }
            }
        }
        
        return $result
    }
}

function Test-GraphPermission {
    <#
    .SYNOPSIS
        Tests if the current Graph connection has the specified permission.
    .DESCRIPTION
        Verifies that the current Microsoft Graph API connection has
        the specified permission scope.
    .PARAMETER Permission
        The permission to check for.
    .EXAMPLE
        if (Test-GraphPermission -Permission "Policy.Read.All") {
            # Proceed with policy reading operation
        }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Permission
    )
    
    process {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            Write-Warning "Not connected to Microsoft Graph. Use Connect-CAAnalyzer first."
            return $false
        }
        
        return $context.Scopes -contains $Permission
    }
}

function Get-BatchRequestChunks {
    <#
    .SYNOPSIS
        Splits a large collection into chunks for batch processing.
    .DESCRIPTION
        Microsoft Graph batch requests are limited to 20 requests per batch.
        This function helps split larger collections into appropriately sized chunks.
    .PARAMETER Collection
        The collection to split into chunks.
    .PARAMETER ChunkSize
        The maximum size of each chunk.
    .EXAMPLE
        $userChunks = Get-BatchRequestChunks -Collection $userIds -ChunkSize 20
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Collection,
        
        [Parameter(Mandatory = $false)]
        [int]$ChunkSize = 20
    )
    
    process {
        $chunks = @()
        $totalItems = $Collection.Count
        
        for ($i = 0; $i -lt $totalItems; $i += $ChunkSize) {
            $end = [Math]::Min($i + $ChunkSize - 1, $totalItems - 1)
            $chunk = $Collection[$i..$end]
            $chunks += ,$chunk
        }
        
        return $chunks
    }
}

function Invoke-GraphBatchRequest {
    <#
    .SYNOPSIS
        Executes a batch request to Microsoft Graph API.
    .DESCRIPTION
        Creates and sends a batch request to Microsoft Graph API,
        allowing multiple operations in a single HTTP request.
    .PARAMETER Requests
        Array of request objects, each containing Method, Url, Id, and optionally Body.
    .PARAMETER ApiVersion
        The Microsoft Graph API version to use.
    .EXAMPLE
        $requests = @(
            @{
                Method = "GET"
                Url = "/users/user1@contoso.com"
                Id = "1"
            },
            @{
                Method = "GET"
                Url = "/users/user2@contoso.com"
                Id = "2"
            }
        )
        $results = Invoke-GraphBatchRequest -Requests $requests
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Requests,
        
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "v1.0"
    )
    
    process {
        if ($Requests.Count -gt 20) {
            throw "Batch requests are limited to 20 requests per batch."
        }
        
        $batchRequestBody = @{
            requests = $Requests
        }
        
        try {
            $response = Invoke-GraphRequest -Method POST -Uri "/$BatchRequest" -Body $batchRequestBody -ApiVersion $ApiVersion
            return $response.responses
        }
        catch {
            Write-Error "Batch request failed: $_"
            throw
        }
    }
}
