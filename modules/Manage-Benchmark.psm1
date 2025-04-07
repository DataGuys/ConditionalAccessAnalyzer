function Save-CABenchmark {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Array]$CAPolicies,
        
        [Parameter(Mandatory = $false)]
        [string]$Path = ""
    )
    
    try {
        $config = Get-Configuration
        
        if ([string]::IsNullOrEmpty($Path)) {
            $timestamp = Get-TimeStamp
            $Path = Join-Path -Path $config.OutputPath -ChildPath "CABenchmark_$timestamp.json"
        }
        
        # Create benchmark object with metadata
        $benchmark = @{
            CreatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TenantId = (Get-MgContext).TenantId
            TenantName = (Get-MgContext).TenantId # Ideally this would be the actual tenant name
            Policies = $CAPolicies
        }
        
        # Save to file
        $benchmark | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding utf8
        
        Write-Host "Benchmark saved to: $Path" -ForegroundColor Green
        
        # Update config to use this benchmark by default
        $config.BenchmarkOptions.Enabled = $true
        $config.BenchmarkOptions.Path = $Path
        
        $configPath = Join-Path -Path $PSScriptRoot -ChildPath "..\config\config.json"
        $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
        
        return $true
    }
    catch {
        Write-Error "Error saving benchmark: $_"
        return $false
    }
}

function Get-CABenchmark {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path = ""
    )
    
    try {
        $config = Get-Configuration
        
        if ([string]::IsNullOrEmpty($Path)) {
            if ([string]::IsNullOrEmpty($config.BenchmarkOptions.Path)) {
                throw "No benchmark file specified in configuration or parameters."
            }
            $Path = $config.BenchmarkOptions.Path
        }
        
        if (-not (Test-Path -Path $Path)) {
            throw "Benchmark file not found: $Path"
        }
        
        $benchmark = Get-Content -Path $Path -Raw | ConvertFrom-Json
        
        return $benchmark.Policies
    }
    catch {
        Write-Error "Error loading benchmark: $_"
        return $null
    }
}

function Compare-CAWithBenchmark {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Array]$CurrentPolicies,
        
        [Parameter(Mandatory = $true)]
        [Array]$BenchmarkPolicies
    )
    
    try {
        $comparison = @{
            NewPolicies = @()
            ModifiedPolicies = @()
            MissingPolicies = @()
            UnchangedPolicies = @()
        }
        
        # Find new policies (in current but not in benchmark)
        $comparison.NewPolicies = $CurrentPolicies | Where-Object { 
            $currentDisplayName = $_.DisplayName
            -not ($BenchmarkPolicies | Where-Object { $_.DisplayName -eq $currentDisplayName })
        }
        
        # Find missing policies (in benchmark but not in current)
        $comparison.MissingPolicies = $BenchmarkPolicies | Where-Object { 
            $benchmarkDisplayName = $_.DisplayName
            -not ($CurrentPolicies | Where-Object { $_.DisplayName -eq $benchmarkDisplayName })
        }
        
        # Find modified and unchanged policies
        foreach ($currentPolicy in $CurrentPolicies) {
            $benchmarkPolicy = $BenchmarkPolicies | Where-Object { $_.DisplayName -eq $currentPolicy.DisplayName }
            
            if ($benchmarkPolicy) {
                $isDifferent = $false
                
                # Compare key properties
                if ($currentPolicy.State -ne $benchmarkPolicy.State) {
                    $isDifferent = $true
                }
                
                # Add more detailed comparisons here
                
                if ($isDifferent) {
                    $comparison.ModifiedPolicies += $currentPolicy
                } else {
                    $comparison.UnchangedPolicies += $currentPolicy
                }
            }
        }
        
        return $comparison
    }
    catch {
        Write-Error "Error comparing policies: $_"
        return $null
    }
}

Export-ModuleMember -Function Save-CABenchmark, Get-CABenchmark, Compare-CAWithBenchmark
