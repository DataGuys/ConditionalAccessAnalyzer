function Get-Configuration {
    [CmdletBinding()]
    param()
    
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath "..\config\config.json"
    
    if (-not (Test-Path -Path $configPath)) {
        # Create default configuration if not exists
        $defaultConfig = @{
            OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\ConditionalAccessAnalyzer")
            ExcelOptions = @{
                ShowGridlines = $false
                AutoSize = $true
                FreezeTopRow = $true
                BoldTopRow = $true
                TableStyle = "Medium2"
            }
            PowerPointOptions = @{
                Enabled = $true
                CreateForCurrentPolicies = $true
                CreateForComparison = $true
                TemplatePath = ""
                CompanyLogo = ""
                ShowRecommendations = $true
            }
            BenchmarkOptions = @{
                Enabled = $false
                Path = ""
                CompareWithCurrent = $true
            }
        }
        
        # Create output directory if it doesn't exist
        if (-not (Test-Path -Path $defaultConfig.OutputPath)) {
            New-Item -Path $defaultConfig.OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Create config directory if it doesn't exist
        $configDir = Split-Path -Path $configPath -Parent
        if (-not (Test-Path -Path $configDir)) {
            New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        }
        
        # Save default configuration
        $defaultConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
        
        return $defaultConfig
    }
    else {
        # Load existing configuration
        $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        
        # Ensure output directory exists
        if (-not (Test-Path -Path $config.OutputPath)) {
            New-Item -Path $config.OutputPath -ItemType Directory -Force | Out-Null
        }
        
        return $config
    }
}

Export-ModuleMember -Function Get-Configuration
