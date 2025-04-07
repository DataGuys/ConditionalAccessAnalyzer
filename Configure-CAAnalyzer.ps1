# Import configuration module
Import-Module -Name "./modules/Get-Configuration.psm1" -Force

function Show-Menu {
    Clear-Host
    Write-Host "Conditional Access Analyzer - Configuration Utility" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host
    Write-Host "1. View Current Configuration"
    Write-Host "2. Set Output Path"
    Write-Host "3. Configure Excel Options"
    Write-Host "4. Configure PowerPoint Options"
    Write-Host "5. Configure Benchmark Options"
    Write-Host "6. Reset to Default Configuration"
    Write-Host "Q. Quit"
    Write-Host
}

function View-Configuration {
    $config = Get-Configuration
    
    Clear-Host
    Write-Host "Current Configuration" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host
    
    Write-Host "Output Path: $($config.OutputPath)" -ForegroundColor Yellow
    
    Write-Host "`nExcel Options:" -ForegroundColor Green
    $config.ExcelOptions.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Value)"
    }
    
    Write-Host "`nPowerPoint Options:" -ForegroundColor Green
    Write-Host "  Enabled: $($config.PowerPointOptions.Enabled)"
    Write-Host "  Create For Current Policies: $($config.PowerPointOptions.CreateForCurrentPolicies)"
    Write-Host "  Create For Comparison: $($config.PowerPointOptions.CreateForComparison)"
    Write-Host "  Template Path: $($config.PowerPointOptions.TemplatePath)"
    Write-Host "  Company Logo: $($config.PowerPointOptions.CompanyLogo)"
    Write-Host "  Show Recommendations: $($config.PowerPointOptions.ShowRecommendations)"
    
    Write-Host "`nBenchmark Options:" -ForegroundColor Green
    Write-Host "  Enabled: $($config.BenchmarkOptions.Enabled)"
    Write-Host "  Path: $($config.BenchmarkOptions.Path)"
    Write-Host "  Compare With Current: $($config.BenchmarkOptions.CompareWithCurrent)"
    
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Set-OutputPath {
    $config = Get-Configuration
    
    Clear-Host
    Write-Host "Set Output Path" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    Write-Host
    
    Write-Host "Current Output Path: $($config.OutputPath)" -ForegroundColor Yellow
    Write-Host
    
    $newPath = Read-Host "Enter new output path (press Enter to keep current)"
    
    if (-not [string]::IsNullOrWhiteSpace($newPath)) {
        try {
            # Create the directory if it doesn't exist
            if (-not (Test-Path -Path $newPath)) {
                New-Item -Path $newPath -ItemType Directory -Force | Out-Null
            }
            
            $config.OutputPath = $newPath
            
            # Save configuration
            $configPath = Join-Path -Path $PSScriptRoot -ChildPath "config\config.json"
            $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
            
            Write-Host "`nOutput path updated successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "`nError updating output path: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Configure-ExcelOptions {
    $config = Get-Configuration
    
    Clear-Host
    Write-Host "Configure Excel Options" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host
    
    Write-Host "Current Excel Options:" -ForegroundColor Yellow
    $config.ExcelOptions.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Value)"
    }
    Write-Host
    
    $config.ExcelOptions.ShowGridlines = (Read-Host "Show gridlines? (true/false)") -eq "true"
    $config.ExcelOptions.AutoSize = (Read-Host "Auto-size columns? (true/false)") -eq "true"
    $config.ExcelOptions.FreezeTopRow = (Read-Host "Freeze top row? (true/false)") -eq "true"
    $config.ExcelOptions.BoldTopRow = (Read-Host "Bold top row? (true/false)") -eq "true"
    
    $tableStyle = Read-Host "Table style (e.g., Medium1, Medium2, Light1, etc.)"
    if (-not [string]::IsNullOrWhiteSpace($tableStyle)) {
        $config.ExcelOptions.TableStyle = $tableStyle
    }
    
    # Save configuration
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath "config\config.json"
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
    
    Write-Host "`nExcel options updated successfully." -ForegroundColor Green
    
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Configure-PowerPointOptions {
    $config = Get-Configuration
    
    Clear-Host
    Write-Host "Configure PowerPoint Options" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host
    
    Write-Host "Current PowerPoint Options:" -ForegroundColor Yellow
    Write-Host "  Enabled: $($config.PowerPointOptions.Enabled)"
    Write-Host "  Create For Current Policies: $($config.PowerPointOptions.CreateForCurrentPolicies)"
    Write-Host "  Create For Comparison: $($config.PowerPointOptions.CreateForComparison)"
    Write-Host "  Template Path: $($config.PowerPointOptions.TemplatePath)"
    Write-Host "  Company Logo: $($config.PowerPointOptions.CompanyLogo)"
    Write-Host "  Show Recommendations: $($config.PowerPointOptions.ShowRecommendations)"
    Write-Host
    
    $config.PowerPointOptions.Enabled = (Read-Host "Enable PowerPoint generation? (true/false)") -eq "true"
    
    if ($config.PowerPointOptions.Enabled) {
        $config.PowerPointOptions.CreateForCurrentPolicies = (Read-Host "Create for current policies? (true/false)") -eq "true"
        $config.PowerPointOptions.CreateForComparison = (Read-Host "Create for comparison with benchmark? (true/false)") -eq "true"
        $config.PowerPointOptions.ShowRecommendations = (Read-Host "Show recommendations? (true/false)") -eq "true"
        
        $templatePath = Read-Host "Template path (leave blank for default)"
        if (-not [string]::IsNullOrWhiteSpace($templatePath)) {
            $config.PowerPointOptions.TemplatePath = $templatePath
        }
        
        $logoPath = Read-Host "Company logo path (leave blank for none)"
        if (-not [string]::IsNullOrWhiteSpace($logoPath)) {
            $config.PowerPointOptions.CompanyLogo = $logoPath
        }
    }
    
    # Save configuration
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath "config\config.json"
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
    
    Write-Host "`nPowerPoint options updated successfully." -ForegroundColor Green
    
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Configure-BenchmarkOptions {
    $config = Get-Configuration
    
    Clear-Host
    Write-Host "Configure Benchmark Options" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host
    
    Write-Host "Current Benchmark Options:" -ForegroundColor Yellow
    Write-Host "  Enabled: $($config.BenchmarkOptions.Enabled)"
    Write-Host "  Path: $($config.BenchmarkOptions.Path)"
    Write-Host "  Compare With Current: $($config.BenchmarkOptions.CompareWithCurrent)"
    Write-Host
    
    $config.BenchmarkOptions.Enabled = (Read-Host "Enable benchmark functionality? (true/false)") -eq "true"
    
    if ($config.BenchmarkOptions.Enabled) {
        $benchmarkPath = Read-Host "Benchmark file path (leave blank to keep current)"
        if (-not [string]::IsNullOrWhiteSpace($benchmarkPath)) {
            $config.BenchmarkOptions.Path = $benchmarkPath
        }
        
        $config.BenchmarkOptions.CompareWithCurrent = (Read-Host "Compare with current policies? (true/false)") -eq "true"
    }
    
    # Save configuration
    $configPath = Join-Path -Path $PSScriptRoot -ChildPath "config\config.json"
    $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding utf8
    
    Write-Host "`nBenchmark options updated successfully." -ForegroundColor Green
    
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Reset-Configuration {
    Clear-Host
    Write-Host "Reset Configuration" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host
    
    $confirm = Read-Host "Are you sure you want to reset to default configuration? (y/n)"
    
    if ($confirm -eq "y") {
        try {
            # Delete existing config file
            $configPath = Join-Path -Path $PSScriptRoot -ChildPath "config\config.json"
            if (Test-Path -Path $configPath) {
                Remove-Item -Path $configPath -Force
            }
            
            # Get default configuration
            $config = Get-Configuration
            
            Write-Host "`nConfiguration reset to defaults successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "`nError resetting configuration: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Main menu loop
$running = $true
while ($running) {
    Show-Menu
    $choice = Read-Host "Enter your choice"
    
    switch ($choice) {
        "1" { View-Configuration }
        "2" { Set-OutputPath }
        "3" { Configure-ExcelOptions }
        "4" { Configure-PowerPointOptions }
        "5" { Configure-BenchmarkOptions }
        "6" { Reset-Configuration }
        "Q" { $running = $false }
        "q" { $running = $false }
        default { 
            Write-Host "`nInvalid choice. Press any key to continue..." -ForegroundColor Red
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
}
