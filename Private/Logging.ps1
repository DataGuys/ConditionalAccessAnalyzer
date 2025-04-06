# Logging.ps1 - Contains functions for module logging

function Initialize-CALogging {
    <#
    .SYNOPSIS
        Initializes the logging system for the module.
    .DESCRIPTION
        Sets up logging configuration for the Conditional Access Analyzer module.
    .PARAMETER LogPath
        The path where log files will be stored.
    .PARAMETER LogLevel
        The level of logging detail.
    .EXAMPLE
        Initialize-CALogging -LogPath "C:\Logs\CAAnalyzer.log" -LogLevel "Verbose"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "$env:TEMP\ConditionalAccessAnalyzer.log",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warning", "Info", "Verbose", "Debug")]
        [string]$LogLevel = "Info"
    )
    
    process {
        # Store logging settings in script variables
        $Script:CAAnalyzerLogPath = $LogPath
        $Script:CAAnalyzerLogLevel = $LogLevel
        
        # Create log directory if it doesn't exist
        $logDir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path -Path $logDir -PathType Container)) {
            try {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                Write-Verbose "Created log directory: $logDir"
            }
            catch {
                Write-Warning "Failed to create log directory: $_"
            }
        }
        
        # Write initial log entry
        Write-CALog -Message "Conditional Access Analyzer logging initialized" -Level "Info"
        Write-CALog -Message "Log level set to: $LogLevel" -Level "Info"
        
        return $true
    }
}

function Write-CALog {
    <#
    .SYNOPSIS
        Writes a message to the module log file.
    .DESCRIPTION
        Records a log message with timestamp and level to the Conditional Access Analyzer log file.
    .PARAMETER Message
        The message to log.
    .PARAMETER Level
        The log level for the message.
    .PARAMETER NoConsole
        If specified, the message will not be written to the console.
    .EXAMPLE
        Write-CALog -Message "Processing policy" -Level "Info"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Error", "Warning", "Info", "Verbose", "Debug")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    
    # Define log levels numeric values
    $logLevels = @{
        "Error" = 1
        "Warning" = 2
        "Info" = 3
        "Verbose" = 4
        "Debug" = 5
    }
    
    # Only log messages at or below the configured log level
    if ($logLevels[$Level] -le $logLevels[$Script:CAAnalyzerLogLevel]) {
        # Format the log message
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        
        # Write to log file
        try {
            Add-Content -Path $Script:CAAnalyzerLogPath -Value $logMessage -ErrorAction SilentlyContinue
        }
        catch {
            # If writing to log file fails, just output to console
            Write-Warning "Failed to write to log file: $_"
        }
        
        # Write to console if not suppressed
        if (-not $NoConsole) {
            $consoleColor = switch ($Level) {
                "Error" { "Red" }
                "Warning" { "Yellow" }
                "Info" { "White" }
                "Verbose" { "Cyan" }
                "Debug" { "Gray" }
                default { "White" }
            }
            
            switch ($Level) {
                "Error" { Write-Error $Message }
                "Warning" { Write-Warning $Message }
                default { Write-Host $Message -ForegroundColor $consoleColor }
            }
        }
    }
}

function Get-CALogs {
    <#
    .SYNOPSIS
        Retrieves the Conditional Access Analyzer logs.
    .DESCRIPTION
        Gets log entries from the Conditional Access Analyzer log file with optional filtering.
    .PARAMETER StartTime
        If specified, only logs after this time will be returned.
    .PARAMETER EndTime
        If specified, only logs before this time will be returned.
    .PARAMETER Level
        If specified, only logs of this level will be returned.
    .PARAMETER Pattern
        If specified, only logs matching this pattern will be returned.
    .PARAMETER TailCount
        If specified, returns only the last N log entries.
    .EXAMPLE
        Get-CALogs -Level "Error" -TailCount 20
    #>
    [CmdletBinding(DefaultParameterSetName = "Filter")]
    param (
        [Parameter(ParameterSetName = "Filter")]
        [datetime]$StartTime,
        
        [Parameter(ParameterSetName = "Filter")]
        [datetime]$EndTime,
        
        [Parameter(ParameterSetName = "Filter")]
        [ValidateSet("Error", "Warning", "Info", "Verbose", "Debug")]
        [string]$Level,
        
        [Parameter(ParameterSetName = "Filter")]
        [string]$Pattern,
        
        [Parameter(ParameterSetName = "Tail")]
        [int]$TailCount = 0
    )
    
    process {
        if (-not (Test-Path -Path $Script:CAAnalyzerLogPath)) {
            Write-Warning "Log file does not exist: $($Script:CAAnalyzerLogPath)"
            return @()
        }
        
        try {
            # Read log file content
            $logContent = if ($TailCount -gt 0) {
                Get-Content -Path $Script:CAAnalyzerLogPath -Tail $TailCount
            }
            else {
                Get-Content -Path $Script:CAAnalyzerLogPath
            }
            
            # Parse log entries
            $logs = @()
            $pattern = '^\[(.*?)\] \[(.*?)\] (.*)$'
            
            foreach ($line in $logContent) {
                if ($line -match $pattern) {
                    $timestamp = [datetime]::ParseExact($matches[1], "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
                    $logLevel = $matches[2]
                    $message = $matches[3]
                    
                    # Apply filters
                    $includeEntry = $true
                    
                    if ($StartTime -and $timestamp -lt $StartTime) {
                        $includeEntry = $false
                    }
                    
                    if ($EndTime -and $timestamp -gt $EndTime) {
                        $includeEntry = $false
                    }
                    
                    if ($Level -and $logLevel -ne $Level) {
                        $includeEntry = $false
                    }
                    
                    if ($Pattern -and $message -notmatch $Pattern) {
                        $includeEntry = $false
                    }
                    
                    if ($includeEntry) {
                        $logs += [PSCustomObject]@{
                            Timestamp = $timestamp
                            Level = $logLevel
                            Message = $message
                        }
                    }
                }
            }
            
            return $logs
        }
        catch {
            Write-Error "Failed to read log file: $_"
            return @()
        }
    }
}

function Clear-CALogs {
    <#
    .SYNOPSIS
        Clears the Conditional Access Analyzer logs.
    .DESCRIPTION
        Clears the content of the Conditional Access Analyzer log file.
    .PARAMETER Confirm
        If specified, no confirmation prompt will be displayed.
    .EXAMPLE
        Clear-CALogs -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param ()
    
    process {
        if (-not (Test-Path -Path $Script:CAAnalyzerLogPath)) {
            Write-Warning "Log file does not exist: $($Script:CAAnalyzerLogPath)"
            return
        }
        
        if ($PSCmdlet.ShouldProcess($Script:CAAnalyzerLogPath, "Clear log file")) {
            try {
                Clear-Content -Path $Script:CAAnalyzerLogPath -Force -ErrorAction Stop
                Write-Host "Log file cleared: $($Script:CAAnalyzerLogPath)" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to clear log file: $_"
            }
        }
    }
}
