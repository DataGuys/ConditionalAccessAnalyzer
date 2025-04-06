class CAComplianceScore {
    [string]$Category
    [int]$Score
    [string]$Level
    [string]$Description
    [bool]$IsCriticalItem
    [int]$Weight
    [string]$Status
    
    CAComplianceScore([string]$Category, [int]$Score, [string]$Description, [bool]$IsCriticalItem = $false) {
        $this.Category = $Category
        $this.Score = $Score
        $this.Description = $Description
        $this.IsCriticalItem = $IsCriticalItem
        
        # Set default weight
        $this.Weight = if ($IsCriticalItem) { 2 } else { 1 }
        
        # Calculate level based on score
        $this.Level = $this.GetLevelFromScore($Score)
        
        # Set status based on score
        $this.Status = if ($Score -ge 70) { "PASS" } else { "FAIL" }
    }
    
    # Constructor with weight parameter
    CAComplianceScore([string]$Category, [int]$Score, [string]$Description, [bool]$IsCriticalItem, [int]$Weight) {
        $this.Category = $Category
        $this.Score = $Score
        $this.Description = $Description
        $this.IsCriticalItem = $IsCriticalItem
        $this.Weight = $Weight
        
        # Calculate level based on score
        $this.Level = $this.GetLevelFromScore($Score)
        
        # Set status based on score
        $this.Status = if ($Score -ge 70) { "PASS" } else { "FAIL" }
    }
    
    # Calculate level based on score
    [string] GetLevelFromScore([int]$Score) {
        if ($Score -ge 90) { return "Excellent" }
        elseif ($Score -ge 80) { return "Good" }
        elseif ($Score -ge 70) { return "Fair" }
        elseif ($Score -ge 60) { return "Poor" }
        else { return "Critical" }
    }
    
    # Get color for visualization
    [string] GetColor() {
        switch ($this.Level) {
            "Excellent" { return "Green" }
            "Good" { return "YellowGreen" }
            "Fair" { return "Gold" }
            "Poor" { return "Orange" }
            "Critical" { return "Red" }
            default { return "Gray" }
        }
    }
    
    # Get text color for visualization
    [string] GetTextColor() {
        switch ($this.Level) {
            "Excellent" { return "White" }
            "Good" { return "Black" }
            "Fair" { return "Black" }
            "Poor" { return "White" }
            "Critical" { return "White" }
            default { return "Black" }
        }
    }
    
    # Get weighted score
    [int] GetWeightedScore() {
        return $this.Score * $this.Weight
    }
    
    # Get total possible weighted score
    [int] GetPossibleWeightedScore() {
        return 100 * $this.Weight
    }
    
    # ToString override for display
    [string] ToString() {
        return "$($this.Category): $($this.Score)% - $($this.Level)"
    }
}

class CAComplianceScoreCollection {
    [System.Collections.Generic.List[CAComplianceScore]]$Scores
    [int]$OverallScore
    [string]$OverallLevel
    
    CAComplianceScoreCollection() {
        $this.Scores = New-Object System.Collections.Generic.List[CAComplianceScore]
        $this.OverallScore = 0
        $this.OverallLevel = "Critical"
    }
    
    # Add a score to the collection
    [void] AddScore([CAComplianceScore]$Score) {
        $this.Scores.Add($Score)
        $this.RecalculateOverallScore()
    }
    
    # Add a new score with provided parameters
    [void] AddScore([string]$Category, [int]$Score, [string]$Description, [bool]$IsCriticalItem = $false) {
        $newScore = [CAComplianceScore]::new($Category, $Score, $Description, $IsCriticalItem)
        $this.Scores.Add($newScore)
        $this.RecalculateOverallScore()
    }
    
    # Add a new score with weight
    [void] AddScore([string]$Category, [int]$Score, [string]$Description, [bool]$IsCriticalItem, [int]$Weight) {
        $newScore = [CAComplianceScore]::new($Category, $Score, $Description, $IsCriticalItem, $Weight)
        $this.Scores.Add($newScore)
        $this.RecalculateOverallScore()
    }
    
    # Remove score from collection
    [void] RemoveScore([CAComplianceScore]$Score) {
        $this.Scores.Remove($Score)
        $this.RecalculateOverallScore()
    }
    
    # Remove score by category
    [void] RemoveScoreByCategory([string]$Category) {
        $scoreToRemove = $this.Scores | Where-Object { $_.Category -eq $Category }
        if ($scoreToRemove) {
            $this.Scores.Remove($scoreToRemove)
            $this.RecalculateOverallScore()
        }
    }
    
    # Recalculate overall score
    [void] RecalculateOverallScore() {
        if ($this.Scores.Count -eq 0) {
            $this.OverallScore = 0
            $this.OverallLevel = "Critical"
            return
        }
        
        $totalWeightedScore = 0
        $totalPossibleScore = 0
        
        foreach ($score in $this.Scores) {
            $totalWeightedScore += $score.GetWeightedScore()
            $totalPossibleScore += $score.GetPossibleWeightedScore()
        }
        
        if ($totalPossibleScore -gt 0) {
            $this.OverallScore = [math]::Round(($totalWeightedScore / $totalPossibleScore) * 100)
        }
        else {
            $this.OverallScore = 0
        }
        
        # Set overall level
        $dummyScore = [CAComplianceScore]::new("Overall", $this.OverallScore, "")
        $this.OverallLevel = $dummyScore.Level
    }
    
    # Get scores by level
    [System.Collections.Generic.List[CAComplianceScore]] GetScoresByLevel([string]$Level) {
        return $this.Scores | Where-Object { $_.Level -eq $Level }
    }
    
    # Get scores by status
    [System.Collections.Generic.List[CAComplianceScore]] GetScoresByStatus([string]$Status) {
        return $this.Scores | Where-Object { $_.Status -eq $Status }
    }
    
    # Get critical item scores
    [System.Collections.Generic.List[CAComplianceScore]] GetCriticalItems() {
        return $this.Scores | Where-Object { $_.IsCriticalItem -eq $true }
    }
    
    # Get failed critical items
    [System.Collections.Generic.List[CAComplianceScore]] GetFailedCriticalItems() {
        return $this.Scores | Where-Object { $_.IsCriticalItem -eq $true -and $_.Status -eq "FAIL" }
    }
    
    # Get summary object
    [PSCustomObject] GetSummary() {
        $passedScores = ($this.Scores | Where-Object { $_.Status -eq "PASS" }).Count
        $failedScores = ($this.Scores | Where-Object { $_.Status -eq "FAIL" }).Count
        $criticalItems = ($this.Scores | Where-Object { $_.IsCriticalItem -eq $true }).Count
        $failedCriticalItems = ($this.Scores | Where-Object { $_.IsCriticalItem -eq $true -and $_.Status -eq "FAIL" }).Count
        
        return [PSCustomObject]@{
            TotalScores = $this.Scores.Count
            PassedScores = $passedScores
            FailedScores = $failedScores
            CriticalItems = $criticalItems
            FailedCriticalItems = $failedCriticalItems
            OverallScore = $this.OverallScore
            OverallLevel = $this.OverallLevel
        }
    }
    
    # ToString override for display
    [string] ToString() {
        return "Total Items: $($this.Scores.Count), Overall Score: $($this.OverallScore)% - $($this.OverallLevel)"
    }
}
