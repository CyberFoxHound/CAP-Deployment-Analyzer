#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Reports, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications
<#
.SYNOPSIS
    Enhanced Conditional Access Policies (CAPS) Report-Only Readiness Analysis Script
.DESCRIPTION
    This enhanced script performs comprehensive analysis of Conditional Access Policies with:
    - Definitive readiness assessment for report-only policies
    - Clear "Ready to Enable" indicators with confidence levels
    - Detailed sign-in log analysis with Microsoft's conditional access evaluation results
    - Policy readiness assessment with specific recommendations
    - Coverage gaps identification and reporting
.NOTES
    Author: Enhanced CAPS Analysis Tool
    Version: 3.1
    
    Required Graph Permissions:
    - Policy.Read.All
    - AuditLog.Read.All
    - Directory.Read.All
    - Reports.Read.All
    - User.Read.All
    - Group.Read.All
    - Application.Read.All
#>
# Global variables for enhanced analysis
$Global:EnhancedPolicyAnalysis = @{
    Policies = @()
    SignInData = @()
    PolicyImpactAnalysis = @{}
    CoverageAnalysis = @{}
    ReadinessAssessment = @{}
    Users = @()
    Groups = @()
    Applications = @()
    PolicyProblems = @{}
    ReadinessScores = @{}
    EnableRecommendations = @{}
}
function Write-AnalysisHeader {
    param([string]$Title)
    Write-Host "`n" + "="*90 -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Yellow
    Write-Host "="*90 -ForegroundColor Cyan
}
function Write-AnalysisSection {
    param([string]$Section)
    Write-Host "`n[$Section]" -ForegroundColor Green
    Write-Host "-" * ($Section.Length + 2) -ForegroundColor Green
}
function Test-GraphConnection {
    Write-AnalysisSection "Testing Microsoft Graph Connection"
    
    try {
        $context = Get-MgContext
        if ($null -eq $context) {
            throw "No active Microsoft Graph connection found"
        }
        
        Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "  Tenant ID: $($context.TenantId)" -ForegroundColor Gray
        Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
        
        # Check required permissions
        $requiredScopes = @('Policy.Read.All', 'AuditLog.Read.All', 'Directory.Read.All', 'Reports.Read.All', 'User.Read.All', 'Group.Read.All', 'Application.Read.All')
        $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
        
        if ($missingScopes.Count -gt 0) {
            Write-Host "⚠️  Missing required scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
        }
        
        return $true
    }
    catch {
        Write-Host "✗ Microsoft Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please run: Connect-MgGraph -Scopes 'Policy.Read.All','AuditLog.Read.All','Directory.Read.All','Reports.Read.All','User.Read.All','Group.Read.All','Application.Read.All'" -ForegroundColor Yellow
        return $false
    }
}
function Get-DirectoryObjects {
    Write-AnalysisSection "Retrieving Directory Objects for Coverage Analysis"
    
    try {
        Write-Host "Fetching users..." -ForegroundColor Yellow
        $users = Get-MgUser -All -Property "Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,CreatedDateTime" -PageSize 999
        $Global:EnhancedPolicyAnalysis.Users = $users
        Write-Host "✓ Retrieved $($users.Count) users" -ForegroundColor Green
        
        Write-Host "Fetching groups..." -ForegroundColor Yellow
        $groups = Get-MgGroup -All -Property "Id,DisplayName,GroupTypes,SecurityEnabled,CreatedDateTime" -PageSize 999
        $Global:EnhancedPolicyAnalysis.Groups = $groups
        Write-Host "✓ Retrieved $($groups.Count) groups" -ForegroundColor Green
        
        Write-Host "Fetching applications..." -ForegroundColor Yellow
        $applications = Get-MgApplication -All -Property "Id,AppId,DisplayName,CreatedDateTime" -PageSize 999
        $servicePrincipals = Get-MgServicePrincipal -All -Property "Id,AppId,DisplayName,ServicePrincipalType,CreatedDateTime" -PageSize 999
        $Global:EnhancedPolicyAnalysis.Applications = $applications + $servicePrincipals
        Write-Host "✓ Retrieved $($applications.Count) applications and $($servicePrincipals.Count) service principals" -ForegroundColor Green
        
        return $true
    }
    catch {
        Write-Host "✗ Failed to retrieve directory objects: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
function Get-ConditionalAccessPolicies {
    Write-AnalysisSection "Retrieving Conditional Access Policies"
    
    try {
        Write-Host "Fetching all Conditional Access policies..." -ForegroundColor Yellow
        $policies = Get-MgIdentityConditionalAccessPolicy -All -Property "Id, DisplayName, State, Conditions, CreatedDateTime, ModifiedDateTime"
        
        $Global:EnhancedPolicyAnalysis.Policies = $policies
        
        # Categorize policies
        $enabledPolicies = $policies | Where-Object { $_.State -eq "enabled" }
        $reportOnlyPolicies = $policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
        $disabledPolicies = $policies | Where-Object { $_.State -eq "disabled" }
        
        Write-Host "✓ Policy retrieval complete" -ForegroundColor Green
        Write-Host "  Total Policies: $($policies.Count)" -ForegroundColor Gray
        Write-Host "  Enabled: $($enabledPolicies.Count)" -ForegroundColor Green
        Write-Host "  Report-Only: $($reportOnlyPolicies.Count)" -ForegroundColor Yellow
        Write-Host "  Disabled: $($disabledPolicies.Count)" -ForegroundColor Red
        
        return $policies
    }
    catch {
        Write-Host "✗ Failed to retrieve policies: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}
function Get-SignInLogs {
    param(
        [int]$DaysBack = 30
    )
    
    Write-AnalysisSection "Analyzing Sign-In Logs"
    
    try {
        $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        Write-Host "Retrieving sign-in logs from the last $DaysBack days..." -ForegroundColor Yellow
        Write-Host "Start date: $startDate" -ForegroundColor Gray
        
        # Get sign-in logs with conditional access details
        Write-Host "Retrieving sign-in logs (this may take several minutes for large datasets)..." -ForegroundColor Yellow
        $signInLogs = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate" -All
        
        # Filter out null or empty conditional access policy data
        $validSignInLogs = $signInLogs | Where-Object { 
            $_.AppliedConditionalAccessPolicies -and $_.AppliedConditionalAccessPolicies.Count -gt 0 
        }
        
        Write-Host "✓ Retrieved $($signInLogs.Count) total sign-in events" -ForegroundColor Green
        Write-Host "✓ $($validSignInLogs.Count) events have conditional access policy data" -ForegroundColor Green
        
        $Global:EnhancedPolicyAnalysis.SignInData = $validSignInLogs
        return $validSignInLogs
    }
    catch {
        Write-Host "✗ Failed to retrieve sign-in logs: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Note: Sign-in logs require Azure AD Premium P1 or P2 license" -ForegroundColor Yellow
        return @()
    }
}
function Analyze-PolicyCoverage {
    param(
        [array]$Policies,
        [array]$SignInLogs
    )
    
    Write-AnalysisSection "Analyzing Policy Coverage and Target Assessment"
    
    $coverageAnalysis = @{}
    $policyProblems = @{}
    
    foreach ($policy in $Policies) {
        Write-Host "Analyzing coverage for policy: $($policy.DisplayName)" -ForegroundColor Cyan
        
        $policyId = $policy.Id
        $conditions = $policy.Conditions
        $problems = @()
        
        # Initialize coverage tracking
        $targetedUsers = @()
        $targetedGroups = @()
        $targetedApps = @()
        $actualUsers = @()
        $actualApps = @()
        
        # Analyze user targeting
        if ($conditions.Users) {
            # Include Users
            if ($conditions.Users.IncludeUsers) {
                foreach ($userId in $conditions.Users.IncludeUsers) {
                    if ($userId -eq "All") {
                        $targetedUsers = $Global:EnhancedPolicyAnalysis.Users | Where-Object { $_.AccountEnabled -eq $true }
                    } else {
                        $user = $Global:EnhancedPolicyAnalysis.Users | Where-Object { $_.Id -eq $userId }
                        if ($user) {
                            $targetedUsers += $user
                        } else {
                            $problems += "User ID $userId not found in directory"
                        }
                    }
                }
            }
            
            # Include Groups
            if ($conditions.Users.IncludeGroups) {
                foreach ($groupId in $conditions.Users.IncludeGroups) {
                    $group = $Global:EnhancedPolicyAnalysis.Groups | Where-Object { $_.Id -eq $groupId }
                    if ($group) {
                        $targetedGroups += $group
                        # Get group members (simplified - in reality you'd need to expand group membership)
                        try {
                            $groupMembers = Get-MgGroupMember -GroupId $groupId -All
                            $targetedUsers += $groupMembers | ForEach-Object {
                                $Global:EnhancedPolicyAnalysis.Users | Where-Object { $_.Id -eq $_.Id }
                            }
                        } catch {
                            $problems += "Could not retrieve members for group: $($group.DisplayName)"
                        }
                    } else {
                        $problems += "Group ID $groupId not found in directory"
                    }
                }
            }
            
            # Exclude Users and Groups (subtract from targeted users)
            if ($conditions.Users.ExcludeUsers -or $conditions.Users.ExcludeGroups) {
                $excludedUsers = @()
                
                if ($conditions.Users.ExcludeUsers) {
                    foreach ($userId in $conditions.Users.ExcludeUsers) {
                        $user = $Global:EnhancedPolicyAnalysis.Users | Where-Object { $_.Id -eq $userId }
                        if ($user) {
                            $excludedUsers += $user
                        }
                    }
                }
                
                if ($conditions.Users.ExcludeGroups) {
                    foreach ($groupId in $conditions.Users.ExcludeGroups) {
                        try {
                            $groupMembers = Get-MgGroupMember -GroupId $groupId -All
                            $excludedUsers += $groupMembers | ForEach-Object {
                                $Global:EnhancedPolicyAnalysis.Users | Where-Object { $_.Id -eq $_.Id }
                            }
                        } catch {
                            $problems += "Could not retrieve excluded group members for group ID: $groupId"
                        }
                    }
                }
                
                # Remove excluded users from targeted users
                $targetedUsers = $targetedUsers | Where-Object { $_.Id -notin $excludedUsers.Id }
            }
        }
        
        # Analyze application targeting
        if ($conditions.Applications) {
            if ($conditions.Applications.IncludeApplications) {
                foreach ($appId in $conditions.Applications.IncludeApplications) {
                    if ($appId -eq "All") {
                        $targetedApps = $Global:EnhancedPolicyAnalysis.Applications
                    } else {
                        $app = $Global:EnhancedPolicyAnalysis.Applications | Where-Object { $_.AppId -eq $appId -or $_.Id -eq $appId }
                        if ($app) {
                            $targetedApps += $app
                        } else {
                            $problems += "Application ID $appId not found in directory"
                        }
                    }
                }
            }
        }
        
        # Analyze actual coverage from sign-in logs
        $policySignIns = $SignInLogs | Where-Object {
            $_.AppliedConditionalAccessPolicies | Where-Object { $_.Id -eq $policyId }
        }
        
        if ($policySignIns.Count -gt 0) {
            $actualUsers = $policySignIns | Select-Object -ExpandProperty UserId -Unique
            $actualApps = $policySignIns | Select-Object -ExpandProperty AppId -Unique
            
            # Convert to user objects for comparison
            $actualUserObjects = $actualUsers | ForEach-Object {
                $userId = $_
                $Global:EnhancedPolicyAnalysis.Users | Where-Object { $_.Id -eq $userId }
            } | Where-Object { $_ -ne $null }
            
            # Convert to app objects for comparison
            $actualAppObjects = $actualApps | ForEach-Object {
                $appId = $_
                $Global:EnhancedPolicyAnalysis.Applications | Where-Object { $_.AppId -eq $appId -or $_.Id -eq $appId }
            } | Where-Object { $_ -ne $null }
        } else {
            $actualUserObjects = @()
            $actualAppObjects = @()
            if ($policy.State -eq "enabledForReportingButNotEnforced") {
                $problems += "No sign-in activity found for this report-only policy - cannot assess coverage"
            }
        }
        
        # Calculate coverage percentages
        $userCoveragePercent = 0
        $appCoveragePercent = 0
        $uncoveredUsers = @()
        $uncoveredApps = @()
        
        if ($targetedUsers.Count -gt 0) {
            $coveredUserIds = $actualUserObjects | Select-Object -ExpandProperty Id
            $targetedUserIds = $targetedUsers | Select-Object -ExpandProperty Id
            $coveredCount = ($targetedUserIds | Where-Object { $_ -in $coveredUserIds }).Count
            $userCoveragePercent = [Math]::Round(($coveredCount / $targetedUsers.Count) * 100, 2)
            
            $uncoveredUsers = $targetedUsers | Where-Object { $_.Id -notin $coveredUserIds }
        }
        
        if ($targetedApps.Count -gt 0) {
            $coveredAppIds = $actualAppObjects | Select-Object -ExpandProperty AppId
            $targetedAppIds = $targetedApps | Select-Object -ExpandProperty AppId
            $coveredCount = ($targetedAppIds | Where-Object { $_ -in $coveredAppIds }).Count
            $appCoveragePercent = [Math]::Round(($coveredCount / $targetedApps.Count) * 100, 2)
            
            $uncoveredApps = $targetedApps | Where-Object { $_.AppId -notin $coveredAppIds }
        }
        
        # Check for coverage issues
        if ($userCoveragePercent -lt 50 -and $targetedUsers.Count -gt 0) {
            $problems += "Low user coverage: Only $userCoveragePercent% of targeted users have sign-in activity"
        }
        
        if ($appCoveragePercent -lt 50 -and $targetedApps.Count -gt 0) {
            $problems += "Low app coverage: Only $appCoveragePercent% of targeted applications have sign-in activity"
        }
        
        if ($uncoveredUsers.Count -gt 10) {
            $problems += "$($uncoveredUsers.Count) targeted users have no sign-in activity (potential inactive accounts)"
        }
        
        # Store coverage analysis
        $coverageAnalysis[$policyId] = @{
            PolicyName = $policy.DisplayName
            PolicyState = $policy.State
            TargetedUsersCount = $targetedUsers.Count
            TargetedAppsCount = $targetedApps.Count
            ActualUsersCount = $actualUserObjects.Count
            ActualAppsCount = $actualAppObjects.Count
            UserCoveragePercent = $userCoveragePercent
            AppCoveragePercent = $appCoveragePercent
            UncoveredUsers = $uncoveredUsers
            UncoveredApps = $uncoveredApps
            SignInEvents = $policySignIns.Count
        }
        
        # Store problems
        $policyProblems[$policyId] = @{
            PolicyName = $policy.DisplayName
            Problems = $problems
        }
        
        Write-Host "  ✓ Coverage analysis complete - User: $userCoveragePercent%, App: $appCoveragePercent%" -ForegroundColor Gray
        if ($problems.Count -gt 0) {
            Write-Host "  ⚠️  $($problems.Count) issues identified" -ForegroundColor Yellow
        }
    }
    
    $Global:EnhancedPolicyAnalysis.CoverageAnalysis = $coverageAnalysis
    $Global:EnhancedPolicyAnalysis.PolicyProblems = $policyProblems
    
    Write-Host "✓ Coverage analysis complete for all policies" -ForegroundColor Green
}
function Analyze-DetailedPolicyImpact {
    param(
        [array]$Policies,
        [array]$SignInLogs
    )
    
    Write-AnalysisSection "Analyzing Detailed Policy Impact with Microsoft's CA Evaluation Results"
    
    if ($SignInLogs.Count -eq 0) {
        Write-Host "⚠️  No sign-in logs available for analysis" -ForegroundColor Yellow
        return
    }
    
    $policyImpactData = @{}
    
    # Focus on report-only and enabled policies
    $relevantPolicies = $Policies | Where-Object { $_.State -in @("enabled", "enabledForReportingButNotEnforced") }
    
    foreach ($policy in $relevantPolicies) {
        Write-Host "Analyzing policy impact: $($policy.DisplayName)" -ForegroundColor Cyan
        
        $policyId = $policy.Id
        $policyName = $policy.DisplayName
        $policyState = $policy.State
        $createdDateTime = $policy.CreatedDateTime
        
        # Find sign-ins that were evaluated against this policy
        $affectedSignIns = $SignInLogs | Where-Object {
            $_.AppliedConditionalAccessPolicies | Where-Object { $_.Id -eq $policyId }
        }
        
        if ($affectedSignIns.Count -eq 0) {
            Write-Host "  No sign-ins found for this policy" -ForegroundColor Gray
            continue
        }
        
        # Detailed analysis of Microsoft's conditional access evaluation results
        $successResults = @()
        $failureResults = @()
        $reportOnlyFailureResults = @()
        $reportOnlySuccessResults = @()
        $reportOnlyInterruptedResults = @()
        $notAppliedResults = @()
        $unknownResults = @()
        
        foreach ($signIn in $affectedSignIns) {
            $policyResult = $signIn.AppliedConditionalAccessPolicies | Where-Object { $_.Id -eq $policyId }
            
            if ($policyResult) {
                switch ($policyResult.Result) {
                    "success" { $successResults += $signIn }
                    "failure" { $failureResults += $signIn }
                    "reportOnlyFailure" { $reportOnlyFailureResults += $signIn }
                    "reportOnlySuccess" { $reportOnlySuccessResults += $signIn }
                    "reportOnlyInterrupted" { $reportOnlyInterruptedResults += $signIn }
                    "notApplied" { $notAppliedResults += $signIn }
                    default { $unknownResults += $signIn }
                }
            }
        }
        
        # Calculate readiness metrics
        $totalEvaluations = $affectedSignIns.Count
        $wouldBeBlockedCount = $reportOnlyFailureResults.Count + $reportOnlyInterruptedResults.Count
        $wouldBeBlockedPercent = if ($totalEvaluations -gt 0) { ($wouldBeBlockedCount / $totalEvaluations) * 100 } else { 0 }
        $currentlyBlockedPercent = if ($totalEvaluations -gt 0) { ($failureResults.Count / $totalEvaluations) * 100 } else { 0 }
        
        # Calculate success rate
        $successCount = $successResults.Count + $reportOnlySuccessResults.Count
        $successRate = if ($totalEvaluations -gt 0) { ($successCount / $totalEvaluations) * 100 } else { 0 }
        
        # Calculate time in report-only mode
        $daysInReportOnly = if ($policyState -eq "enabledForReportingButNotEnforced") {
            [Math]::Round(((Get-Date) - (Get-Date $createdDateTime)).TotalDays, 1)
        } else {
            0
        }
        
        # Analyze impact by user type, location, device, etc.
        $impactByUserType = $affectedSignIns | Group-Object {
            if ($_.UserType) { $_.UserType } else { "Unknown" }
        }
        
        $impactByDevice = $affectedSignIns | Group-Object {
            if ($_.DeviceDetail.OperatingSystem) { $_.DeviceDetail.OperatingSystem } else { "Unknown" }
        }
        
        $impactByApp = $affectedSignIns | Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 5
        
        # Store detailed impact analysis
        $policyImpactData[$policyId] = @{
            PolicyName = $policyName
            PolicyState = $policyState
            TotalEvaluations = $totalEvaluations
            
            # Microsoft CA Evaluation Results
            SuccessCount = $successResults.Count
            FailureCount = $failureResults.Count
            ReportOnlyFailureCount = $reportOnlyFailureResults.Count
            ReportOnlySuccessCount = $reportOnlySuccessResults.Count
            ReportOnlyInterruptedCount = $reportOnlyInterruptedResults.Count
            NotAppliedCount = $notAppliedResults.Count
            UnknownResultCount = $unknownResults.Count
            
            # Success Rate Calculation
            TotalSuccessCount = $successCount
            SuccessRate = [Math]::Round($successRate, 2)
            
            # Readiness Assessment
            WouldBeBlockedCount = $wouldBeBlockedCount
            WouldBeBlockedPercent = [Math]::Round($wouldBeBlockedPercent, 2)
            CurrentlyBlockedPercent = [Math]::Round($currentlyBlockedPercent, 2)
            DaysInReportOnly = $daysInReportOnly
            
            # Impact Analysis
            AffectedUsers = ($affectedSignIns | Select-Object -ExpandProperty UserId -Unique).Count
            AffectedApps = ($affectedSignIns | Select-Object -ExpandProperty AppId -Unique).Count
            ImpactByUserType = $impactByUserType
            ImpactByDevice = $impactByDevice
            TopAffectedApps = $impactByApp
            
            # Time-based analysis
            DailyBreakdown = $affectedSignIns | Group-Object { (Get-Date $_.CreatedDateTime).Date }
        }
        
        Write-Host "  ✓ Impact analysis complete - $totalEvaluations total, $wouldBeBlockedCount would be blocked ($($wouldBeBlockedPercent.ToString('F2'))%), success rate: $($successRate.ToString('F2'))%" -ForegroundColor Gray
    }
    
    $Global:EnhancedPolicyAnalysis.PolicyImpactAnalysis = $policyImpactData
    Write-Host "✓ Detailed policy impact analysis complete" -ForegroundColor Green
}
function Calculate-ReadinessScore {
    param(
        [hashtable]$ImpactData,
        [hashtable]$CoverageData,
        [array]$Problems
    )
    
    $score = 0
    $maxScore = 100
    $reasons = @()
    
    # Factor 1: Block rate (40 points)
    $blockRate = $ImpactData.WouldBeBlockedPercent
    if ($blockRate -le 1) {
        $score += 40
        $reasons += "Excellent: Block rate ≤ 1% (40/40 points)"
    } elseif ($blockRate -le 3) {
        $score += 30
        $reasons += "Good: Block rate ≤ 3% (30/40 points)"
    } elseif ($blockRate -le 5) {
        $score += 20
        $reasons += "Fair: Block rate ≤ 5% (20/40 points)"
    } elseif ($blockRate -le 10) {
        $score += 10
        $reasons += "Poor: Block rate ≤ 10% (10/40 points)"
    } else {
        $reasons += "Critical: Block rate > 10% (0/40 points)"
    }
    
    # Factor 2: Coverage (30 points)
    $userCoverage = $CoverageData.UserCoveragePercent
    $appCoverage = $CoverageData.AppCoveragePercent
    $avgCoverage = ($userCoverage + $appCoverage) / 2
    
    if ($avgCoverage -ge 90) {
        $score += 30
        $reasons += "Excellent: Average coverage ≥ 90% (30/30 points)"
    } elseif ($avgCoverage -ge 70) {
        $score += 25
        $reasons += "Good: Average coverage ≥ 70% (25/30 points)"
    } elseif ($avgCoverage -ge 50) {
        $score += 15
        $reasons += "Fair: Average coverage ≥ 50% (15/30 points)"
    } else {
        $reasons += "Poor: Average coverage < 50% (0/30 points)"
    }
    
    # Factor 3: Time in report-only (15 points)
    $daysInReportOnly = $ImpactData.DaysInReportOnly
    if ($daysInReportOnly -ge 30) {
        $score += 15
        $reasons += "Excellent: ≥30 days in report-only (15/15 points)"
    } elseif ($daysInReportOnly -ge 14) {
        $score += 10
        $reasons += "Good: ≥14 days in report-only (10/15 points)"
    } elseif ($daysInReportOnly -ge 7) {
        $score += 5
        $reasons += "Fair: ≥7 days in report-only (5/15 points)"
    } else {
        $reasons += "Insufficient: <7 days in report-only (0/15 points)"
    }
    
    # Factor 4: Problems (15 points)
    if ($Problems.Count -eq 0) {
        $score += 15
        $reasons += "Excellent: No identified problems (15/15 points)"
    } elseif ($Problems.Count -le 2) {
        $score += 10
        $reasons += "Good: Minor issues only (10/15 points)"
    } elseif ($Problems.Count -le 5) {
        $score += 5
        $reasons += "Fair: Several issues identified (5/15 points)"
    } else {
        $reasons += "Poor: Multiple critical issues (0/15 points)"
    }
    
    # Determine readiness status
    $readinessStatus = "Not Ready"
    $statusColor = "Red"
    $enableConfidence = "Low"
    
    if ($score -ge 85) {
        $readinessStatus = "Ready to Enable"
        $statusColor = "Green"
        $enableConfidence = "High"
    } elseif ($score -ge 70) {
        $readinessStatus = "Almost Ready"
        $statusColor = "Yellow"
        $enableConfidence = "Medium"
    } elseif ($score -ge 50) {
        $readinessStatus = "Needs Attention"
        $statusColor = "Yellow"
        $enableConfidence = "Low-Medium"
    }
    
    return @{
        Score = $score
        MaxScore = $maxScore
        ReadinessStatus = $readinessStatus
        StatusColor = $statusColor
        EnableConfidence = $enableConfidence
        Reasons = $reasons
    }
}
function Analyze-PolicyReadiness {
    Write-AnalysisSection "Calculating Policy Readiness Scores"
    
    $readinessScores = @{}
    $enableRecommendations = @{}
    
    foreach ($policy in $Global:EnhancedPolicyAnalysis.Policies) {
        if ($policy.State -ne "enabledForReportingButNotEnforced") {
            continue
        }
        
        $policyId = $policy.Id
        $policyName = $policy.DisplayName
        
        Write-Host "Calculating readiness for: $policyName" -ForegroundColor Cyan
        
        # Get impact and coverage data
        $impactData = if ($Global:EnhancedPolicyAnalysis.PolicyImpactAnalysis.ContainsKey($policyId)) {
            $Global:EnhancedPolicyAnalysis.PolicyImpactAnalysis[$policyId]
        } else {
            $null
        }
        
        $coverageData = if ($Global:EnhancedPolicyAnalysis.CoverageAnalysis.ContainsKey($policyId)) {
            $Global:EnhancedPolicyAnalysis.CoverageAnalysis[$policyId]
        } else {
            $null
        }
        
        $problemsData = if ($Global:EnhancedPolicyAnalysis.PolicyProblems.ContainsKey($policyId)) {
            $Global:EnhancedPolicyAnalysis.PolicyProblems[$policyId].Problems
        } else {
            @()
        }
        
        if ($null -eq $impactData -or $null -eq $coverageData) {
            $readinessScores[$policyId] = @{
                Score = 0
                MaxScore = 100
                ReadinessStatus = "Insufficient Data"
                StatusColor = "Red"
                EnableConfidence = "None"
                Reasons = @("Insufficient data for analysis")
            }
            continue
        }
        
        # Calculate readiness score
        $readinessResult = Calculate-ReadinessScore -ImpactData $impactData -CoverageData $coverageData -Problems $problemsData
        $readinessScores[$policyId] = $readinessResult
        
        # Generate enable recommendation
        $enableRecommendations[$policyId] = @{
            PolicyName = $policyName
            ReadinessStatus = $readinessResult.ReadinessStatus
            EnableConfidence = $readinessResult.EnableConfidence
            Recommendation = ""
            Timeline = ""
            NextSteps = @()
        }
        
        # Set recommendation based on readiness
        switch ($readinessResult.ReadinessStatus) {
            "Ready to Enable" {
                $enableRecommendations[$policyId].Recommendation = "Enable immediately"
                $enableRecommendations[$policyId].Timeline = "Within 1 week"
                $enableRecommendations[$policyId].NextSteps = @(
                    "Enable policy during business hours",
                    "Monitor sign-in logs for 48 hours",
                    "Prepare help desk for potential inquiries"
                )
            }
            "Almost Ready" {
                $enableRecommendations[$policyId].Recommendation = "Enable with caution"
                $enableRecommendations[$policyId].Timeline = "Within 2-3 weeks"
                $enableRecommendations[$policyId].NextSteps = @(
                    "Address minor issues first",
                    "Communicate changes to affected users",
                    "Enable during low-usage periods"
                )
            }
            "Needs Attention" {
                $enableRecommendations[$policyId].Recommendation = "Not ready to enable"
                $enableRecommendations[$policyId].Timeline = "4+ weeks"
                $enableRecommendations[$policyId].NextSteps = @(
                    "Review and refine policy conditions",
                    "Address identified problems",
                    "Extend report-only monitoring period"
                )
            }
            "Not Ready" {
                $enableRecommendations[$policyId].Recommendation = "Do not enable"
                $enableRecommendations[$policyId].Timeline = "Indefinite"
                $enableRecommendations[$policyId].NextSteps = @(
                    "Major policy redesign required",
                    "Consider excluding high-risk groups",
                    "Re-evaluate policy scope"
                )
            }
        }
        
        Write-Host "  ✓ Readiness score: $($readinessResult.Score)/$($readinessResult.MaxScore) - $($readinessResult.ReadinessStatus)" -ForegroundColor $readinessResult.StatusColor
    }
    
    $Global:EnhancedPolicyAnalysis.ReadinessScores = $readinessScores
    $Global:EnhancedPolicyAnalysis.EnableRecommendations = $enableRecommendations
    
    Write-Host "✓ Policy readiness analysis complete" -ForegroundColor Green
}
function Show-EnhancedPolicyReport {
    Write-AnalysisHeader "ENHANCED CONDITIONAL ACCESS POLICIES ANALYSIS REPORT"
    
    $policies = $Global:EnhancedPolicyAnalysis.Policies
    $impactData = $Global:EnhancedPolicyAnalysis.PolicyImpactAnalysis
    $coverageData = $Global:EnhancedPolicyAnalysis.CoverageAnalysis
    $problemsData = $Global:EnhancedPolicyAnalysis.PolicyProblems
    $readinessScores = $Global:EnhancedPolicyAnalysis.ReadinessScores
    $enableRecommendations = $Global:EnhancedPolicyAnalysis.EnableRecommendations
    
    if ($policies.Count -eq 0) {
        Write-Host "❌ No policies found to analyze" -ForegroundColor Red
        return
    }
    
    # Report-Only Policies Detailed Analysis
    $reportOnlyPolicies = $policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
    
    Write-Host "`n🧪 REPORT-ONLY POLICIES READINESS ANALYSIS" -ForegroundColor Yellow
    Write-Host "=" * 50 -ForegroundColor Yellow
    
    if ($reportOnlyPolicies.Count -eq 0) {
        Write-Host "❌ No report-only policies found. Consider creating policies in report-only mode first." -ForegroundColor Red
        return
    }
    
    foreach ($policy in $reportOnlyPolicies) {
        $policyId = $policy.Id
        $policyName = $policy.DisplayName
        
        Write-Host "`n📋 POLICY: $policyName" -ForegroundColor White
        Write-Host "=" * ($policyName.Length + 10) -ForegroundColor Gray
        Write-Host "ID: $policyId" -ForegroundColor Gray
        Write-Host "State: REPORT-ONLY" -ForegroundColor Yellow
        
        # Readiness Score and Status
        if ($readinessScores.ContainsKey($policyId)) {
            $readiness = $readinessScores[$policyId]
            Write-Host "`n🎯 READINESS ASSESSMENT:" -ForegroundColor Magenta
            Write-Host "  Status: $($readiness.ReadinessStatus)" -ForegroundColor $readiness.StatusColor
            Write-Host "  Score: $($readiness.Score)/$($readiness.MaxScore)" -ForegroundColor $readiness.StatusColor
            Write-Host "  Enable Confidence: $($readiness.EnableConfidence)" -ForegroundColor $readiness.StatusColor
            
            Write-Host "`n📊 SCORE BREAKDOWN:" -ForegroundColor Cyan
            foreach ($reason in $readiness.Reasons) {
                Write-Host "  • $reason" -ForegroundColor Gray
            }
        }
        
        # Enable Recommendation
        if ($enableRecommendations.ContainsKey($policyId)) {
            $recommendation = $enableRecommendations[$policyId]
            Write-Host "`n💡 ENABLE RECOMMENDATION:" -ForegroundColor Yellow
            Write-Host "  Recommendation: $($recommendation.Recommendation)" -ForegroundColor $readiness.StatusColor
            Write-Host "  Timeline: $($recommendation.Timeline)" -ForegroundColor Gray
            
            Write-Host "`n📋 NEXT STEPS:" -ForegroundColor Cyan
            foreach ($step in $recommendation.NextSteps) {
                Write-Host "  □ $step" -ForegroundColor Gray
            }
        }
        
        # Coverage Analysis
        if ($coverageData.ContainsKey($policyId)) {
            $coverage = $coverageData[$policyId]
            Write-Host "`n📊 COVERAGE ANALYSIS:" -ForegroundColor Cyan
            Write-Host "  • Targeted Users: $($coverage.TargetedUsersCount)" -ForegroundColor Gray
            Write-Host "  • Users with Sign-ins: $($coverage.ActualUsersCount)" -ForegroundColor Gray
            Write-Host "  • User Coverage: $($coverage.UserCoveragePercent)%" -ForegroundColor $(if($coverage.UserCoveragePercent -ge 70) {"Green"} elseif($coverage.UserCoveragePercent -ge 40) {"Yellow"} else {"Red"})
            
            Write-Host "  • Targeted Applications: $($coverage.TargetedAppsCount)" -ForegroundColor Gray
            Write-Host "  • Apps with Sign-ins: $($coverage.ActualAppsCount)" -ForegroundColor Gray
            Write-Host "  • App Coverage: $($coverage.AppCoveragePercent)%" -ForegroundColor $(if($coverage.AppCoveragePercent -ge 70) {"Green"} elseif($coverage.AppCoveragePercent -ge 40) {"Yellow"} else {"Red"})
        }
        
        # Microsoft's Conditional Access Results Analysis
        if ($impactData.ContainsKey($policyId)) {
            $impact = $impactData[$policyId]
            Write-Host "`n🔍 MICROSOFT CA EVALUATION RESULTS:" -ForegroundColor Magenta
            Write-Host "  • Total Evaluations: $($impact.TotalEvaluations)" -ForegroundColor Gray
            Write-Host "  • Would Be Blocked: $($impact.WouldBeBlockedCount) sign-ins ($($impact.WouldBeBlockedPercent)%)" -ForegroundColor $(if($impact.WouldBeBlockedPercent -le 3) {"Green"} elseif($impact.WouldBeBlockedPercent -le 10) {"Yellow"} else {"Red"})
            Write-Host "  • Success Rate: $($impact.SuccessRate)%" -ForegroundColor $(if($impact.SuccessRate -ge 95) {"Green"} elseif($impact.SuccessRate -ge 90) {"Yellow"} else {"Red"})
            Write-Host "  • Days in Report-Only: $($impact.DaysInReportOnly)" -ForegroundColor $(if($impact.DaysInReportOnly -ge 30) {"Green"} elseif($impact.DaysInReportOnly -ge 7) {"Yellow"} else {"Red"})
            
            # Top affected applications
            if ($impact.TopAffectedApps -and $impact.TopAffectedApps.Count -gt 0) {
                Write-Host "`n📱 TOP AFFECTED APPLICATIONS:" -ForegroundColor Blue
                foreach ($app in $impact.TopAffectedApps | Select-Object -First 3) {
                    Write-Host "  • $($app.Name): $($app.Count) sign-ins" -ForegroundColor Gray
                }
            }
        }
        
        # Problems and Issues
        if ($problemsData.ContainsKey($policyId)) {
            $problems = $problemsData[$policyId].Problems
            if ($problems.Count -gt 0) {
                Write-Host "`n⚠️  IDENTIFIED PROBLEMS:" -ForegroundColor Red
                foreach ($problem in $problems) {
                    Write-Host "  ❌ $problem" -ForegroundColor Red
                }
            }
        }
        
        Write-Host "`n" + "-" * 80 -ForegroundColor Gray
    }
}
function Show-PoliciesProblemsReport {
    Write-AnalysisHeader "POLICIES PROBLEMS AND ISSUES REPORT"
    
    $problemsData = $Global:EnhancedPolicyAnalysis.PolicyProblems
    $coverageData = $Global:EnhancedPolicyAnalysis.CoverageAnalysis
    
    Write-Host "`n🚨 CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION" -ForegroundColor Red
    Write-Host "=" * 55 -ForegroundColor Red
    
    $criticalIssuesFound = $false
    
    foreach ($policyId in $problemsData.Keys) {
        $policyProblems = $problemsData[$policyId]
        $policyName = $policyProblems.PolicyName
        $problems = $policyProblems.Problems
        
        if ($problems.Count -gt 0) {
            $criticalIssuesFound = $true
            Write-Host "`n📋 POLICY: $policyName" -ForegroundColor White
            Write-Host "ID: $policyId" -ForegroundColor Gray
            
            foreach ($problem in $problems) {
                Write-Host "  ❌ $problem" -ForegroundColor Red
            }
            
            # Add coverage-specific issues
            if ($coverageData.ContainsKey($policyId)) {
                $coverage = $coverageData[$policyId]
                
                if ($coverage.UserCoveragePercent -lt 30 -and $coverage.TargetedUsersCount -gt 0) {
                    Write-Host "  ⚠️  CRITICAL: Very low user coverage ($($coverage.UserCoveragePercent)%) - Policy may not be working as expected" -ForegroundColor Red
                }
                
                if ($coverage.AppCoveragePercent -lt 30 -and $coverage.TargetedAppsCount -gt 0) {
                    Write-Host "  ⚠️  CRITICAL: Very low app coverage ($($coverage.AppCoveragePercent)%) - Targeted apps may not be in use" -ForegroundColor Red
                }
                
                if ($coverage.SignInEvents -eq 0) {
                    Write-Host "  ❌ CRITICAL: No sign-in events found - Policy is not being evaluated" -ForegroundColor Red
                }
                
                if ($coverage.UncoveredUsers.Count -gt 50) {
                    Write-Host "  ⚠️  WARNING: $($coverage.UncoveredUsers.Count) targeted users have no sign-in activity" -ForegroundColor Yellow
                }
            }
        }
    }
    
    if (-not $criticalIssuesFound) {
        Write-Host "✅ No critical issues found in policy configurations" -ForegroundColor Green
    }
    
    # Coverage Issues Summary
    Write-Host "`n📊 COVERAGE ANALYSIS SUMMARY" -ForegroundColor Blue
    Write-Host "=" * 30 -ForegroundColor Blue
    
    $lowCoveragePolicies = @()
    $noCoveragePolicies = @()
    $goodCoveragePolicies = @()
    
    foreach ($policyId in $coverageData.Keys) {
        $coverage = $coverageData[$policyId]
        $avgCoverage = ($coverage.UserCoveragePercent + $coverage.AppCoveragePercent) / 2
        
        if ($coverage.SignInEvents -eq 0) {
            $noCoveragePolicies += $coverage
        } elseif ($avgCoverage -lt 50) {
            $lowCoveragePolicies += $coverage
        } else {
            $goodCoveragePolicies += $coverage
        }
    }
    
    Write-Host "`n✅ GOOD COVERAGE ($($goodCoveragePolicies.Count) policies):" -ForegroundColor Green
    foreach ($policy in $goodCoveragePolicies) {
        Write-Host "  • $($policy.PolicyName): Users $($policy.UserCoveragePercent)%, Apps $($policy.AppCoveragePercent)%" -ForegroundColor Green
    }
    
    Write-Host "`n⚠️  LOW COVERAGE ($($lowCoveragePolicies.Count) policies):" -ForegroundColor Yellow
    foreach ($policy in $lowCoveragePolicies) {
        Write-Host "  • $($policy.PolicyName): Users $($policy.UserCoveragePercent)%, Apps $($policy.AppCoveragePercent)%" -ForegroundColor Yellow
    }
    
    Write-Host "`n❌ NO COVERAGE ($($noCoveragePolicies.Count) policies):" -ForegroundColor Red
    foreach ($policy in $noCoveragePolicies) {
        Write-Host "  • $($policy.PolicyName): No sign-in activity detected" -ForegroundColor Red
    }
}
function Show-ReadinessMatrix {
    Write-AnalysisHeader "CONDITIONAL ACCESS POLICIES READINESS MATRIX"
    
    $readinessScores = $Global:EnhancedPolicyAnalysis.ReadinessScores
    $coverageData = $Global:EnhancedPolicyAnalysis.CoverageAnalysis
    $policies = $Global:EnhancedPolicyAnalysis.Policies
    
    $reportOnlyPolicies = $policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
    
    if ($reportOnlyPolicies.Count -eq 0) {
        Write-Host "❌ No report-only policies found for readiness assessment" -ForegroundColor Red
        return
    }
    
    # Create readiness matrix
    Write-Host "`n📊 READINESS MATRIX" -ForegroundColor Cyan
    Write-Host "=" * 20 -ForegroundColor Cyan
    
    $readyPolicies = @()
    $almostReadyPolicies = @()
    $needsAttentionPolicies = @()
    $notReadyPolicies = @()
    
    # Headers
    $headerFormat = "{0,-40} {1,-15} {2,-10} {3,-15} {4,-15} {5,-15} {6,-15}"
    Write-Host ($headerFormat -f "Policy Name", "Readiness", "Score", "Success Rate", "Would Block %", "User Coverage", "App Coverage") -ForegroundColor White
    Write-Host ("-" * 130) -ForegroundColor Gray
    
    foreach ($policy in $reportOnlyPolicies) {
        $policyId = $policy.Id
        $policyName = $policy.DisplayName
        
        # Truncate long policy names
        $displayName = if ($policyName.Length -gt 37) { $policyName.Substring(0, 34) + "..." } else { $policyName }
        
        $readinessStatus = "Unknown"
        $score = "N/A"
        $successRate = "N/A"
        $wouldBlockPercent = "N/A"
        $userCoverage = "N/A"
        $appCoverage = "N/A"
        $statusColor = "Gray"
        
        if ($readinessScores.ContainsKey($policyId)) {
            $readiness = $readinessScores[$policyId]
            $readinessStatus = $readiness.ReadinessStatus
            $score = "$($readiness.Score)/$($readiness.MaxScore)"
            $statusColor = $readiness.StatusColor
        }
        
        if ($Global:EnhancedPolicyAnalysis.PolicyImpactAnalysis.ContainsKey($policyId)) {
            $impact = $Global:EnhancedPolicyAnalysis.PolicyImpactAnalysis[$policyId]
            $successRate = "$($impact.SuccessRate)%"
            $wouldBlockPercent = "$($impact.WouldBeBlockedPercent)%"
        }
        
        if ($coverageData.ContainsKey($policyId)) {
            $coverage = $coverageData[$policyId]
            $userCoverage = "$($coverage.UserCoveragePercent)%"
            $appCoverage = "$($coverage.AppCoveragePercent)%"
        }
        
        # Display row
        $rowFormat = "{0,-40} {1,-15} {2,-10} {3,-15} {4,-15} {5,-15} {6,-15}"
        Write-Host ($rowFormat -f $displayName, $readinessStatus, $score, $successRate, $wouldBlockPercent, $userCoverage, $appCoverage) -ForegroundColor $statusColor
        
        # Categorize for summary
        switch ($readinessStatus) {
            "Ready to Enable" { $readyPolicies += $policy }
            "Almost Ready" { $almostReadyPolicies += $policy }
            "Needs Attention" { $needsAttentionPolicies += $policy }
            "Not Ready" { $notReadyPolicies += $policy }
        }
    }
    
    # Summary
    Write-Host "`n📈 READINESS SUMMARY" -ForegroundColor Magenta
    Write-Host "=" * 20 -ForegroundColor Magenta
    Write-Host "Ready to Enable: $($readyPolicies.Count)" -ForegroundColor Green
    Write-Host "Almost Ready: $($almostReadyPolicies.Count)" -ForegroundColor Yellow
    Write-Host "Needs Attention: $($needsAttentionPolicies.Count)" -ForegroundColor Yellow
    Write-Host "Not Ready: $($notReadyPolicies.Count)" -ForegroundColor Red
    
    $totalReadiness = if ($reportOnlyPolicies.Count -gt 0) { 
        [Math]::Round(($readyPolicies.Count / $reportOnlyPolicies.Count) * 100, 2) 
    } else { 0 }
    
    Write-Host "`nOverall Readiness Score: $totalReadiness%" -ForegroundColor $(
        if ($totalReadiness -ge 70) { "Green" }
        elseif ($totalReadiness -ge 40) { "Yellow" }
        else { "Red" }
    )
}
function Show-DetailedRecommendations {
    Write-AnalysisHeader "DETAILED ENFORCEMENT RECOMMENDATIONS"
    
    $readinessScores = $Global:EnhancedPolicyAnalysis.ReadinessScores
    $enableRecommendations = $Global:EnhancedPolicyAnalysis.EnableRecommendations
    $policies = $Global:EnhancedPolicyAnalysis.Policies
    
    $reportOnlyPolicies = $policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
    
    # Categorize policies
    $readyPolicies = @()
    $almostReadyPolicies = @()
    $needsAttentionPolicies = @()
    $notReadyPolicies = @()
    
    foreach ($policy in $reportOnlyPolicies) {
        $policyId = $policy.Id
        if ($readinessScores.ContainsKey($policyId)) {
            $readiness = $readinessScores[$policyId]
            switch ($readiness.ReadinessStatus) {
                "Ready to Enable" { $readyPolicies += $policy }
                "Almost Ready" { $almostReadyPolicies += $policy }
                "Needs Attention" { $needsAttentionPolicies += $policy }
                "Not Ready" { $notReadyPolicies += $policy }
            }
        }
    }
    
    # Immediate Actions (Ready to Enable)
    Write-Host "`n🚀 IMMEDIATE ACTIONS - READY TO ENABLE" -ForegroundColor Green
    Write-Host "=" * 45 -ForegroundColor Green
    
    if ($readyPolicies.Count -gt 0) {
        Write-Host "`n✅ Enable these $($readyPolicies.Count) policies with high confidence:" -ForegroundColor Green
        foreach ($policy in $readyPolicies) {
            $policyId = $policy.Id
            $recommendation = $enableRecommendations[$policyId]
            $readiness = $readinessScores[$policyId]
            
            Write-Host "  • $($policy.DisplayName)" -ForegroundColor White
            Write-Host "    Confidence: $($readiness.EnableConfidence) | Score: $($readiness.Score)/$($readiness.MaxScore)" -ForegroundColor Gray
            Write-Host "    Command: Set-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId '$policyId' -State enabled" -ForegroundColor Cyan
        }
        
        Write-Host "`n📋 Post-enablement monitoring checklist:" -ForegroundColor Yellow
        Write-Host "  □ Monitor sign-in logs for 48 hours after enabling" -ForegroundColor Gray
        Write-Host "  □ Check help desk ticket volume" -ForegroundColor Gray
        Write-Host "  □ Verify no business-critical applications are blocked" -ForegroundColor Gray
        Write-Host "  □ Monitor user complaint channels (email, Teams, etc.)" -ForegroundColor Gray
    } else {
        Write-Host "❌ No policies are ready for immediate enforcement" -ForegroundColor Red
    }
    
    # Short-term Actions (Almost Ready)
    Write-Host "`n⚠️  SHORT-TERM ACTIONS - ALMOST READY" -ForegroundColor Yellow
    Write-Host "=" * 40 -ForegroundColor Yellow
    
    if ($almostReadyPolicies.Count -gt 0) {
        Write-Host "`n🔶 Prepare these $($almostReadyPolicies.Count) policies for enabling:" -ForegroundColor Yellow
        foreach ($policy in $almostReadyPolicies) {
            $policyId = $policy.Id
            $recommendation = $enableRecommendations[$policyId]
            $readiness = $readinessScores[$policyId]
            
            Write-Host "  • $($policy.DisplayName)" -ForegroundColor White
            Write-Host "    Confidence: $($readiness.EnableConfidence) | Score: $($readiness.Score)/$($readiness.MaxScore)" -ForegroundColor Gray
            Write-Host "    Timeline: $($recommendation.Timeline)" -ForegroundColor Gray
            
            Write-Host "    📋 Preparation steps:" -ForegroundColor Cyan
            foreach ($step in $recommendation.NextSteps) {
                Write-Host "      □ $step" -ForegroundColor Gray
            }
        }
    }
    
    # Medium-term Actions (Needs Attention)
    Write-Host "`n🔧 MEDIUM-TERM ACTIONS - NEEDS ATTENTION" -ForegroundColor Magenta
    Write-Host "=" * 50 -ForegroundColor Magenta
    
    if ($needsAttentionPolicies.Count -gt 0) {
        Write-Host "`n🔴 Address these $($needsAttentionPolicies.Count) policies before enabling:" -ForegroundColor Red
        foreach ($policy in $needsAttentionPolicies) {
            $policyId = $policy.Id
            $recommendation = $enableRecommendations[$policyId]
            $readiness = $readinessScores[$policyId]
            
            Write-Host "  • $($policy.DisplayName)" -ForegroundColor White
            Write-Host "    Confidence: $($readiness.EnableConfidence) | Score: $($readiness.Score)/$($readiness.MaxScore)" -ForegroundColor Gray
            Write-Host "    Timeline: $($recommendation.Timeline)" -ForegroundColor Gray
            
            Write-Host "    📋 Required actions:" -ForegroundColor Cyan
            foreach ($step in $recommendation.NextSteps) {
                Write-Host "      □ $step" -ForegroundColor Gray
            }
        }
    }
    
    # Long-term Actions (Not Ready)
    Write-Host "`n📅 LONG-TERM ACTIONS - NOT READY" -ForegroundColor Red
    Write-Host "=" * 35 -ForegroundColor Red
    
    if ($notReadyPolicies.Count -gt 0) {
        Write-Host "`n🚫 Major redesign needed for these $($notReadyPolicies.Count) policies:" -ForegroundColor Red
        foreach ($policy in $notReadyPolicies) {
            $policyId = $policy.Id
            $recommendation = $enableRecommendations[$policyId]
            $readiness = $readinessScores[$policyId]
            
            Write-Host "  • $($policy.DisplayName)" -ForegroundColor White
            Write-Host "    Confidence: $($readiness.EnableConfidence) | Score: $($readiness.Score)/$($readiness.MaxScore)" -ForegroundColor Gray
            Write-Host "    Timeline: $($recommendation.Timeline)" -ForegroundColor Gray
            
            Write-Host "    📋 Major redesign required:" -ForegroundColor Cyan
            foreach ($step in $recommendation.NextSteps) {
                Write-Host "      □ $step" -ForegroundColor Gray
            }
        }
    }
    
    # Overall Strategy
    Write-Host "`n🎯 OVERALL ENFORCEMENT STRATEGY" -ForegroundColor Magenta
    Write-Host "=" * 35 -ForegroundColor Magenta
    
    $totalPolicies = $reportOnlyPolicies.Count
    $readyPercent = if ($totalPolicies -gt 0) { [Math]::Round(($readyPolicies.Count / $totalPolicies) * 100, 2) } else { 0 }
    
    Write-Host "`n📊 Current Status:" -ForegroundColor White
    Write-Host "  • Total Report-Only Policies: $totalPolicies" -ForegroundColor Gray
    Write-Host "  • Ready to Enable: $($readyPolicies.Count) ($readyPercent%)" -ForegroundColor Green
    Write-Host "  • Almost Ready: $($almostReadyPolicies.Count)" -ForegroundColor Yellow
    Write-Host "  • Needs Attention: $($needsAttentionPolicies.Count)" -ForegroundColor Yellow
    Write-Host "  • Not Ready: $($notReadyPolicies.Count)" -ForegroundColor Red
    
    # Strategic recommendations
    if ($readyPercent -ge 70) {
        Write-Host "`n🟢 HIGH READINESS ORGANIZATION" -ForegroundColor Green
        Write-Host "Strategy: Aggressive enforcement timeline" -ForegroundColor Green
        Write-Host "Timeline: Complete enforcement within 4-6 weeks" -ForegroundColor Green
    } elseif ($readyPercent -ge 40) {
        Write-Host "`n🟡 MODERATE READINESS ORGANIZATION" -ForegroundColor Yellow
        Write-Host "Strategy: Phased enforcement approach" -ForegroundColor Yellow
        Write-Host "Timeline: Complete enforcement within 8-12 weeks" -ForegroundColor Yellow
    } else {
        Write-Host "`n🔴 LOW READINESS ORGANIZATION" -ForegroundColor Red
        Write-Host "Strategy: Focus on problem resolution and policy refinement" -ForegroundColor Red
        Write-Host "Timeline: 3-6 months preparation before enforcement" -ForegroundColor Red
    }
    
    # Success metrics to track
    Write-Host "`n📈 SUCCESS METRICS TO MONITOR:" -ForegroundColor Cyan
    Write-Host "  • Sign-in success rate (target: >95%)" -ForegroundColor Gray
    Write-Host "  • Help desk tickets related to access (monitor for spikes)" -ForegroundColor Gray
    Write-Host "  • User compliance with MFA requirements" -ForegroundColor Gray
    Write-Host "  • Business continuity impact assessment" -ForegroundColor Gray
    Write-Host "  • Security incident reduction" -ForegroundColor Gray
}
function Export-EnhancedAnalysisToCSV {
    param(
        [string]$OutputPath = ".\Enhanced_CAPS_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    )
    
    Write-Host "`n📊 Exporting enhanced analysis results to CSV..." -ForegroundColor Cyan
    
    try {
        $exportData = @()
        $impactData = $Global:EnhancedPolicyAnalysis.PolicyImpactAnalysis
        $coverageData = $Global:EnhancedPolicyAnalysis.CoverageAnalysis
        $problemsData = $Global:EnhancedPolicyAnalysis.PolicyProblems
        $readinessScores = $Global:EnhancedPolicyAnalysis.ReadinessScores
        $enableRecommendations = $Global:EnhancedPolicyAnalysis.EnableRecommendations
        
        foreach ($policyId in $impactData.Keys) {
            $impact = $impactData[$policyId]
            $coverage = if ($coverageData.ContainsKey($policyId)) { $coverageData[$policyId] } else { $null }
            $problems = if ($problemsData.ContainsKey($policyId)) { $problemsData[$policyId].Problems -join "; " } else { "" }
            $readiness = if ($readinessScores.ContainsKey($policyId)) { $readinessScores[$policyId] } else { $null }
            $recommendation = if ($enableRecommendations.ContainsKey($policyId)) { $enableRecommendations[$policyId] } else { $null }
            
            $exportData += [PSCustomObject]@{
                PolicyName = $impact.PolicyName
                PolicyState = $impact.PolicyState
                PolicyId = $policyId
                ReadinessStatus = if ($readiness) { $readiness.ReadinessStatus } else { "Unknown" }
                ReadinessScore = if ($readiness) { $readiness.Score } else { 0 }
                MaxReadinessScore = if ($readiness) { $readiness.MaxScore } else { 100 }
                EnableConfidence = if ($readiness) { $readiness.EnableConfidence } else { "None" }
                EnableRecommendation = if ($recommendation) { $recommendation.Recommendation } else { "Unknown" }
                EnableTimeline = if ($recommendation) { $recommendation.Timeline } else { "Unknown" }
                TotalEvaluations = $impact.TotalEvaluations
                WouldBeBlockedCount = $impact.WouldBeBlockedCount
                WouldBeBlockedPercent = $impact.WouldBeBlockedPercent
                CurrentlyBlockedPercent = $impact.CurrentlyBlockedPercent
                SuccessCount = $impact.SuccessCount
                FailureCount = $impact.FailureCount
                ReportOnlyFailureCount = $impact.ReportOnlyFailureCount
                ReportOnlySuccessCount = $impact.ReportOnlySuccessCount
                ReportOnlyInterruptedCount = $impact.ReportOnlyInterruptedCount
                NotAppliedCount = $impact.NotAppliedCount
                TotalSuccessCount = $impact.TotalSuccessCount
                SuccessRate = $impact.SuccessRate
                AffectedUsers = $impact.AffectedUsers
                AffectedApps = $impact.AffectedApps
                DaysInReportOnly = $impact.DaysInReportOnly
                TargetedUsersCount = if ($coverage) { $coverage.TargetedUsersCount } else { "N/A" }
                ActualUsersCount = if ($coverage) { $coverage.ActualUsersCount } else { "N/A" }
                UserCoveragePercent = if ($coverage) { $coverage.UserCoveragePercent } else { "N/A" }
                TargetedAppsCount = if ($coverage) { $coverage.TargetedAppsCount } else { "N/A" }
                ActualAppsCount = if ($coverage) { $coverage.ActualAppsCount } else { "N/A" }
                AppCoveragePercent = if ($coverage) { $coverage.AppCoveragePercent } else { "N/A" }
                IdentifiedProblems = $problems
            }
        }
        
        $exportData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "✅ Enhanced analysis results exported to: $OutputPath" -ForegroundColor Green
        
    }
    catch {
        Write-Host "❌ Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
# Main execution function
function Start-EnhancedCAPSAnalysis {
    param(
        [int]$SignInLogDays = 30
    )
    
    Write-AnalysisHeader "ENHANCED CONDITIONAL ACCESS POLICIES ANALYSIS"
    Write-Host "Comprehensive CAPS readiness analysis with definitive enable recommendations..." -ForegroundColor White
    Write-Host "Analysis Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Sign-in Log Period: Last $SignInLogDays days" -ForegroundColor Gray
    
    # Test connection
    if (-not (Test-GraphConnection)) {
        return
    }
    
    # Get directory objects for coverage analysis
    if (-not (Get-DirectoryObjects)) {
        Write-Host "⚠️  Continuing without full directory data - coverage analysis will be limited" -ForegroundColor Yellow
    }
    
    # Get policies
    $policies = Get-ConditionalAccessPolicies
    if ($policies.Count -eq 0) {
        Write-Host "`n❌ No Conditional Access policies found. Exiting analysis." -ForegroundColor Red
        return
    }
    
    # Get sign-in logs
    $signInLogs = Get-SignInLogs -DaysBack $SignInLogDays
    
    # Perform enhanced analysis
    Analyze-PolicyCoverage -Policies $policies -SignInLogs $signInLogs
    Analyze-DetailedPolicyImpact -Policies $policies -SignInLogs $signInLogs
    Analyze-PolicyReadiness
    
    # Generate comprehensive reports
    Show-EnhancedPolicyReport
    Show-PoliciesProblemsReport
    Show-ReadinessMatrix
    Show-DetailedRecommendations
    
    Write-Host "`n" + "="*90 -ForegroundColor Cyan
    Write-Host "Enhanced CAPS Analysis completed successfully!" -ForegroundColor Green
    Write-Host "Use Export-EnhancedAnalysisToCSV to save results to file." -ForegroundColor Cyan
    Write-Host "="*90 -ForegroundColor Cyan
}
# Execute the enhanced analysis
Start-EnhancedCAPSAnalysis
# Display available functions
Write-Host "`n🛠️  ADDITIONAL FUNCTIONS AVAILABLE:" -ForegroundColor Cyan
Write-Host "• Export-EnhancedAnalysisToCSV -OutputPath '.\enhanced_results.csv'" -ForegroundColor White
Write-Host "• Get-DetailedSignInAnalysis -PolicyId '<policy-id>' -DaysBack 7" -ForegroundColor White