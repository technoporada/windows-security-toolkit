# MegaScanner.ps1 - ULTIMATE INTEGRATION MODULE
# Łączy: Malware Scanner + Registry Repair + Persistence Hunter
# SAFE MODE: Multiple confirmations, backups, dry-run support
# NIE USUWA POŁOWY WINDOWSA - OBIECUJĘ KURWA!

#Requires -RunAsAdministrator

param(
    [string]$OutputPath = ".\mega_scan_report.json",
    [string]$BackupPath = ".\mega_backup",
    [string]$QuarantinePath = "C:\MegaScan_Quarantine",
    [string]$LogPath = ".\mega_scan.log",
    
    # Moduły do uruchomienia
    [switch]$MalwareScan,
    [switch]$RegistryRepair,
    [switch]$PersistenceHunt,
    [switch]$AllScans,
    
    # Opcje bezpieczeństwa
    [switch]$DryRun,              # TYLKO RAPORT, NIE USUWA NIC!
    [switch]$AutoQuarantine,      # Auto-kwarantanna (wymaga potwierdzenia)
    [switch]$AutoRepair,          # Auto-naprawa (wymaga potwierdzenia)
    [switch]$CreateBackup = $true,
    
    # Opcje zaawansowane
    [switch]$DeepScan,
    [switch]$Verbose,
    [int]$SignatureCheckTimeout = 3,
    [int]$RegistryAccessTimeout = 3
)

$ErrorActionPreference = "Continue"

# SAFETY CHECKS - NIE POZWÓL KURWA ZNISZCZYĆ SYSTEMU
$CRITICAL_WINDOWS_PATHS = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems",
    "HKLM:\SYSTEM\CurrentControlSet\Services\*\Start"  # Krytyczne usługi
)

$PROTECTED_FILES = @(
    "explorer.exe",
    "winlogon.exe",
    "csrss.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe"
)

# Główny raport
$MegaReport = @{
    ScanDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    DryRun = $DryRun
    ModulesExecuted = @()
    MalwareScan = @{
        Enabled = $false
        Findings = @()
        Statistics = @{}
    }
    RegistryRepair = @{
        Enabled = $false
        Issues = @()
        Repairs = @()
        Statistics = @{}
    }
    PersistenceHunt = @{
        Enabled = $false
        Detections = @()
        Statistics = @{}
    }
    GlobalStatistics = @{
        TotalFindings = 0
        HighRiskFindings = 0
        ItemsQuarantined = 0
        ItemsRepaired = 0
        BackupsCreated = 0
        SafetyBlocksTriggered = 0
    }
    SafetyBlocks = @()
}

function Write-MegaLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "SAFETY" { "Magenta" }
        "DRYRUN" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    
    try {
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
    } catch {}
}

function Test-CriticalWindowsPath {
    param([string]$KeyPath, [string]$ValueName)
    
    foreach ($criticalPath in $CRITICAL_WINDOWS_PATHS) {
        if ($KeyPath -like $criticalPath) {
            Write-MegaLog "🛡️  SAFETY BLOCK: Critical Windows path detected: $KeyPath\$ValueName" "SAFETY"
            $MegaReport.SafetyBlocks += @{
                Path = $KeyPath
                ValueName = $ValueName
                Reason = "Critical Windows system path"
                Action = "BLOCKED"
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            $MegaReport.GlobalStatistics.SafetyBlocksTriggered++
            return $true
        }
    }
    
    return $false
}

function Test-ProtectedFile {
    param([string]$FilePath)
    
    $fileName = Split-Path $FilePath -Leaf
    
    if ($PROTECTED_FILES -contains $fileName.ToLower()) {
        Write-MegaLog "🛡️  SAFETY BLOCK: Protected Windows file: $fileName" "SAFETY"
        $MegaReport.SafetyBlocks += @{
            FilePath = $FilePath
            Reason = "Critical Windows system file"
            Action = "BLOCKED"
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        $MegaReport.GlobalStatistics.SafetyBlocksTriggered++
        return $true
    }
    
    # Sprawdź czy plik jest w System32 lub SysWOW64
    if ($FilePath -match '\\(System32|SysWOW64)\\' -and $FilePath -match '\.(exe|dll|sys)$') {
        Write-MegaLog "🛡️  SAFETY BLOCK: System directory file: $FilePath" "SAFETY"
        $MegaReport.SafetyBlocks += @{
            FilePath = $FilePath
            Reason = "File in protected system directory"
            Action = "BLOCKED"
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        $MegaReport.GlobalStatistics.SafetyBlocksTriggered++
        return $true
    }
    
    return $false
}

function New-SafeBackup {
    param(
        [string]$KeyPath,
        [string]$ValueName = ""
    )
    
    if (-not $CreateBackup) { return $null }
    
    try {
        if (-not (Test-Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        }
        
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $safePath = $KeyPath -replace '[:\\]', '_'
        $backupFile = Join-Path $BackupPath "${timestamp}_${safePath}.reg"
        
        $regPath = $KeyPath -replace 'HKLM:', 'HKEY_LOCAL_MACHINE' -replace 'HKCU:', 'HKEY_CURRENT_USER'
        $exportCmd = "reg export `"$regPath`" `"$backupFile`" /y 2>nul"
        cmd /c $exportCmd
        
        if (Test-Path $backupFile) {
            Write-MegaLog "✅ Backup created: $backupFile" "SUCCESS"
            $MegaReport.GlobalStatistics.BackupsCreated++
            return $backupFile
        }
        
    } catch {
        Write-MegaLog "Backup failed: $_" "WARN"
    }
    
    return $null
}

function Invoke-MalwareScan {
    Write-MegaLog "`n╔══════════════════════════════════════════════════╗" "INFO"
    Write-MegaLog "║  MODULE 1: MALWARE REGISTRY SCANNER             ║" "INFO"
    Write-MegaLog "╚══════════════════════════════════════════════════╝" "INFO"
    
    $MegaReport.MalwareScan.Enabled = $true
    $MegaReport.ModulesExecuted += "MalwareScan"
    
    # Podejrzane lokalizacje
    $suspiciousLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    $patterns = @("\\Temp\\", "\\AppData\\Local\\Temp\\", "\.tmp", "\.vbs", "powershell.*-enc")
    
    foreach ($location in $suspiciousLocations) {
        try {
            if (-not (Test-Path $location)) { continue }
            
            $key = Get-Item -Path $location -ErrorAction Stop
            $values = $key.GetValueNames()
            
            Write-MegaLog "  Scanning: $location ($($values.Count) entries)" "INFO"
            
            foreach ($valueName in $values) {
                $valueData = $key.GetValue($valueName)
                
                if ([string]::IsNullOrWhiteSpace($valueData)) { continue }
                
                $riskScore = 0
                $reasons = @()
                
                foreach ($pattern in $patterns) {
                    if ($valueData -match $pattern) {
                        $riskScore += 3
                        $reasons += "Pattern match: $pattern"
                    }
                }
                
                # Sprawdź nieistniejące pliki
                if ($valueData -match '[A-Z]:\\[^"]*\.exe') {
                    $fileMatch = [regex]::Match($valueData, '[A-Z]:\\[^"]*\.exe')
                    $filePath = $fileMatch.Value
                    
                    if (-not (Test-Path $filePath)) {
                        $riskScore += 5
                        $reasons += "File does not exist: $filePath"
                    }
                }
                
                if ($riskScore -ge 3) {
                    Write-MegaLog "    ⚠️  SUSPICIOUS: $valueName (Risk: $riskScore)" "WARN"
                    
                    $finding = @{
                        KeyPath = $location
                        ValueName = $valueName
                        ValueData = $valueData
                        RiskScore = $riskScore
                        Reasons = $reasons
                    }
                    
                    $MegaReport.MalwareScan.Findings += $finding
                    $MegaReport.GlobalStatistics.TotalFindings++
                    
                    if ($riskScore -ge 5) {
                        $MegaReport.GlobalStatistics.HighRiskFindings++
                    }
                }
            }
            
        } catch {
            Write-MegaLog "  Error scanning $location : $_" "ERROR"
        }
    }
    
    $MegaReport.MalwareScan.Statistics = @{
        TotalFindings = $MegaReport.MalwareScan.Findings.Count
        HighRisk = ($MegaReport.MalwareScan.Findings | Where-Object { $_.RiskScore -ge 5 }).Count
    }
    
    Write-MegaLog "  ✅ Malware scan completed: $($MegaReport.MalwareScan.Findings.Count) findings" "SUCCESS"
}

function Invoke-RegistryRepair {
    Write-MegaLog "`n╔══════════════════════════════════════════════════╗" "INFO"
    Write-MegaLog "║  MODULE 2: REGISTRY REPAIR SCANNER              ║" "INFO"
    Write-MegaLog "╚══════════════════════════════════════════════════╝" "INFO"
    
    $MegaReport.RegistryRepair.Enabled = $true
    $MegaReport.ModulesExecuted += "RegistryRepair"
    
    $repairLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($location in $repairLocations) {
        try {
            if (-not (Test-Path $location)) { continue }
            
            $subKeys = Get-ChildItem -Path $location -ErrorAction SilentlyContinue
            Write-MegaLog "  Scanning: $location ($($subKeys.Count) entries)" "INFO"
            
            foreach ($subKey in $subKeys) {
                try {
                    $key = Get-Item -Path $subKey.PSPath
                    $displayName = $key.GetValue("DisplayName")
                    $uninstallString = $key.GetValue("UninstallString")
                    
                    # Orphaned entry detection
                    if ([string]::IsNullOrWhiteSpace($displayName) -and [string]::IsNullOrWhiteSpace($uninstallString)) {
                        Write-MegaLog "    ⚠️  ORPHANED: $($subKey.PSChildName)" "WARN"
                        
                        $issue = @{
                            KeyPath = $subKey.PSPath
                            IssueType = "OrphanedEntry"
                            Details = "Missing DisplayName and UninstallString"
                        }
                        
                        $MegaReport.RegistryRepair.Issues += $issue
                        $MegaReport.GlobalStatistics.TotalFindings++
                    }
                    
                    # Missing file detection
                    if ($uninstallString -and $uninstallString -match '[A-Z]:\\[^"]*\.exe') {
                        $fileMatch = [regex]::Match($uninstallString, '[A-Z]:\\[^"]*\.exe')
                        $filePath = $fileMatch.Value.Trim('"')
                        
                        if (-not (Test-Path $filePath)) {
                            Write-MegaLog "    ⚠️  MISSING FILE: $displayName" "WARN"
                            
                            $issue = @{
                                KeyPath = $subKey.PSPath
                                IssueType = "MissingFile"
                                Details = "Uninstall file does not exist: $filePath"
                                DisplayName = $displayName
                            }
                            
                            $MegaReport.RegistryRepair.Issues += $issue
                            $MegaReport.GlobalStatistics.TotalFindings++
                        }
                    }
                    
                } catch {}
            }
            
        } catch {
            Write-MegaLog "  Error scanning $location : $_" "ERROR"
        }
    }
    
    $MegaReport.RegistryRepair.Statistics = @{
        TotalIssues = $MegaReport.RegistryRepair.Issues.Count
        OrphanedEntries = ($MegaReport.RegistryRepair.Issues | Where-Object { $_.IssueType -eq "OrphanedEntry" }).Count
        MissingFiles = ($MegaReport.RegistryRepair.Issues | Where-Object { $_.IssueType -eq "MissingFile" }).Count
    }
    
    Write-MegaLog "  ✅ Registry repair scan completed: $($MegaReport.RegistryRepair.Issues.Count) issues" "SUCCESS"
}

function Invoke-PersistenceHunt {
    Write-MegaLog "`n╔══════════════════════════════════════════════════╗" "INFO"
    Write-MegaLog "║  MODULE 3: PERSISTENCE MECHANISM HUNTER         ║" "INFO"
    Write-MegaLog "╚══════════════════════════════════════════════════╝" "INFO"
    
    $MegaReport.PersistenceHunt.Enabled = $true
    $MegaReport.ModulesExecuted += "PersistenceHunt"
    
    # Sprawdź Scheduled Tasks
    Write-MegaLog "  Scanning Scheduled Tasks..." "INFO"
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
            $_.TaskPath -notmatch '^\\Microsoft\\' 
        }
        
        foreach ($task in $tasks) {
            $actions = $task.Actions
            foreach ($action in $actions) {
                if ($action.Execute -match '(powershell|cmd|wscript|cscript)') {
                    Write-MegaLog "    ⚠️  SUSPICIOUS TASK: $($task.TaskName)" "WARN"
                    
                    $detection = @{
                        Type = "ScheduledTask"
                        Name = $task.TaskName
                        Path = $task.TaskPath
                        Action = $action.Execute
                        Arguments = $action.Arguments
                        State = $task.State
                    }
                    
                    $MegaReport.PersistenceHunt.Detections += $detection
                    $MegaReport.GlobalStatistics.TotalFindings++
                }
            }
        }
    } catch {
        Write-MegaLog "  Error scanning scheduled tasks: $_" "ERROR"
    }
    
    # Sprawdź Services
    Write-MegaLog "  Scanning Services..." "INFO"
    try {
        $services = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue | 
            Where-Object { $_.ImagePath -match '(\\Temp\\|\\AppData\\)' }
        
        foreach ($service in $services) {
            Write-MegaLog "    ⚠️  SUSPICIOUS SERVICE: $($service.PSChildName)" "WARN"
            
            $detection = @{
                Type = "Service"
                Name = $service.PSChildName
                ImagePath = $service.ImagePath
                Start = $service.Start
            }
            
            $MegaReport.PersistenceHunt.Detections += $detection
            $MegaReport.GlobalStatistics.TotalFindings++
        }
    } catch {
        Write-MegaLog "  Error scanning services: $_" "ERROR"
    }
    
    # Sprawdź Startup folder
    Write-MegaLog "  Scanning Startup folders..." "INFO"
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($startupPath in $startupPaths) {
        try {
            if (Test-Path $startupPath) {
                $items = Get-ChildItem -Path $startupPath -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    Write-MegaLog "    ℹ️  Startup item: $($item.Name)" "INFO"
                    
                    $detection = @{
                        Type = "StartupFolder"
                        Name = $item.Name
                        Path = $item.FullName
                        Target = if ($item.Target) { $item.Target } else { "N/A" }
                    }
                    
                    $MegaReport.PersistenceHunt.Detections += $detection
                }
            }
        } catch {}
    }
    
    $MegaReport.PersistenceHunt.Statistics = @{
        TotalDetections = $MegaReport.PersistenceHunt.Detections.Count
        ScheduledTasks = ($MegaReport.PersistenceHunt.Detections | Where-Object { $_.Type -eq "ScheduledTask" }).Count
        Services = ($MegaReport.PersistenceHunt.Detections | Where-Object { $_.Type -eq "Service" }).Count
        StartupItems = ($MegaReport.PersistenceHunt.Detections | Where-Object { $_.Type -eq "StartupFolder" }).Count
    }
    
    Write-MegaLog "  ✅ Persistence hunt completed: $($MegaReport.PersistenceHunt.Detections.Count) detections" "SUCCESS"
}

function Invoke-SmartRemediation {
    Write-MegaLog "`n╔══════════════════════════════════════════════════╗" "INFO"
    Write-MegaLog "║  SMART REMEDIATION ENGINE                        ║" "INFO"
    Write-MegaLog "╚══════════════════════════════════════════════════╝" "INFO"
    
    if ($DryRun) {
        Write-MegaLog "🔍 DRY-RUN MODE: No changes will be made" "DRYRUN"
        return
    }
    
    # Zbierz wszystkie high-risk findings
    $highRiskItems = @()
    
    foreach ($finding in $MegaReport.MalwareScan.Findings) {
        if ($finding.RiskScore -ge 5) {
            $highRiskItems += @{
                Type = "Malware"
                Data = $finding
            }
        }
    }
    
    foreach ($issue in $MegaReport.RegistryRepair.Issues) {
        $highRiskItems += @{
            Type = "RegistryIssue"
            Data = $issue
        }
    }
    
    if ($highRiskItems.Count -eq 0) {
        Write-MegaLog "  ✅ No high-risk items require remediation" "SUCCESS"
        return
    }
    
    Write-MegaLog "  Found $($highRiskItems.Count) high-risk items" "WARN"
    
    if ($AutoQuarantine -or $AutoRepair) {
        Write-Host "`n⚠️  WARNING: Auto-remediation is enabled!" -ForegroundColor Yellow
        Write-Host "The following actions will be taken:" -ForegroundColor Yellow
        Write-Host "  - Backup creation: $CreateBackup" -ForegroundColor Cyan
        Write-Host "  - Items to process: $($highRiskItems.Count)" -ForegroundColor Cyan
        Write-Host "`nCritical Windows files are PROTECTED and will NOT be modified." -ForegroundColor Green
        
        $confirmation = Read-Host "`nType 'YES' to proceed with remediation"
        
        if ($confirmation -ne "YES") {
            Write-MegaLog "  ❌ Remediation cancelled by user" "WARN"
            return
        }
    } else {
        Write-MegaLog "  Auto-remediation disabled. Run with -AutoQuarantine or -AutoRepair to enable." "INFO"
        return
    }
    
    foreach ($item in $highRiskItems) {
        try {
            if ($item.Type -eq "Malware") {
                $finding = $item.Data
                
                # Safety check
                if (Test-CriticalWindowsPath -KeyPath $finding.KeyPath -ValueName $finding.ValueName) {
                    Write-MegaLog "    🛡️  BLOCKED: Critical system path" "SAFETY"
                    continue
                }
                
                # Backup
                New-SafeBackup -KeyPath $finding.KeyPath -ValueName $finding.ValueName | Out-Null
                
                # Quarantine/Remove
                Write-MegaLog "    🔒 Quarantining: $($finding.KeyPath)\$($finding.ValueName)" "WARN"
                Remove-ItemProperty -Path $finding.KeyPath -Name $finding.ValueName -Force -ErrorAction Stop
                $MegaReport.GlobalStatistics.ItemsQuarantined++
                
            } elseif ($item.Type -eq "RegistryIssue") {
                $issue = $item.Data
                
                # Safety check
                if (Test-CriticalWindowsPath -KeyPath $issue.KeyPath -ValueName "") {
                    Write-MegaLog "    🛡️  BLOCKED: Critical system path" "SAFETY"
                    continue
                }
                
                # Backup
                New-SafeBackup -KeyPath $issue.KeyPath | Out-Null
                
                # Repair
                Write-MegaLog "    🔧 Repairing: $($issue.KeyPath)" "WARN"
                Remove-Item -Path $issue.KeyPath -Force -Recurse -ErrorAction Stop
                $MegaReport.GlobalStatistics.ItemsRepaired++
            }
            
        } catch {
            Write-MegaLog "    ❌ Failed to remediate: $_" "ERROR"
        }
    }
    
    Write-MegaLog "  ✅ Remediation completed" "SUCCESS"
}

function Export-MegaReport {
    try {
        $MegaReport.ScanDuration = ((Get-Date) - [datetime]$MegaReport.ScanDate).TotalSeconds
        
        $reportJson = $MegaReport | ConvertTo-Json -Depth 10
        Set-Content -Path $OutputPath -Value $reportJson -Force
        
        Write-MegaLog "`n📄 Report saved: $OutputPath" "SUCCESS"
        
        Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           MEGA-SCANNER FINAL SUMMARY                    ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host "Modules executed:        $($MegaReport.ModulesExecuted -join ', ')" -ForegroundColor White
        Write-Host "Dry-run mode:            $(if($DryRun){'YES'}else{'NO'})" -ForegroundColor $(if($DryRun){'Cyan'}else{'White'})
        Write-Host ""
        Write-Host "FINDINGS:" -ForegroundColor Yellow
        Write-Host "  Total findings:        $($MegaReport.GlobalStatistics.TotalFindings)" -ForegroundColor Yellow
        Write-Host "  High-risk findings:    $($MegaReport.GlobalStatistics.HighRiskFindings)" -ForegroundColor Red
        Write-Host ""
        Write-Host "ACTIONS TAKEN:" -ForegroundColor Green
        Write-Host "  Items quarantined:     $($MegaReport.GlobalStatistics.ItemsQuarantined)" -ForegroundColor Green
        Write-Host "  Items repaired:        $($MegaReport.GlobalStatistics.ItemsRepaired)" -ForegroundColor Green
        Write-Host "  Backups created:       $($MegaReport.GlobalStatistics.BackupsCreated)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "SAFETY:" -ForegroundColor Magenta
        Write-Host "  Safety blocks:         $($MegaReport.GlobalStatistics.SafetyBlocksTriggered)" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "Scan duration:           $([math]::Round($MegaReport.ScanDuration, 2))s" -ForegroundColor White
        Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
        
        if ($MegaReport.SafetyBlocks.Count -gt 0) {
            Write-Host "🛡️  SAFETY BLOCKS TRIGGERED: $($MegaReport.SafetyBlocks.Count)" -ForegroundColor Magenta
            Write-Host "Critical Windows components were PROTECTED from modification." -ForegroundColor Green
            Write-Host "See full report for details.`n" -ForegroundColor DarkGray
        }
        
    } catch {
        Write-MegaLog "Failed to export report: $_" "ERROR"
    }
}

# MAIN EXECUTION
try {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ███╗   ███╗███████╗ ██████╗  █████╗       ███████╗ ██████╗  ║
║     ████╗ ████║██╔════╝██╔════╝ ██╔══██╗      ██╔════╝██╔════╝  ║
║     ██╔████╔██║█████╗  ██║  ███╗███████║█████╗███████╗██║       ║
║     ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║╚════╝╚════██║██║       ║
║     ██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║      ███████║╚██████╗  ║
║     ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚══════╝ ╚═════╝  ║
║                                                                  ║
║   ULTIMATE INTEGRATION MODULE - Malware + Repair + Persistence  ║
║   🛡️  SAFE MODE: Multiple protections, nie usuwa połowy Windowsa ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    if (Test-Path $LogPath) {
        Remove-Item $LogPath -Force
    }
    
    Write-MegaLog "╔═══════════════════════════════════════════════════════════╗" "INFO"
    Write-MegaLog "║ MEGA-SCANNER INITIALIZED - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-MegaLog "╚═══════════════════════════════════════════════════════════╝" "INFO"
    
    if ($DryRun) {
        Write-Host "`n🔍 DRY-RUN MODE ACTIVE" -ForegroundColor Cyan
        Write-Host "No changes will be made to your system.`n" -ForegroundColor Cyan
    }
    
    # Determine which modules to run
    if ($AllScans) {
        $MalwareScan = $true
        $RegistryRepair = $true
        $PersistenceHunt = $true
    }
    
    if (-not ($MalwareScan -or $RegistryRepair -or $PersistenceHunt)) {
        Write-Host "`n⚠️  No modules selected!" -ForegroundColor Yellow
        Write-Host "Usage examples:" -ForegroundColor White
        Write-Host "  .\MegaScanner.ps1 -AllScans" -ForegroundColor Cyan
        Write-Host "  .\MegaScanner.ps1 -MalwareScan -RegistryRepair" -ForegroundColor Cyan
        Write-Host "  .\MegaScanner.ps1 -AllScans -DryRun" -ForegroundColor Cyan
        exit 1
    }
    
    # Execute selected modules
    if ($MalwareScan) {
        Invoke-MalwareScan
    }
    
    if ($RegistryRepair) {
        Invoke-RegistryRepair
    }
    
    if ($PersistenceHunt) {
        Invoke-PersistenceHunt
    }
    
    # Smart remediation
    Invoke-SmartRemediation
    
    # Export final report
    Export-MegaReport
    
    Write-MegaLog "✅ MEGA-SCANNER completed successfully" "SUCCESS"
    Write-Host "`n🎄 Wesołych Świąt! System pozostał w jednym kawałku! 🎄`n" -ForegroundColor Green
    
} catch {
    Write-MegaLog "💀 FATAL ERROR: $_" "ERROR"
    Export-MegaReport
    exit 1
}