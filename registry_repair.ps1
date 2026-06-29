# RegistryRepair.ps1 - ENTERPRISE EDITION
# Kompletny moduł skanowania błędów rejestru + automatyczna naprawa
# Wykrywa: broken paths, missing files, orphaned entries, invalid CLSIDs
# Wymaga uprawnień administratora

#Requires -RunAsAdministrator

param(
    [string]$OutputPath = ".\registry_repair_report.json",
    [string]$BackupPath = ".\registry_backup",
    [string]$QuarantinePath = "C:\Quarantine_Registry",
    [string]$VerboseLogPath = ".\registry_repair_verbose.log",
    [switch]$AutoRepair,
    [switch]$CreateBackup = $true,
    [switch]$DeepScan,
    [int]$RegistryAccessTimeout = 3
)

$ErrorActionPreference = "Continue"

# Struktura raportu
$RepairReport = @{
    ScanDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    ScanType = if ($DeepScan) { "Deep" } else { "Quick" }
    AutoRepairEnabled = $AutoRepair
    Issues = @()
    RepairedEntries = @()
    QuarantinedEntries = @()
    BackupFiles = @()
    SkippedKeys = @()
    Statistics = @{
        TotalKeysScanned = 0
        TotalKeysSkipped = 0
        BrokenPathsFound = 0
        MissingFilesFound = 0
        OrphanedEntriesFound = 0
        InvalidCLSIDsFound = 0
        EmptyKeysFound = 0
        IssuesRepaired = 0
        EntriesQuarantined = 0
        BackupsCreated = 0
        AccessDeniedCount = 0
    }
}

# Lokalizacje do skanowania
$ScanLocations = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Classes\CLSID",
    "HKCU:\SOFTWARE\Classes\CLSID",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
    "HKLM:\SOFTWARE\Classes\*\ShellEx\ContextMenuHandlers",
    "HKCU:\SOFTWARE\Classes\*\ShellEx\ContextMenuHandlers"
)

$DeepScanLocations = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
    "HKLM:\SOFTWARE\Classes\TypeLib",
    "HKLM:\SOFTWARE\Classes\Interface",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports"
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "SUCCESS" { "Green" }
            "VERBOSE" { "Cyan" }
            "SKIP" { "DarkGray" }
            "REPAIR" { "Magenta" }
            default { "White" }
        }
    )
    
    try {
        Add-Content -Path $VerboseLogPath -Value $logMessage -ErrorAction SilentlyContinue
    } catch {}
}

function New-RegistryBackup {
    param(
        [string]$KeyPath,
        [string]$ValueName
    )
    
    if (-not $CreateBackup) { return $null }
    
    try {
        if (-not (Test-Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        }
        
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $safePath = $KeyPath -replace '[:\\]', '_'
        $backupFile = Join-Path $BackupPath "${timestamp}_${safePath}_${ValueName}.reg"
        
        # Export klucza rejestru
        $regPath = $KeyPath -replace 'HKLM:', 'HKEY_LOCAL_MACHINE' -replace 'HKCU:', 'HKEY_CURRENT_USER'
        $exportCmd = "reg export `"$regPath`" `"$backupFile`" /y 2>nul"
        cmd /c $exportCmd
        
        if (Test-Path $backupFile) {
            Write-Log "Backup created: $backupFile" "VERBOSE"
            $RepairReport.BackupFiles += @{
                OriginalPath = $KeyPath
                ValueName = $ValueName
                BackupFile = $backupFile
                Timestamp = $timestamp
            }
            $RepairReport.Statistics.BackupsCreated++
            return $backupFile
        }
        
    } catch {
        Write-Log "Backup failed for ${KeyPath}\${ValueName}: $_" "WARN"
    }
    
    return $null
}

function Test-PathExists {
    param([string]$Path)
    
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    
    # Wyodrębnij ścieżki plików
    $pathPattern = '([A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)'
    $matches = [regex]::Matches($Path, $pathPattern)
    
    foreach ($match in $matches) {
        $filePath = $match.Value.Trim('"')
        
        # Pomiń zmienne środowiskowe
        if ($filePath -match '%.*%') {
            $expandedPath = [System.Environment]::ExpandEnvironmentVariables($filePath)
            if (Test-Path $expandedPath) { return $true }
        } elseif (Test-Path $filePath) {
            return $true
        } else {
            return $false
        }
    }
    
    return $true
}

function Test-CLSIDValid {
    param([string]$CLSID)
    
    if ($CLSID -notmatch '\{[A-F0-9]{8}-([A-F0-9]{4}-){3}[A-F0-9]{12}\}') {
        return $false
    }
    
    # Sprawdź czy CLSID istnieje w HKCR
    $clsidPath = "Registry::HKEY_CLASSES_ROOT\CLSID\$CLSID"
    return (Test-Path $clsidPath)
}

function Invoke-QuarantineRegistryEntry {
    param(
        [string]$KeyPath,
        [string]$ValueName,
        [string]$ValueData,
        [string]$Reason
    )
    
    try {
        if (-not (Test-Path $QuarantinePath)) {
            New-Item -ItemType Directory -Path $QuarantinePath -Force | Out-Null
        }
        
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $safePath = $KeyPath -replace '[:\\]', '_'
        $quarantineFile = Join-Path $QuarantinePath "${timestamp}_${safePath}_${ValueName}.json"
        
        $quarantineData = @{
            OriginalKeyPath = $KeyPath
            ValueName = $ValueName
            ValueData = $ValueData
            Reason = $Reason
            QuarantineDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            BackupFile = (New-RegistryBackup -KeyPath $KeyPath -ValueName $ValueName)
        }
        
        $quarantineData | ConvertTo-Json -Depth 5 | Set-Content -Path $quarantineFile
        
        Write-Log "Entry quarantined: ${KeyPath}\${ValueName}" "SUCCESS"
        
        $RepairReport.QuarantinedEntries += $quarantineData
        $RepairReport.Statistics.EntriesQuarantined++
        
        return $true
        
    } catch {
        Write-Log "Quarantine failed: ${KeyPath}\${ValueName} - $_" "ERROR"
        return $false
    }
}

function Repair-RegistryEntry {
    param(
        [string]$KeyPath,
        [string]$ValueName,
        [string]$IssueType,
        [string]$Details
    )
    
    if (-not $AutoRepair) {
        Write-Log "Auto-repair disabled - skipping repair for ${KeyPath}\${ValueName}" "VERBOSE"
        return $false
    }
    
    try {
        Write-Log "REPAIRING: ${KeyPath}\${ValueName} (Type: $IssueType)" "REPAIR"
        
        # Backup przed naprawą
        New-RegistryBackup -KeyPath $KeyPath -ValueName $ValueName | Out-Null
        
        $key = Get-Item -Path $KeyPath -ErrorAction Stop
        
        switch ($IssueType) {
            "BrokenPath" {
                # Usuń wartość z błędną ścieżką
                Remove-ItemProperty -Path $KeyPath -Name $ValueName -Force -ErrorAction Stop
                Write-Log "  └─ Removed broken path entry" "SUCCESS"
            }
            
            "MissingFile" {
                # Usuń wartość wskazującą na nieistniejący plik
                Remove-ItemProperty -Path $KeyPath -Name $ValueName -Force -ErrorAction Stop
                Write-Log "  └─ Removed missing file reference" "SUCCESS"
            }
            
            "OrphanedEntry" {
                # Usuń osierocony wpis
                Remove-ItemProperty -Path $KeyPath -Name $ValueName -Force -ErrorAction Stop
                Write-Log "  └─ Removed orphaned entry" "SUCCESS"
            }
            
            "InvalidCLSID" {
                # Usuń nieprawidłowy CLSID
                Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction Stop
                Write-Log "  └─ Removed invalid CLSID key" "SUCCESS"
            }
            
            "EmptyKey" {
                # Usuń pusty klucz
                Remove-Item -Path $KeyPath -Force -ErrorAction Stop
                Write-Log "  └─ Removed empty registry key" "SUCCESS"
            }
        }
        
        $RepairReport.RepairedEntries += @{
            KeyPath = $KeyPath
            ValueName = $ValueName
            IssueType = $IssueType
            Details = $Details
            RepairDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        $RepairReport.Statistics.IssuesRepaired++
        return $true
        
    } catch [System.Security.SecurityException] {
        Write-Log "  └─ REPAIR FAILED: Access Denied (Security)" "ERROR"
        return $false
    } catch [System.UnauthorizedAccessException] {
        Write-Log "  └─ REPAIR FAILED: Access Denied (Unauthorized)" "ERROR"
        return $false
    } catch {
        Write-Log "  └─ REPAIR FAILED: $_" "ERROR"
        return $false
    }
}

function Scan-RegistryKey {
    param([string]$KeyPath)
    
    $keyName = Split-Path $KeyPath -Leaf
    Write-Log "═══ SCANNING: $keyName" "VERBOSE"
    
    $RepairReport.Statistics.TotalKeysScanned++
    
    try {
        # Timeout dla dostępu
        $timeoutJob = Start-Job -ScriptBlock {
            param($path)
            Test-Path $path
        } -ArgumentList $KeyPath
        
        $completed = Wait-Job -Job $timeoutJob -Timeout $RegistryAccessTimeout
        
        if (-not $completed) {
            Stop-Job -Job $timeoutJob
            Remove-Job -Job $timeoutJob -Force
            $RepairReport.Statistics.TotalKeysSkipped++
            Write-Log "SKIPPED (Timeout): $KeyPath" "SKIP"
            $RepairReport.SkippedKeys += @{
                Path = $KeyPath
                Reason = "Registry access timeout"
            }
            return
        }
        
        $exists = Receive-Job -Job $timeoutJob
        Remove-Job -Job $timeoutJob -Force
        
        if (-not $exists) {
            Write-Log "SKIPPED (Does not exist): $KeyPath" "SKIP"
            return
        }
        
        $key = Get-Item -Path $KeyPath -ErrorAction Stop
        $values = $key.GetValueNames()
        
        Write-Log "  ├─ Analyzing $($values.Count) values" "VERBOSE"
        
        # Sprawdź czy klucz jest pusty (bez wartości i podkluczy)
        $subKeys = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue
        if ($values.Count -eq 0 -and $subKeys.Count -eq 0) {
            Write-Log "  └─ ⚠️  EMPTY KEY detected" "WARN"
            
            $issue = @{
                KeyPath = $KeyPath
                ValueName = "(Empty Key)"
                IssueType = "EmptyKey"
                Severity = "Low"
                Details = "Registry key has no values or subkeys"
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            $RepairReport.Issues += $issue
            $RepairReport.Statistics.EmptyKeysFound++
            
            if ($AutoRepair) {
                Repair-RegistryEntry -KeyPath $KeyPath -ValueName "" -IssueType "EmptyKey" -Details $issue.Details
            }
            
            return
        }
        
        foreach ($valueName in $values) {
            try {
                $valueData = $key.GetValue($valueName)
                
                if ([string]::IsNullOrWhiteSpace($valueData)) {
                    Write-Log "  ├─ Skipping empty value: $valueName" "VERBOSE"
                    continue
                }
                
                Write-Log "  ├─ Checking: $valueName" "VERBOSE"
                
                $issueFound = $false
                $issueType = ""
                $issueDetails = ""
                $severity = "Medium"
                
                # Sprawdź CLSID
                if ($KeyPath -match '\\CLSID\\' -and $valueName -eq "(Default)") {
                    $clsidMatch = [regex]::Match($KeyPath, '\{[A-F0-9-]+\}')
                    if ($clsidMatch.Success) {
                        if (-not (Test-CLSIDValid -CLSID $clsidMatch.Value)) {
                            $issueFound = $true
                            $issueType = "InvalidCLSID"
                            $issueDetails = "CLSID does not exist in HKCR: $($clsidMatch.Value)"
                            $severity = "High"
                            Write-Log "  └─ ⚠️  INVALID CLSID: $($clsidMatch.Value)" "WARN"
                            $RepairReport.Statistics.InvalidCLSIDsFound++
                        }
                    }
                }
                
                # Sprawdź ścieżki plików
                if ($valueData -match '[A-Z]:\\') {
                    if (-not (Test-PathExists -Path $valueData)) {
                        $issueFound = $true
                        $issueType = "MissingFile"
                        $issueDetails = "Referenced file does not exist: $valueData"
                        $severity = "High"
                        Write-Log "  └─ ⚠️  MISSING FILE: $valueData" "WARN"
                        $RepairReport.Statistics.MissingFilesFound++
                    }
                }
                
                # Sprawdź osierocone wpisy uninstall
                if ($KeyPath -match '\\Uninstall\\') {
                    $displayName = $key.GetValue("DisplayName")
                    $uninstallString = $key.GetValue("UninstallString")
                    
                    if ([string]::IsNullOrWhiteSpace($displayName) -and [string]::IsNullOrWhiteSpace($uninstallString)) {
                        $issueFound = $true
                        $issueType = "OrphanedEntry"
                        $issueDetails = "Uninstall entry lacks DisplayName and UninstallString"
                        $severity = "Medium"
                        Write-Log "  └─ ⚠️  ORPHANED UNINSTALL ENTRY" "WARN"
                        $RepairReport.Statistics.OrphanedEntriesFound++
                    }
                }
                
                # Sprawdź broken paths (nieprawidłowe formatowanie)
                if ($valueData -match '[<>"|?*]') {
                    $issueFound = $true
                    $issueType = "BrokenPath"
                    $issueDetails = "Path contains illegal characters: $valueData"
                    $severity = "High"
                    Write-Log "  └─ ⚠️  BROKEN PATH: Illegal characters" "WARN"
                    $RepairReport.Statistics.BrokenPathsFound++
                }
                
                if ($issueFound) {
                    $issue = @{
                        KeyPath = $KeyPath
                        ValueName = $valueName
                        ValueData = $valueData
                        IssueType = $issueType
                        Severity = $severity
                        Details = $issueDetails
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    }
                    
                    $RepairReport.Issues += $issue
                    
                    # Kwarantanna dla high severity
                    if ($severity -eq "High") {
                        Invoke-QuarantineRegistryEntry -KeyPath $KeyPath -ValueName $valueName -ValueData $valueData -Reason $issueDetails
                    }
                    
                    # Auto-naprawa
                    if ($AutoRepair) {
                        Repair-RegistryEntry -KeyPath $KeyPath -ValueName $valueName -IssueType $issueType -Details $issueDetails
                    }
                }
                
            } catch [System.Security.SecurityException] {
                $RepairReport.Statistics.AccessDeniedCount++
                Write-Log "  ├─ SKIPPED (Access Denied): $valueName" "SKIP"
                $RepairReport.SkippedKeys += @{
                    Path = "$KeyPath\$valueName"
                    Reason = "Access Denied (Security)"
                }
            } catch [System.UnauthorizedAccessException] {
                $RepairReport.Statistics.AccessDeniedCount++
                Write-Log "  ├─ SKIPPED (Unauthorized): $valueName" "SKIP"
                $RepairReport.SkippedKeys += @{
                    Path = "$KeyPath\$valueName"
                    Reason = "Unauthorized Access"
                }
            } catch {
                Write-Log "  ├─ ERROR: $valueName - $_" "ERROR"
            }
        }
        
    } catch [System.Security.SecurityException] {
        $RepairReport.Statistics.AccessDeniedCount++
        $RepairReport.Statistics.TotalKeysSkipped++
        Write-Log "SKIPPED (Access Denied): $KeyPath" "SKIP"
        $RepairReport.SkippedKeys += @{
            Path = $KeyPath
            Reason = "Access Denied"
        }
    } catch {
        Write-Log "ERROR scanning: $KeyPath - $_" "ERROR"
    }
}

function Start-RegistryRepairScan {
    Write-Log "🔧 Starting registry repair scan..." "INFO"
    Write-Log "Scan type: $($RepairReport.ScanType)" "INFO"
    Write-Log "Auto-repair: $AutoRepair" "INFO"
    Write-Log "Create backups: $CreateBackup" "INFO"
    
    $locationsToScan = $ScanLocations
    
    if ($DeepScan) {
        $locationsToScan += $DeepScanLocations
        Write-Log "Deep scan enabled - $($locationsToScan.Count) locations" "INFO"
    }
    
    $progress = 0
    foreach ($location in $locationsToScan) {
        $progress++
        $percentComplete = [math]::Round(($progress / $locationsToScan.Count) * 100)
        Write-Progress -Activity "Registry Repair Scan" -Status "[$progress/$($locationsToScan.Count)] $location" -PercentComplete $percentComplete
        
        Scan-RegistryKey -KeyPath $location
        
        # Skanuj podklucze dla Uninstall i CLSID
        if ($location -match 'Uninstall$|CLSID$|Services$') {
            try {
                Write-Log "  └─ Scanning subkeys..." "VERBOSE"
                $subKeys = Get-ChildItem -Path $location -ErrorAction SilentlyContinue
                foreach ($subKey in $subKeys) {
                    Scan-RegistryKey -KeyPath $subKey.PSPath
                }
            } catch {
                Write-Log "  └─ ERROR scanning subkeys: $_" "ERROR"
            }
        }
    }
    
    Write-Progress -Activity "Registry Repair Scan" -Completed
}

function Export-RepairReport {
    try {
        $RepairReport.Statistics.ScanDuration = ((Get-Date) - [datetime]$RepairReport.ScanDate).TotalSeconds
        
        $reportJson = $RepairReport | ConvertTo-Json -Depth 10
        Set-Content -Path $OutputPath -Value $reportJson -Force
        
        Write-Log "📄 Report saved: $OutputPath" "SUCCESS"
        Write-Log "📄 Verbose log: $VerboseLogPath" "SUCCESS"
        
        Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║       REGISTRY REPAIR SCAN - SUMMARY            ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host "Registry keys scanned:  $($RepairReport.Statistics.TotalKeysScanned)" -ForegroundColor White
        Write-Host "Registry keys skipped:  $($RepairReport.Statistics.TotalKeysSkipped)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "ISSUES FOUND:" -ForegroundColor Yellow
        Write-Host "  Broken paths:         $($RepairReport.Statistics.BrokenPathsFound)" -ForegroundColor Red
        Write-Host "  Missing files:        $($RepairReport.Statistics.MissingFilesFound)" -ForegroundColor Red
        Write-Host "  Orphaned entries:     $($RepairReport.Statistics.OrphanedEntriesFound)" -ForegroundColor Yellow
        Write-Host "  Invalid CLSIDs:       $($RepairReport.Statistics.InvalidCLSIDsFound)" -ForegroundColor Red
        Write-Host "  Empty keys:           $($RepairReport.Statistics.EmptyKeysFound)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "ACTIONS TAKEN:" -ForegroundColor Green
        Write-Host "  Issues repaired:      $($RepairReport.Statistics.IssuesRepaired)" -ForegroundColor Green
        Write-Host "  Entries quarantined:  $($RepairReport.Statistics.EntriesQuarantined)" -ForegroundColor Magenta
        Write-Host "  Backups created:      $($RepairReport.Statistics.BackupsCreated)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Access denied count:    $($RepairReport.Statistics.AccessDeniedCount)" -ForegroundColor DarkGray
        Write-Host "Scan duration:          $([math]::Round($RepairReport.Statistics.ScanDuration, 2))s" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
        
        if ($RepairReport.Issues.Count -gt 0) {
            Write-Host "🔥 TOP 5 CRITICAL ISSUES:" -ForegroundColor Red
            $RepairReport.Issues | Where-Object { $_.Severity -eq "High" } | Select-Object -First 5 | ForEach-Object {
                Write-Host "  [$($_.IssueType)] $($_.KeyPath)\$($_.ValueName)" -ForegroundColor Yellow
                Write-Host "    └─ $($_.Details)" -ForegroundColor DarkYellow
            }
            Write-Host ""
        }
        
        if (-not $AutoRepair -and $RepairReport.Issues.Count -gt 0) {
            Write-Host "💡 TIP: Run with -AutoRepair to automatically fix issues" -ForegroundColor Yellow
            Write-Host "💡 TIP: All backups saved to: $BackupPath`n" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Log "Failed to export report: $_" "ERROR"
    }
}

# MAIN EXECUTION
try {
    Clear-Host
    Write-Host @"
╔══════════════════════════════════════════════════════════╗
║   WINDOWS REGISTRY ERROR SCANNER & REPAIR v1.0          ║
║   🔧 Kompletny moduł naprawy rejestru                   ║
║                                                          ║
║   ✓ Broken Paths Detection                              ║
║   ✓ Missing Files Detection                             ║
║   ✓ Orphaned Entries Cleanup                            ║
║   ✓ Invalid CLSID Detection                             ║
║   ✓ Automatic Repair + Backup                           ║
╚══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    if (Test-Path $VerboseLogPath) {
        Remove-Item $VerboseLogPath -Force
    }
    
    Write-Log "╔═══════════════════════════════════════════════════════╗" "INFO"
    Write-Log "║ REPAIR SCAN INITIALIZED - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "╚═══════════════════════════════════════════════════════╝" "INFO"
    
    Start-RegistryRepairScan
    Export-RepairReport
    
    Write-Log "✅ Scan completed successfully" "SUCCESS"
    
} catch {
    Write-Log "💀 FATAL ERROR: $_" "ERROR"
    Export-RepairReport
    exit 1
}
