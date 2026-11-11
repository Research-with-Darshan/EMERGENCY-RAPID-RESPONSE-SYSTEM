
# ============================================================
# NERP / ERRS - COMPLETE EVIDENCE COLLECTION
# COMSM0122 - Fundamentals of System Security
# ============================================================

$ErrorActionPreference = "Continue"

$Project = Get-Location
$Evidence = Join-Path $Project "evidence"

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " NERP COMPLETE EVIDENCE COLLECTION"
Write-Host "==========================================" -ForegroundColor Cyan

# 1. CREATE EVIDENCE FOLDERS

$Folders = @(
    "screenshots",
    "test-results",
    "experiments",
    "governance",
    "checkpoints"
)

foreach ($Folder in $Folders) {
    New-Item -ItemType Directory `
        -Path (Join-Path $Evidence $Folder) `
        -Force | Out-Null
}

Write-Host "`nEvidence folders created." -ForegroundColor Green

# 2. PYTHON VERSION

python --version 2>&1 |
Out-File "$Evidence\test-results\python-version.txt"

# 3. RUN PYTEST AND SAVE COMPLETE OUTPUT

Write-Host "`n[1] RUNNING PYTEST..." -ForegroundColor Yellow

python -m pytest -v 2>&1 |
Tee-Object -FilePath "$Evidence\test-results\pytest-results.txt"

$TestResult = $LASTEXITCODE

# 4. RUN CONSENSUS AND GOVERNANCE EXPERIMENTS

Write-Host "`n[2] RUNNING NINE CONSENSUS EXPERIMENTS AND GOVERNANCE SCENARIOS..." -ForegroundColor Yellow

python export_evidence.py 2>&1 |
Tee-Object -FilePath "$Evidence\test-results\experiment-results.txt"

$ExperimentResult = $LASTEXITCODE

# 5. GENERATE CONSENSUS SUMMARY

Write-Host "`n[3] GENERATING CONSENSUS SUMMARY..." -ForegroundColor Yellow

$ExperimentFiles = Get-ChildItem "$Evidence\experiments" -Filter "*.json"

$ExperimentData = @(
    foreach ($File in $ExperimentFiles) {
        Get-Content $File.FullName -Raw | ConvertFrom-Json
    }
)

$Summary = [PSCustomObject]@{
    Project = "NERP"
    Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalExperiments = $ExperimentData.Count
    Passed = @($ExperimentData | Where-Object test_result -eq "PASS").Count
    Failed = @($ExperimentData | Where-Object test_result -eq "FAIL").Count
    Results = $ExperimentData
}

$Summary |
ConvertTo-Json -Depth 10 |
Set-Content "$Evidence\test-results\consensus-summary.json"

# 6. GOVERNANCE SUMMARY

Write-Host "`n[4] CHECKING GOVERNANCE EVIDENCE..." -ForegroundColor Yellow

$GovernanceFile = "$Evidence\governance\scenarios.json"

if (Test-Path $GovernanceFile) {

    $Governance = Get-Content $GovernanceFile -Raw |
        ConvertFrom-Json

    $GovernanceCount = @($Governance).Count

} else {

    $GovernanceCount = 0

}

# 7. GENERATE FINAL TEST SUMMARY

$FinalSummary = [PSCustomObject]@{
    Project = "NERP Security Coursework"
    CollectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    PythonTests = if ($TestResult -eq 0) {"PASS"} else {"CHECK"}
    EvidenceExport = if ($ExperimentResult -eq 0) {"PASS"} else {"CHECK"}
    ConsensusExperiments = $ExperimentData.Count
    ConsensusPassed = $Summary.Passed
    ConsensusFailed = $Summary.Failed
    GovernanceScenarios = $GovernanceCount
}

$FinalSummary |
ConvertTo-Json -Depth 5 |
Set-Content "$Evidence\test-results\test-summary.json"

# 8. CREATE EVIDENCE README

$Readme = @"
# NERP Security Assurance Evidence

Course: COMSM0122 - Fundamentals of System Security

## Evidence contents

- screenshots/: Application and experiment screenshots.
- test-results/: Automated test outputs and summaries.
- experiments/: Nine consensus experiment JSON records.
- governance/: Five governance scenario results.
- checkpoints/: Application checkpoints.

## Automated testing

Pytest result: $($FinalSummary.PythonTests)

Evidence export: $($FinalSummary.EvidenceExport)

Consensus experiments: $($FinalSummary.ConsensusExperiments)

Governance scenarios: $($FinalSummary.GovernanceScenarios)

Collection date: $($FinalSummary.CollectionDate)

## Important

PASS indicates that the corresponding automated test or
simulated experiment passed its defined checks.
It does not establish complete system security.
"@

Set-Content "$Evidence\README.md" $Readme

# 9. DISPLAY FINAL SUMMARY

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " FINAL EVIDENCE COLLECTION SUMMARY"
Write-Host "==========================================" -ForegroundColor Cyan

$FinalSummary | Format-List

Write-Host "`nEVIDENCE FILES GENERATED:" -ForegroundColor Green

Get-ChildItem $Evidence -Recurse -File |
Select-Object FullName

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host " EVIDENCE COLLECTION COMPLETED"
Write-Host "==========================================" -ForegroundColor Green
