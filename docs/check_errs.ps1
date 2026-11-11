
# ============================================================
# COMSM0122 - ERRS COURSEWORK
# COMPLETE PROJECT INSPECTION AND VERIFICATION
# ============================================================

$ErrorActionPreference = "Continue"

# 1. Navigate to the actual coursework directory
$Project = "C:\Users\MSc Lab\Desktop\ERRS_COMSM0122_prototype\ERRS_Coursework_Submission"

Write-Host "`n========== ERRS COURSEWORK PROJECT ==========" -ForegroundColor Cyan

if (!(Test-Path $Project)) {
    Write-Host "ERROR: Coursework folder not found!" -ForegroundColor Red
    exit
}

Set-Location $Project

Write-Host "`nProject location:" -ForegroundColor Green
Get-Location

# 2. Check important folders
Write-Host "`n========== PROJECT FOLDERS ==========" -ForegroundColor Cyan

$Folders = @(
    "app",
    "app\consensus",
    "docs",
    "evidence",
    "evidence\experiments",
    "evidence\governance",
    "evidence\checkpoints",
    "data\source",
    "tests",
    "instance"
)

foreach ($Folder in $Folders) {
    if (Test-Path $Folder) {
        Write-Host "[FOUND] $Folder" -ForegroundColor Green
    }
    else {
        Write-Host "[MISSING] $Folder" -ForegroundColor Red
    }
}

# 3. Display documentation
Write-Host "`n========== DOCUMENTATION FILES ==========" -ForegroundColor Cyan

if (Test-Path "docs") {
    Get-ChildItem docs -File | Select-Object Name
}

# 4. Display application files
Write-Host "`n========== APPLICATION FILES ==========" -ForegroundColor Cyan

Get-ChildItem app -Recurse -File |
Where-Object { $_.Extension -eq ".py" } |
Select-Object FullName

# 5. Display consensus modules
Write-Host "`n========== CONSENSUS MODULES ==========" -ForegroundColor Cyan

if (Test-Path "app\consensus") {
    Get-ChildItem app\consensus -File |
    Select-Object Name
}

# 6. Display source datasets
Write-Host "`n========== SOURCE DATASETS ==========" -ForegroundColor Cyan

if (Test-Path "data\source") {
    Get-ChildItem data\source -File |
    Select-Object Name
}

# 7. Display test files
Write-Host "`n========== TEST FILES ==========" -ForegroundColor Cyan

if (Test-Path "tests") {
    Get-ChildItem tests -File |
    Select-Object Name
}

# 8. Activate virtual environment
Write-Host "`n========== VIRTUAL ENVIRONMENT ==========" -ForegroundColor Cyan

if (Test-Path ".venv\Scripts\Activate.ps1") {
    & .\.venv\Scripts\Activate.ps1
    Write-Host "Virtual environment activated." -ForegroundColor Green
}
else {
    Write-Host "Virtual environment activation script missing." -ForegroundColor Yellow
}

# 9. Check Python version
Write-Host "`n========== PYTHON VERSION ==========" -ForegroundColor Cyan

python --version

# 10. Run all coursework tests
Write-Host "`n========== PYTEST VERIFICATION ==========" -ForegroundColor Cyan

python -m pytest -v

$TestExitCode = $LASTEXITCODE

if ($TestExitCode -eq 0) {
    Write-Host "`nALL TESTS PASSED." -ForegroundColor Green
}
else {
    Write-Host "`nTESTS FAILED OR INCOMPLETE. CHECK OUTPUT." -ForegroundColor Red
}

# 11. Regenerate exported evidence
Write-Host "`n========== EVIDENCE EXPORT ==========" -ForegroundColor Cyan

if (Test-Path "export_evidence.py") {
    python export_evidence.py
}
else {
    Write-Host "export_evidence.py not found." -ForegroundColor Yellow
}

# 12. Display generated evidence
Write-Host "`n========== EXPERIMENT AND GOVERNANCE EVIDENCE ==========" -ForegroundColor Cyan

if (Test-Path "evidence") {
    Get-ChildItem evidence -Recurse -File |
    Select-Object FullName
}

# 13. Check important project scripts
Write-Host "`n========== PROJECT ROOT FILES ==========" -ForegroundColor Cyan

Get-ChildItem -File | Select-Object Name

# 14. Final result
Write-Host "`n========== VERIFICATION SUMMARY ==========" -ForegroundColor Cyan

Write-Host "Project: $Project"

if ($TestExitCode -eq 0) {
    Write-Host "Pytest: PASSED" -ForegroundColor Green
}
else {
    Write-Host "Pytest: NEEDS INVESTIGATION" -ForegroundColor Red
}

Write-Host "`nERRS coursework inspection completed." -ForegroundColor Cyan

# ============================================================
