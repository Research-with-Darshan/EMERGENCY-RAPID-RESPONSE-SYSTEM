How to run it
In VS Code PowerShell terminal, execute these commands:

1. Open your project directory


powershell
cd "C:\Users\MSc Lab\Desktop\ERRS_COMSM0122_prototype\ERRS_Coursework_Submission"
2. Activate your environment


powershell
.\.venv\Scripts\Activate.ps1
3. Allow this script to run in the current terminal


Set-ExecutionPolicy -Scope Process Bypass -Force
.\collect_evidence.ps1