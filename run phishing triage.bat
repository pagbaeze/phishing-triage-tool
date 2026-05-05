@echo off
echo Running Phishing Triage Tool...
cd /d "%~dp0"
py phishing_triage.py
echo.
echo Opening report...
start "" "%~dp0phishing_triage_report.txt"
echo.
pause