@echo off
cd /d "C:\Users\Administrator\Desktop\KusoADCheck"
powershell -NoProfile -ExecutionPolicy Bypass -File "AD-Full-HealthCheck.ps1"
for /f "delims=" %%F in ('dir /b /o:-d "AD_Full_Overview_*.html" 2^>nul') do (
	start "" "%%F"
	goto :opened
)
if exist "latest.html" start "" "latest.html"
:opened
pause
