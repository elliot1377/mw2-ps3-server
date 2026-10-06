@echo off
rem MW2 PS3 online fix for RPCS3.  Install Online Fix.bat [server IP]   (default: the server on this PC)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install Online Fix.ps1" %*
pause
