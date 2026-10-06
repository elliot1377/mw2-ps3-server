@echo off
rem MW2 PS3 community server on this PC (local only). Keep this window open while you play; close it to stop.
title MW2 PS3 Server
tasklist /fi "imagename eq MW2 Server.exe" | find /i "MW2 Server.exe" >nul
if not errorlevel 1 (
  echo The MW2 server is already running in another window - you only need one.
  pause
  exit /b
)
cd /d "%~dp0server"
echo MW2 PS3 server on this PC - keep this window open while you play MW2 in RPCS3.
echo.
"MW2 Server.exe" %*
pause
