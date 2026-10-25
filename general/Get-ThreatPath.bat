@echo off
rem ---------------------------------------------------------------
rem Get-ThreatPath.bat - makes the operator type the EXACT full path
rem (including the file name) and writes it to the file given as %1.
rem Called by Remove-Threat.ps1.
rem Exit codes: 0 = path written, 1 = cancelled/blank, 2 = bad usage
rem ---------------------------------------------------------------
setlocal EnableDelayedExpansion
set "OUT=%~1"
if "%OUT%"=="" exit /b 2
title Threat Removal - Target File

echo.
echo  ==================================================
echo   BLUE TEAM THREAT REMOVAL - TARGET FILE
echo  ==================================================
echo   Type the EXACT full path INCLUDING the file name:
echo       C:\Windows\System32\getridofme.txt
echo   (Pasting with quotes is fine.)
echo   Leave blank and press Enter to cancel.
echo.

:ask
set "INPUT="
set /p "INPUT=Path> "

:trim
if not defined INPUT exit /b 1
set "INPUT=!INPUT:"=!"
if not defined INPUT exit /b 1
if "!INPUT:~-1!"==" " set "INPUT=!INPUT:~0,-1!" & goto trim
if "!INPUT:~0,1!"==" " set "INPUT=!INPUT:~1!" & goto trim

set "OK="
if "!INPUT:~1,2!"==":\" set "OK=1"
if "!INPUT:~0,2!"=="\\" set "OK=1"
if not defined OK echo   Not a full path - it must start with a drive letter like C:\ ^& include the file name. & goto ask
if "!INPUT:~-1!"=="\" echo   That ends in a backslash (a folder). Include the file name. & goto ask

>"%OUT%" echo(!INPUT!
exit /b 0
