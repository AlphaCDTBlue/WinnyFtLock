@echo off
rem ---------------------------------------------------------------
rem Get-ThreatPath.bat - asks the operator for the target path and
rem writes it to the output file given as %1 (called by Remove-Threat.ps1).
rem Exit codes: 0 = path written, 1 = cancelled/blank, 2 = bad usage
rem ---------------------------------------------------------------
setlocal EnableDelayedExpansion
set "OUT=%~1"
if "%OUT%"=="" exit /b 2
title Threat Removal - Target Path

echo.
echo  ==================================================
echo   BLUE TEAM THREAT REMOVAL - TARGET FILE
echo  ==================================================
echo   Enter the FULL path to the suspicious file, e.g.
echo       C:\Users\Public\update.exe
echo   or only the FOLDER it is in, e.g.
echo       C:\Users\Public
echo   (You can paste a path with quotes. Env vars like %%TEMP%% work.)
echo   Leave blank and press Enter to cancel.
echo.
set "INPUT="
set /p "INPUT=Path> "

:trim
if not defined INPUT exit /b 1
set "INPUT=!INPUT:"=!"
if not defined INPUT exit /b 1
if "!INPUT:~-1!"==" " set "INPUT=!INPUT:~0,-1!" & goto trim
if "!INPUT:~0,1!"==" " set "INPUT=!INPUT:~1!" & goto trim

>"%OUT%" echo(!INPUT!
exit /b 0
