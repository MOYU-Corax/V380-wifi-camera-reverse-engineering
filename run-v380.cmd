@echo off
rem Launch the V380 MJPEG client (Windows version of run-v380.sh).
rem
rem The camera's IP is auto-detected (V380 native discovery, then by MAC) and
rem re-resolved on every reconnect, so this keeps working across DHCP changes.
rem
rem Usage:  run-v380.cmd              # uses HTTP_PORT from config.cmd
rem         run-v380.cmd 8091         # override the port
rem         run-v380.cmd 8091 --debug # extra args are passed through

setlocal EnableExtensions
cd /d "%~dp0"

if not exist "config.cmd" (
	echo error: no config.cmd found.
	echo   copy config.example.cmd to config.cmd, then edit in your camera's details
	exit /b 1
)
call "config.cmd"

set "PORT=%~1"
if not defined PORT set "PORT=%HTTP_PORT%"
if not defined PORT set "PORT=8090"

echo V380 client - device %DEVICE_ID%, serving http://localhost:%PORT%/ (auto-detecting camera IP)

if defined MAC (
	node v380-mjpeg.js --id "%DEVICE_ID%" --password "%PASSWORD%" --mac "%MAC%" --http "%PORT%" %2 %3 %4 %5 %6 %7 %8 %9
) else (
	node v380-mjpeg.js --id "%DEVICE_ID%" --password "%PASSWORD%" --http "%PORT%" %2 %3 %4 %5 %6 %7 %8 %9
)
