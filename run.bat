@echo off
setlocal
echo Starting SentinelNet (Go)...
go run ./cmd/sentinelnet %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo SentinelNet exited with error code %ERRORLEVEL%.
    pause
)
