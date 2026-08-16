<#
.SYNOPSIS
    SentinelNet Runner for PowerShell on Windows.
.EXAMPLE
    .\run.ps1
    .\run.ps1 -ui app
    .\run.ps1 -ui browser
    .\run.ps1 -ui none
#>
[CmdletBinding()]
param (
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgsList
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " SentinelNet (Go) - Network Intelligence" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($ArgsList) {
    go run ./cmd/sentinelnet @ArgsList
} else {
    go run ./cmd/sentinelnet
}
