param([string[]]$Annotator)

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $workspace

if (-not $Annotator -or $Annotator.Count -eq 0) {
    Write-Host "AgentSecBench multi-annotator service" -ForegroundColor Green
    Write-Host "Enter annotator IDs separated by spaces."
    Write-Host "Allowed: A-Z, a-z, 0-9, underscore, and hyphen." -ForegroundColor DarkGray
    Write-Host "Example: reviewer01 reviewer02 reviewer03" -ForegroundColor DarkGray
    $entered = Read-Host "Annotator IDs"
    $Annotator = @($entered -split '\s+' | Where-Object { $_ })
}

if ($Annotator.Count -eq 0) {
    throw "At least one annotator ID is required."
}
foreach ($id in $Annotator) {
    if ($id -notmatch '^[A-Za-z0-9_-]{1,40}$') {
        throw "Invalid annotator ID: $id"
    }
}

$arguments = @("scripts\serve_human_annotation.py", "--share")
foreach ($id in $Annotator) {
    $arguments += @("--annotator", $id)
}

Write-Host ""
Write-Host "Send each generated URL only to its matching annotator." -ForegroundColor Yellow
Write-Host "Keep this window open. Press Ctrl+C to stop; restart with the same IDs to resume." -ForegroundColor Yellow
Write-Host ""
& python @arguments
