param([string[]]$Reviewer)

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $workspace

if (-not $Reviewer -or $Reviewer.Count -eq 0) {
    Write-Host "AgentSecBench model-assisted audit" -ForegroundColor Green
    Write-Host "Enter reviewer IDs separated by spaces."
    Write-Host "Example: auditor01 auditor02" -ForegroundColor DarkGray
    $entered = Read-Host "Reviewer IDs"
    $Reviewer = @($entered -split '\s+' | Where-Object { $_ })
}
if ($Reviewer.Count -eq 0) { throw "At least one reviewer ID is required." }
foreach ($id in $Reviewer) {
    if ($id -notmatch '^[A-Za-z0-9_-]{1,40}$') { throw "Invalid reviewer ID: $id" }
}

$arguments = @("scripts\serve_model_audit.py", "--share")
foreach ($id in $Reviewer) { $arguments += @("--reviewer", $id) }
Write-Host ""
Write-Host "This mode exposes model outputs and is not independent blind annotation." -ForegroundColor Yellow
Write-Host "Send each generated URL only to its matching reviewer." -ForegroundColor Yellow
Write-Host ""
& python @arguments
