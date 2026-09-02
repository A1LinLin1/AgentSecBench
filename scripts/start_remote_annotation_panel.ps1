param(
    [string[]]$Annotator,
    [ValidateSet("blind", "audit")][string]$Mode = "blind"
)

$ErrorActionPreference = "Stop"
$workspace = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $workspace

if ($Mode -eq "audit") {
    $serviceName = "AgentSecBench remote model-audit service"
    $serverScript = "scripts\serve_model_audit.py"
    $idFlag = "--reviewer"
    $port = "8766"
    $registryRelative = "annotations\model_audit\invitations.local.json"
    $runtimeName = "remote_model_audit"
    $linkHeading = "REMOTE MODEL-AUDIT LINKS"
} else {
    $serviceName = "AgentSecBench remote blind-annotation service"
    $serverScript = "scripts\serve_human_annotation.py"
    $idFlag = "--annotator"
    $port = "8765"
    $registryRelative = "annotations\annotator\invitations.local.json"
    $runtimeName = "remote_annotation"
    $linkHeading = "REMOTE BLIND-ANNOTATION LINKS"
}

if (-not $Annotator -or $Annotator.Count -eq 0) {
    Write-Host $serviceName -ForegroundColor Green
    Write-Host "Enter reviewer IDs separated by spaces."
    Write-Host "Allowed: A-Z, a-z, 0-9, underscore, and hyphen." -ForegroundColor DarkGray
    Write-Host "Example: reviewer01 reviewer02 reviewer03" -ForegroundColor DarkGray
    $entered = Read-Host "Reviewer IDs"
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

$cloudflared = Join-Path $workspace "tools\cloudflared\cloudflared.exe"
if (-not (Test-Path -LiteralPath $cloudflared)) {
    throw "Missing tools\cloudflared\cloudflared.exe"
}
$pythonExe = (& python -c "import sys; print(sys.executable)").Trim()
if (-not (Test-Path -LiteralPath $pythonExe)) {
    throw "Unable to resolve the real Python executable."
}
$runtimeRoot = Join-Path $workspace ".runtime\$runtimeName"
$runName = Get-Date -Format "yyyyMMddTHHmmss"
$runDir = Join-Path $runtimeRoot $runName
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$serverOut = Join-Path $runDir "server.stdout.log"
$serverErr = Join-Path $runDir "server.stderr.log"
$tunnelOut = Join-Path $runDir "tunnel.stdout.log"
$tunnelErr = Join-Path $runDir "tunnel.stderr.log"

$serverArgs = @(
    $serverScript,
    "--share",
    "--bind", "127.0.0.1",
    "--port", $port,
    "--no-browser"
)
foreach ($id in $Annotator) {
    $serverArgs += @($idFlag, $id)
}

$server = $null
$tunnel = $null
try {
    $server = Start-Process -FilePath $pythonExe -ArgumentList $serverArgs `
        -WorkingDirectory $workspace -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr

    $serverReady = $false
    for ($i = 0; $i -lt 80; $i++) {
        if ($server.HasExited) {
            throw "Annotation server exited: $(Get-Content -Raw -LiteralPath $serverErr)"
        }
        try {
            Invoke-WebRequest -Uri "http://127.0.0.1:$port/" -UseBasicParsing -TimeoutSec 1 | Out-Null
            $serverReady = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $serverReady) {
        throw "Annotation server did not become ready."
    }

    $tunnel = Start-Process -FilePath $cloudflared `
        -ArgumentList @("tunnel", "--url", "http://127.0.0.1:$port", "--no-autoupdate") `
        -WorkingDirectory $workspace -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $tunnelOut -RedirectStandardError $tunnelErr

    $publicBase = $null
    for ($i = 0; $i -lt 160; $i++) {
        if ($tunnel.HasExited) {
            throw "Cloudflare Tunnel exited: $(Get-Content -Raw -LiteralPath $tunnelErr)"
        }
        $log = ""
        if (Test-Path -LiteralPath $tunnelOut) { $log += Get-Content -Raw -LiteralPath $tunnelOut }
        if (Test-Path -LiteralPath $tunnelErr) { $log += Get-Content -Raw -LiteralPath $tunnelErr }
        if ($log -match 'https://[a-z0-9-]+\.trycloudflare\.com') {
            $publicBase = $Matches[0]
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $publicBase) {
        throw "Timed out waiting for a Quick Tunnel URL. See $tunnelErr"
    }

    $registryPath = Join-Path $workspace $registryRelative
    $registry = Get-Content -Raw -LiteralPath $registryPath | ConvertFrom-Json
    Write-Host ""
    Write-Host $linkHeading -ForegroundColor Green
    Write-Host "Send each URL only to its matching annotator." -ForegroundColor Yellow
    Write-Host ""
    foreach ($id in $Annotator) {
        $property = $registry.PSObject.Properties | Where-Object { $_.Name -ceq $id }
        if (-not $property) { throw "No invitation token found for $id" }
        Write-Host "[$id] $publicBase/#invite=$($property.Value)"
    }
    Write-Host ""
    Write-Host "Keep this window open. Press Ctrl+C to stop public access." -ForegroundColor Yellow
    Write-Host "Quick Tunnel URL: $publicBase" -ForegroundColor DarkGray
    Write-Host "Runtime logs: $runDir" -ForegroundColor DarkGray

    while (-not $server.HasExited -and -not $tunnel.HasExited) {
        Start-Sleep -Seconds 1
    }
    if ($server.HasExited) { throw "Annotation server stopped unexpectedly." }
    if ($tunnel.HasExited) { throw "Cloudflare Tunnel stopped unexpectedly." }
} finally {
    if ($tunnel -and -not $tunnel.HasExited) {
        Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue
    }
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}
