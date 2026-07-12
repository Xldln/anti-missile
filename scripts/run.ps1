$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcPath = Resolve-Path "$scriptDir\..\src"

$proc = Start-Process python -ArgumentList "main.py" -WorkingDirectory $srcPath -PassThru -NoNewWindow

Write-Host "Waiting 20s for service to start..."
Start-Sleep -Seconds 20

try {
    Invoke-WebRequest -Uri "http://localhost:8081/api/devices?probe=false&tcp=false" -UseBasicParsing -TimeoutSec 30 | Out-Null
    Write-Host "Service activated successfully"
} catch {
    Write-Host "Activation request failed (service may still be starting)"
}

Wait-Process -Id $proc.Id

