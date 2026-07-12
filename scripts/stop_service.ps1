$port = 8081
$conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
if ($conn) {
    $procId = $conn.OwningProcess
    Stop-Process -Id $procId -Force
    Write-Host "Stopped process (PID $procId) on port $port"
} else {
    Write-Host "No process found on port $port"
}
