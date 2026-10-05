param([switch]$Start)

$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path "$root\app") -or -not (Test-Path "$root\serve.py")) {
    Write-Host "This does not look like the SecureVault project folder. Nothing deleted." -ForegroundColor Red
    exit 1
}

# Refuse to run while the server is up (Windows cannot delete an open database)
$listening = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
if ($listening) {
    Write-Host "The server is still running on port 5000. Press Ctrl+C in its window first, then run this again." -ForegroundColor Red
    exit 1
}

# 1. Database files (never inside venv, .git or .secrets)
$dbs = Get-ChildItem -Path $root -Recurse -File -Include *.db, *.db-wal, *.db-shm, *.db-journal |
    Where-Object { $_.FullName -notmatch '\\(venv|\.git|\.secrets)\\' }
foreach ($f in $dbs) {
    Remove-Item -Force $f.FullName
    Write-Host "Deleted database file: $($f.FullName)"
}
if (-not $dbs) { Write-Host "No database file found (already clean)." }

# 2. Uploaded encrypted images
$up = Join-Path $root "uploads"
if (Test-Path $up) {
    $files = Get-ChildItem -Path $up -File
    $files | Remove-Item -Force
    Write-Host "Deleted $($files.Count) uploaded file(s)."
}

Write-Host "`nClean. Keys in .secrets were kept. The first account you register will be admin." -ForegroundColor Green

if ($Start) {
    Write-Host "Starting the server..."
    Set-Location $root
    python serve.py
}
