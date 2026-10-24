$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
Set-Location $ProjectDir

$EnvFile = Join-Path $ProjectDir ".env"
if (-not (Test-Path $EnvFile)) {
    throw "Missing .env file"
}

Get-Content $EnvFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
        $parts = $line -split "=", 2
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ($key -match '^[A-Za-z_][A-Za-z0-9_]*$') {
            [Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
    }
}

python .\agent.py once
exit $LASTEXITCODE

