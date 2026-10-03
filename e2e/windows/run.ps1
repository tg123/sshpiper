$ErrorActionPreference = "Stop"

$e2eDir = Split-Path $PSScriptRoot -Parent
$root = Split-Path $e2eDir -Parent
$project = "sshpiper-windows-" + [guid]::NewGuid().ToString("N")
$compose = @(
    "--project-name", $project,
    "-f", "docker-compose.yml",
    "-f", "docker-compose.windows.yml"
)

function Invoke-Compose([string[]]$ComposeArgs) {
    & wsl --cd $e2eDir --exec docker compose @compose @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose failed: $($ComposeArgs -join ' ')"
    }
}

$previousUpstream = $env:SSHPIPERD_E2E_UPSTREAM
# Systemd services alone do not keep WSL alive while the Windows tests run.
$keepAlive = [System.Diagnostics.Process]::Start([System.Diagnostics.ProcessStartInfo]@{
    FileName = "wsl.exe"
    Arguments = '--exec sh -c "read -r _"'
    UseShellExecute = $false
    RedirectStandardInput = $true
})
try {
    Invoke-Compose @("up", "--detach", "--wait", "--wait-timeout", "120", "host-password")
    $upstream = (Invoke-Compose @("port", "host-password", "2222")).Trim()
    if ($upstream -notmatch '^127\.0\.0\.1:\d+$') {
        throw "Unexpected Compose SSH endpoint: $upstream"
    }
    $env:SSHPIPERD_E2E_UPSTREAM = $upstream
    & go -C $root test -v -count=1 -tags e2e -timeout 10m .\e2e\windows
    if ($LASTEXITCODE -ne 0) {
        throw "Native Windows E2E tests failed"
    }
} finally {
    $env:SSHPIPERD_E2E_UPSTREAM = $previousUpstream
    try {
        & wsl --cd $e2eDir --exec docker compose @compose logs --no-color host-password
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not collect Compose SSH server logs"
        }
        Invoke-Compose @("down", "--volumes")
    } finally {
        $keepAlive.StandardInput.Close()
        if (-not $keepAlive.WaitForExit(10000)) {
            $keepAlive.Kill()
            $keepAlive.WaitForExit()
            Write-Warning "WSL keepalive did not exit after closing stdin and was terminated"
        }
        $keepAlive.Dispose()
    }
}
