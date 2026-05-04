param(
    [int]$FrontendStartPort = 5050,
    [int]$BackendStartPort = 8010
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $Root "backend"
$FrontendDir = Join-Path $Root "frontend"

function Get-FreePort {
    param([int]$StartPort)

    $port = $StartPort
    while ($true) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
            $listener.Start()
            return $port
        } catch {
            $port += 1
        } finally {
            if ($listener) {
                $listener.Stop()
            }
        }
    }
}

function Assert-Command {
    param(
        [string]$Name,
        [string]$InstallHint
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "未找到命令 $Name。$InstallHint"
    }
}

Assert-Command "python" "请先安装 Python，并确保 python 已加入 PATH。"
Assert-Command "npm" "请先安装 Node.js/npm，并确保 npm 已加入 PATH。"

$VenvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "正在创建后端虚拟环境..."
    python -m venv (Join-Path $BackendDir ".venv")
}

Write-Host "正在检查后端依赖..."
& $VenvPython -m pip install -r (Join-Path $BackendDir "requirements.txt")

if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
    Write-Host "正在安装前端依赖..."
    Push-Location $FrontendDir
    npm install
    Pop-Location
}

$BackendPort = Get-FreePort $BackendStartPort
$FrontendPort = Get-FreePort $FrontendStartPort
$ApiBase = "http://localhost:$BackendPort"

Write-Host ""
Write-Host "LLM-Guard 即将启动"
Write-Host "后端地址: $ApiBase"
Write-Host "前端地址: http://localhost:$FrontendPort"
Write-Host ""

$BackendCommand = "Set-Location '$BackendDir'; & '$VenvPython' -m uvicorn app.main:app --host 127.0.0.1 --port $BackendPort"
$FrontendCommand = "`$env:VITE_API_BASE='$ApiBase'; Set-Location '$FrontendDir'; npm run dev -- --host 0.0.0.0 --port $FrontendPort --strictPort"

Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $BackendCommand -WindowStyle Normal
Start-Sleep -Seconds 1
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $FrontendCommand -WindowStyle Normal

Write-Host "已打开两个终端窗口分别运行前后端。"
Write-Host "请访问: http://localhost:$FrontendPort"
