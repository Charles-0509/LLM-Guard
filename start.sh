#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
FRONTEND_START_PORT="${FRONTEND_START_PORT:-5050}"
BACKEND_START_PORT="${BACKEND_START_PORT:-8010}"

find_python() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "python3"
  elif command -v python >/dev/null 2>&1; then
    printf '%s\n' "python"
  else
    printf '%s\n' "未找到 python 或 python3，请先安装 Python。" >&2
    exit 1
  fi
}

find_free_port() {
  start_port="$1"
  "$PYTHON_BIN" - "$start_port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            port += 1
        else:
            print(port)
            break
PY
}

PYTHON_BIN=$(find_python)

if ! command -v npm >/dev/null 2>&1; then
  printf '%s\n' "未找到 npm，请先安装 Node.js/npm。" >&2
  exit 1
fi

if [ -x "$BACKEND_DIR/.venv/bin/python" ]; then
  VENV_PY="$BACKEND_DIR/.venv/bin/python"
elif [ -x "$BACKEND_DIR/.venv/Scripts/python.exe" ]; then
  VENV_PY="$BACKEND_DIR/.venv/Scripts/python.exe"
else
  printf '%s\n' "正在创建后端虚拟环境..."
  "$PYTHON_BIN" -m venv "$BACKEND_DIR/.venv"
  if [ -x "$BACKEND_DIR/.venv/bin/python" ]; then
    VENV_PY="$BACKEND_DIR/.venv/bin/python"
  else
    VENV_PY="$BACKEND_DIR/.venv/Scripts/python.exe"
  fi
fi

printf '%s\n' "正在检查后端依赖..."
"$VENV_PY" -m pip install -r "$BACKEND_DIR/requirements.txt"

if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
  printf '%s\n' "正在安装前端依赖..."
  (cd "$FRONTEND_DIR" && npm install)
fi

BACKEND_PORT=$(find_free_port "$BACKEND_START_PORT")
FRONTEND_PORT=$(find_free_port "$FRONTEND_START_PORT")
API_BASE="http://localhost:$BACKEND_PORT"

printf '\n%s\n' "LLM-Guard 即将启动"
printf '%s\n' "后端地址: $API_BASE"
printf '%s\n\n' "前端地址: http://localhost:$FRONTEND_PORT"

cleanup() {
  if [ "${BACKEND_PID:-}" ]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT

(cd "$BACKEND_DIR" && "$VENV_PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$BACKEND_PORT") &
BACKEND_PID=$!

VITE_API_BASE="$API_BASE" npm --prefix "$FRONTEND_DIR" run dev -- --host 0.0.0.0 --port "$FRONTEND_PORT" --strictPort
