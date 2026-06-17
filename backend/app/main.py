from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .auth import (
    authenticate_user,
    create_session,
    file_belongs_to,
    init_auth_db,
    record_file_owner,
    require_token,
    require_user,
    revoke_session,
)
from .file_handlers import MAX_UPLOAD_BYTES, REDACTED_DIR, redact_file, save_upload
from .proxy import proxy_openai_request
from .scanner import build_summary, scan_text
from .schemas import FileScanResponse, LoginRequest, LoginResponse, PromptScanRequest, PromptScanResponse


app = FastAPI(title="LLM-Guard API", version="0.1.0")
logger = logging.getLogger(__name__)
ALLOWED_MODES = {"mask", "placeholder", "remove"}
MAX_PROMPT_CHARS = 200_000

# Simple in-memory login throttle: per-IP failed-attempt counter with a window.
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300
_login_failures: dict[str, list[float]] = {}
_login_lock = threading.Lock()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1):\d+$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _login_throttle_check(ip: str) -> None:
    now = time.monotonic()
    with _login_lock:
        attempts = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
        _login_failures[ip] = attempts
        if len(attempts) >= LOGIN_MAX_FAILURES:
            raise HTTPException(status_code=429, detail="登录尝试过于频繁，请稍后再试")


def _login_record_failure(ip: str) -> None:
    now = time.monotonic()
    with _login_lock:
        attempts = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
        attempts.append(now)
        _login_failures[ip] = attempts


def _login_reset(ip: str) -> None:
    with _login_lock:
        _login_failures.pop(ip, None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy_openai(path: str, request: Request):
    return await proxy_openai_request(path, request)


@app.on_event("startup")
def startup() -> None:
    init_auth_db()


@app.post("/api/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request) -> dict:
    ip = _client_ip(request)
    _login_throttle_check(ip)
    username = payload.username.strip()
    if not username or not payload.password:
        raise HTTPException(status_code=400, detail="请输入账号和密码")
    if not authenticate_user(username, payload.password):
        _login_record_failure(ip)
        logger.warning("Failed login for %r from %s", username, ip)
        raise HTTPException(status_code=401, detail="账号或密码错误")
    _login_reset(ip)
    token, expires_at = create_session(username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "username": username,
    }


@app.post("/api/auth/logout")
def logout(token: str = Depends(require_token)) -> dict[str, str]:
    revoke_session(token)
    return {"status": "ok"}


@app.get("/api/auth/me")
def me(username: str = Depends(require_user)) -> dict[str, str]:
    return {"username": username}


@app.post("/api/scan/prompt", response_model=PromptScanResponse)
def scan_prompt(payload: PromptScanRequest, username: str = Depends(require_user)) -> dict:
    _validate_mode(payload.mode)
    if len(payload.text) > MAX_PROMPT_CHARS:
        raise HTTPException(status_code=413, detail="输入文本过长，最大支持 200000 个字符")
    redacted, findings = scan_text(payload.text, payload.mode)
    return {
        "original_text": payload.text,
        "redacted_text": redacted,
        "summary": build_summary(findings),
        "findings": findings,
    }


@app.post("/api/scan/file", response_model=FileScanResponse)
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    mode: str = Form("mask"),
    username: str = Depends(require_user),
) -> dict:
    _validate_mode(mode)
    # Reject oversized uploads before buffering the whole body into memory.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="上传文件过大，最大支持 20MB")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="上传文件为空")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="上传文件过大，最大支持 20MB")

    source: Path | None = None
    try:
        source = save_upload(file.filename or "upload", content)
        result = redact_file(source, file.filename or source.name, mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("File processing failed")
        raise HTTPException(status_code=500, detail="文件处理失败，请检查文件格式或稍后重试") from exc
    finally:
        # The original upload contains raw PII; never keep it around.
        if source is not None:
            source.unlink(missing_ok=True)

    findings = result["findings"]
    redacted_path: Path = result["path"]
    record_file_owner(redacted_path.name, username)
    return {
        "file_id": redacted_path.name,
        "filename": file.filename or source.name,
        "redacted_filename": result["download_name"],
        "preview": result["preview"],
        "summary": build_summary(findings),
        "findings": findings,
    }


@app.get("/api/files/{file_id}")
def download_file(file_id: str, username: str = Depends(require_user)) -> FileResponse:
    if file_id != Path(file_id).name:
        raise HTTPException(status_code=400, detail="非法文件名")
    if not file_belongs_to(file_id, username):
        # Use 404 (not 403) so non-owners can't tell whether a file exists.
        raise HTTPException(status_code=404, detail="文件不存在")
    safe_name = Path(file_id).name
    path = (REDACTED_DIR / safe_name).resolve()
    if not path.is_relative_to(REDACTED_DIR.resolve()) or not path.exists():
        raise HTTPException(status_code=404, detail="文件不存在")
    return FileResponse(path, filename=safe_name)


def _validate_mode(mode: str) -> None:
    if mode not in ALLOWED_MODES:
        raise HTTPException(status_code=400, detail="不支持的脱敏模式")
