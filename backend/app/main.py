from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .auth import authenticate_user, create_session, init_auth_db, require_user
from .file_handlers import REDACTED_DIR, redact_file, save_upload
from .scanner import build_summary, scan_text
from .schemas import FileScanResponse, LoginRequest, LoginResponse, PromptScanRequest, PromptScanResponse


app = FastAPI(title="LLM-Guard API", version="0.1.0")
logger = logging.getLogger(__name__)
ALLOWED_MODES = {"mask", "placeholder", "remove"}
MAX_PROMPT_CHARS = 200_000

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1):\d+$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
def startup() -> None:
    init_auth_db()


@app.post("/api/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> dict:
    username = payload.username.strip()
    if not username or not payload.password:
        raise HTTPException(status_code=400, detail="请输入账号和密码")
    if not authenticate_user(username, payload.password):
        raise HTTPException(status_code=401, detail="账号或密码错误")
    token, expires_at = create_session(username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "username": username,
    }


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
    file: UploadFile = File(...),
    mode: str = Form("mask"),
    username: str = Depends(require_user),
) -> dict:
    _validate_mode(mode)
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="上传文件为空")

    try:
        source = save_upload(file.filename or "upload", content)
        result = redact_file(source, file.filename or source.name, mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("File processing failed")
        raise HTTPException(status_code=500, detail="文件处理失败，请检查文件格式或稍后重试") from exc

    findings = result["findings"]
    redacted_path: Path = result["path"]
    return {
        "file_id": redacted_path.name,
        "filename": file.filename or source.name,
        "redacted_filename": redacted_path.name,
        "preview": result["preview"],
        "summary": build_summary(findings),
        "findings": findings,
    }


@app.get("/api/files/{file_id}")
def download_file(file_id: str, username: str = Depends(require_user)) -> FileResponse:
    if file_id != Path(file_id).name:
        raise HTTPException(status_code=400, detail="非法文件名")
    safe_name = Path(file_id).name
    path = REDACTED_DIR / safe_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="文件不存在")
    return FileResponse(path, filename=safe_name)


def _validate_mode(mode: str) -> None:
    if mode not in ALLOWED_MODES:
        raise HTTPException(status_code=400, detail="不支持的脱敏模式")
