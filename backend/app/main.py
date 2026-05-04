from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .file_handlers import REDACTED_DIR, redact_file, save_upload
from .scanner import build_summary, scan_text
from .schemas import FileScanResponse, PromptScanRequest, PromptScanResponse


app = FastAPI(title="LLM-Guard API", version="0.1.0")

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


@app.post("/api/scan/prompt", response_model=PromptScanResponse)
def scan_prompt(payload: PromptScanRequest) -> dict:
    redacted, findings = scan_text(payload.text, payload.mode)
    return {
        "original_text": payload.text,
        "redacted_text": redacted,
        "summary": build_summary(findings),
        "findings": findings,
    }


@app.post("/api/scan/file", response_model=FileScanResponse)
async def scan_file(file: UploadFile = File(...), mode: str = Form("mask")) -> dict:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="上传文件为空")

    try:
        source = save_upload(file.filename or "upload", content)
        result = redact_file(source, file.filename or source.name, mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"文件处理失败：{exc}") from exc

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
def download_file(file_id: str) -> FileResponse:
    safe_name = Path(file_id).name
    path = REDACTED_DIR / safe_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="文件不存在")
    return FileResponse(path, filename=safe_name)
