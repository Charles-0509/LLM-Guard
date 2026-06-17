from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: int
    username: str


class Finding(BaseModel):
    type: str
    label: str
    severity: str
    evidence: str
    replacement: str
    start: int | None = None
    end: int | None = None
    location: str | None = None


class DetectionSummary(BaseModel):
    risk_level: str
    score: int
    total_findings: int
    counts_by_type: dict[str, int]
    counts_by_severity: dict[str, int]


class PromptScanRequest(BaseModel):
    text: str = Field(max_length=200_000)
    mode: Literal["mask", "placeholder", "remove"] = "mask"


class PromptScanResponse(BaseModel):
    original_text: str
    redacted_text: str
    summary: DetectionSummary
    findings: list[Finding]


class FileScanResponse(BaseModel):
    file_id: str
    filename: str
    redacted_filename: str
    preview: str
    summary: DetectionSummary
    findings: list[Finding]
