from pydantic import BaseModel


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
    text: str
    mode: str = "mask"


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
