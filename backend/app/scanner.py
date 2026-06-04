from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    type: str
    label: str
    severity: str
    pattern: re.Pattern[str]


RULES: list[Rule] = [
    Rule("id_card", "身份证号", "high", re.compile(r"(?<!\d)(?:\d{17}[\dXx]|\d{15})(?!\d)")),
    Rule("phone", "手机号", "medium", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    Rule("db_credential", "数据库连接凭据", "critical", re.compile(r"(?i)\b(?:mysql|postgresql|postgres|mongodb|redis)://[^:@\s'\"<>]*:[^@\s'\"<>]+@[^\s'\"<>]+")),
    Rule("email", "邮箱地址", "medium", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9_%+-])")),
    Rule("address", "地址", "medium", re.compile(r"[\u4e00-\u9fa5]{2,}(?:省|市|自治区|自治州|区|县|镇|乡|街道|路|街|巷|小区|大街)[\u4e00-\u9fa5A-Za-z0-9\-号室单元栋幢弄院]+")),
    Rule("student_id", "学号 / 工号", "medium", re.compile(r"(?:学号|工号)\s*(?:是|为)?\s*[:=：]?\s*\d{6,14}")),
    Rule("bank_card", "银行卡号", "high", re.compile(r"(?<!\d)(?:\d[ -]?){16,19}(?!\d)")),
    Rule("password", "密码字段", "critical", re.compile(r"(?i)(?:\b(?:password|passwd|pwd)\b|(?:数据库)?(?:口令|密码))\s*[:=：]\s*['\"]?([^\s,'\";，。]{4,})")),
    Rule("api_key", "API Key / Token", "critical", re.compile(r"(?i)(?:\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|bearer)\b\s*(?:[:=：]|是|为)?\s*['\"]?[A-Za-z0-9._\-]{8,}|sk-[A-Za-z0-9_-]{8,})")),
    Rule("url_secret", "URL 敏感参数", "high", re.compile(r"(?i)(?:token|key|secret|password|pwd)=([^&\s]+)")),
    Rule("prompt_injection", "提示注入风险", "high", re.compile(r"(?i)(忽略.*(?:规则|指令|限制)|泄露.*(?:系统提示词|system prompt)|ignore (?:all )?(?:previous|prior) instructions|reveal (?:the )?system prompt|developer message|jailbreak)")),
]


SEVERITY_SCORE = {
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 70,
}


def _mask_value(value: str, type_name: str, stable_map: dict[str, str], mode: str) -> str:
    if mode == "placeholder":
        if value not in stable_map:
            stable_map[value] = f"[{type_name.upper()}_{len(stable_map) + 1}]"
        return stable_map[value]
    if mode == "remove":
        return ""

    compact = value.strip()
    if type_name == "phone" and len(compact) == 11:
        return compact[:3] + "****" + compact[-4:]
    if type_name == "email" and "@" in compact:
        name, domain = compact.split("@", 1)
        return (name[:2] if len(name) > 1 else name[:1]) + "***@" + domain
    if type_name == "address":
        labeled = re.sub(r"(.{0,8}(?:住址|地址)\s*(?:是|为|[:=：])\s*).+", r"\1[ADDRESS]", compact, count=1)
        if labeled != compact:
            return labeled
        return "[ADDRESS]"
    if type_name == "student_id":
        digits_match = re.search(r"\d{6,14}", compact)
        if digits_match:
            digits = digits_match.group(0)
            masked = digits[:4] + "*" * max(2, len(digits) - 6) + digits[-2:]
            return compact.replace(digits, masked, 1)
        return "[STUDENT_ID]"
    if type_name == "password":
        return re.sub(r"([:=：]\s*)['\"]?[^\s,'\";，。]{4,}", r"\1[PASSWORD]", compact, count=1)
    if type_name == "db_credential":
        return re.sub(r"(://[^:@\s'\"<>]*:)[^@\s'\"<>]+(@)", r"\1[PASSWORD]\2", compact, count=1)
    if type_name == "id_card" and len(compact) >= 15:
        return compact[:6] + "********" + compact[-4:]
    if type_name == "bank_card":
        digits = re.sub(r"\D", "", compact)
        return "**** **** **** " + digits[-4:] if len(digits) >= 4 else "[BANK_CARD]"
    return f"[{type_name.upper()}]"


def scan_text(text: str, mode: str = "mask", location: str | None = None) -> tuple[str, list[dict]]:
    findings: list[dict] = []
    spans: list[tuple[int, int, Rule]] = []

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            start, end = match.span()
            if any(not (end <= s or start >= e) for s, e, _ in spans):
                continue
            spans.append((start, end, rule))

    spans.sort(key=lambda item: item[0])
    redacted_parts: list[str] = []
    cursor = 0
    stable_map: dict[str, str] = {}

    for start, end, rule in spans:
        original = text[start:end]
        replacement = _mask_value(original, rule.type, stable_map, mode)
        redacted_parts.append(text[cursor:start])
        redacted_parts.append(replacement)
        cursor = end
        findings.append(
            {
                "type": rule.type,
                "label": rule.label,
                "severity": rule.severity,
                "evidence": original[:120],
                "replacement": replacement,
                "start": start,
                "end": end,
                "location": location,
            }
        )

    redacted_parts.append(text[cursor:])
    return "".join(redacted_parts), findings


def build_summary(findings: list[dict]) -> dict:
    by_type = Counter(item["type"] for item in findings)
    by_severity = Counter(item["severity"] for item in findings)
    score = min(100, sum(SEVERITY_SCORE.get(item["severity"], 10) for item in findings))
    if score >= 70 or by_severity.get("critical", 0):
        risk_level = "high"
    elif score >= 30:
        risk_level = "medium"
    elif score > 0:
        risk_level = "low"
    else:
        risk_level = "safe"

    return {
        "risk_level": risk_level,
        "score": score,
        "total_findings": len(findings),
        "counts_by_type": dict(by_type),
        "counts_by_severity": dict(by_severity),
    }
