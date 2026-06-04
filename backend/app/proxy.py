from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import Response, StreamingResponse

from .scanner import scan_text


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
RESPONSE_DROP_HEADERS = HOP_BY_HOP_HEADERS | {"content-encoding"}
PROTOCOL_FIELD_NAMES = {"model", "role", "type", "name", "tool_choice"}
VALID_PROXY_MODES = {"mask", "placeholder", "remove", "report_only", "off"}


@dataclass(frozen=True)
class ProxyConfig:
    enabled: bool
    upstream: str | None
    mode: str


@dataclass(frozen=True)
class RedactionResult:
    body: bytes
    redacted_count: int
    mode: str


def get_proxy_config() -> ProxyConfig:
    enabled = os.getenv("LLM_GUARD_PROXY_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
    upstream = os.getenv("LLM_GUARD_PROXY_UPSTREAM", "").strip().rstrip("/") or None
    mode = os.getenv("LLM_GUARD_PROXY_MODE", "mask").strip().lower() or "mask"
    if mode not in VALID_PROXY_MODES:
        mode = "mask"
    return ProxyConfig(enabled=enabled, upstream=upstream, mode=mode)


async def proxy_openai_request(path: str, request: Request) -> Response:
    config = get_proxy_config()
    if not config.enabled:
        raise HTTPException(status_code=503, detail="LLM-Guard 代理未启用")
    if not config.upstream:
        raise HTTPException(status_code=503, detail="未配置 LLM_GUARD_PROXY_UPSTREAM")

    try:
        redaction = await redact_request_body(request, config.mode)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="代理脱敏失败，请检查请求格式") from exc

    upstream_url = build_upstream_url(config.upstream, path, request.url.query)
    headers = filtered_request_headers(request.headers)

    try:
        if is_streaming_request(redaction.body):
            return await stream_upstream_response(
                method=request.method,
                upstream_url=upstream_url,
                headers=headers,
                body=redaction.body,
                mode=redaction.mode,
                redacted_count=redaction.redacted_count,
            )
        return await plain_upstream_response(
            method=request.method,
            upstream_url=upstream_url,
            headers=headers,
            body=redaction.body,
            mode=redaction.mode,
            redacted_count=redaction.redacted_count,
        )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="上游代理连接失败") from exc


def build_upstream_url(upstream: str, path: str, query: str) -> str:
    clean_path = path.lstrip("/")
    if upstream.rstrip("/").endswith("/v1"):
        url = f"{upstream}/{clean_path}"
    else:
        url = f"{upstream}/v1/{clean_path}"
    if query:
        url = f"{url}?{query}"
    return url


def filtered_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def filtered_response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in RESPONSE_DROP_HEADERS
    }


def add_proxy_headers(headers: dict[str, str], mode: str, redacted_count: int) -> dict[str, str]:
    headers = dict(headers)
    headers["X-LLM-Guard-Proxy"] = "active"
    headers["X-LLM-Guard-Mode"] = mode
    headers["X-LLM-Guard-Redacted-Count"] = str(redacted_count)
    return headers


async def redact_request_body(request: Request, mode: str) -> RedactionResult:
    body = await request.body()
    if mode == "off" or not body:
        return RedactionResult(body=body, redacted_count=0, mode=mode)

    if not should_try_json(request.headers.get("content-type", ""), body):
        return RedactionResult(body=body, redacted_count=0, mode=mode)

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return RedactionResult(body=body, redacted_count=0, mode=mode)

    redaction_mode = "mask" if mode == "report_only" else mode
    redacted_payload, redacted_count = redact_json_value(payload, redaction_mode)
    if mode == "report_only":
        return RedactionResult(body=body, redacted_count=redacted_count, mode=mode)

    redacted_body = json.dumps(redacted_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return RedactionResult(body=redacted_body, redacted_count=redacted_count, mode=mode)


def should_try_json(content_type: str, body: bytes) -> bool:
    if "json" in content_type.lower():
        return True
    stripped = body.lstrip()
    return stripped.startswith(b"{") or stripped.startswith(b"[")


def redact_json_value(value: Any, mode: str, path: tuple[str, ...] = ()) -> tuple[Any, int]:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        total = 0
        for key, item in value.items():
            child_path = (*path, str(key))
            if should_skip_field(child_path):
                redacted[key] = item
                continue
            redacted_item, count = redact_json_value(item, mode, child_path)
            redacted[key] = redacted_item
            total += count
        return redacted, total

    if isinstance(value, list):
        redacted_items = []
        total = 0
        for index, item in enumerate(value):
            redacted_item, count = redact_json_value(item, mode, (*path, str(index)))
            redacted_items.append(redacted_item)
            total += count
        return redacted_items, total

    if isinstance(value, str):
        redacted_text, findings = scan_text(value, mode)
        return redacted_text, len(findings)

    return value, 0


def should_skip_field(path: tuple[str, ...]) -> bool:
    if not path:
        return False
    key = path[-1]
    if key in PROTOCOL_FIELD_NAMES:
        return True
    return len(path) >= 2 and path[-2] == "function" and key == "name"


def is_streaming_request(body: bytes) -> bool:
    if not body:
        return False
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("stream") is True


async def plain_upstream_response(
    *,
    method: str,
    upstream_url: str,
    headers: dict[str, str],
    body: bytes,
    mode: str,
    redacted_count: int,
) -> Response:
    async with httpx.AsyncClient(timeout=None) as client:
        upstream_response = await client.request(method, upstream_url, headers=headers, content=body)
        response_headers = add_proxy_headers(
            filtered_response_headers(upstream_response.headers),
            mode,
            redacted_count,
        )
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=response_headers,
        )


async def stream_upstream_response(
    *,
    method: str,
    upstream_url: str,
    headers: dict[str, str],
    body: bytes,
    mode: str,
    redacted_count: int,
) -> StreamingResponse:
    client = httpx.AsyncClient(timeout=None)
    stream_context = client.stream(method, upstream_url, headers=headers, content=body)
    try:
        upstream_response = await stream_context.__aenter__()
    except Exception:
        await client.aclose()
        raise
    response_headers = add_proxy_headers(
        filtered_response_headers(upstream_response.headers),
        mode,
        redacted_count,
    )

    async def iter_response() -> AsyncIterator[bytes]:
        try:
            async for chunk in upstream_response.aiter_bytes():
                yield chunk
        finally:
            await stream_context.__aexit__(None, None, None)
            await client.aclose()

    return StreamingResponse(
        iter_response(),
        status_code=upstream_response.status_code,
        headers=response_headers,
    )
