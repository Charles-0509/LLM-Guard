from __future__ import annotations

import ipaddress
import json
import os
import socket
from collections.abc import AsyncIterator
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

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
# Headers we must never forward to the upstream: the upstream key is injected
# by this server, and client credentials / forwarding hints must not leak.
SENSITIVE_REQUEST_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
}
DROP_REQUEST_HEADERS = HOP_BY_HOP_HEADERS | SENSITIVE_REQUEST_HEADERS
RESPONSE_DROP_HEADERS = HOP_BY_HOP_HEADERS | {"content-encoding"}
PROTOCOL_FIELD_NAMES = {"model", "role", "type", "name", "tool_choice"}
VALID_PROXY_MODES = {"mask", "placeholder", "remove", "report_only", "off"}
MAX_PROXY_BODY_BYTES = 10 * 1024 * 1024
PROXY_TIMEOUT = httpx.Timeout(connect=10.0, read=300.0, write=60.0, pool=10.0)


@dataclass(frozen=True)
class ProxyConfig:
    enabled: bool
    upstream: str | None
    mode: str
    api_key: str | None
    upstream_authorization: str | None


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
    api_key = os.getenv("LLM_GUARD_PROXY_API_KEY", "").strip() or None
    upstream_auth = os.getenv("LLM_GUARD_PROXY_UPSTREAM_AUTHORIZATION", "").strip() or None
    return ProxyConfig(
        enabled=enabled,
        upstream=upstream,
        mode=mode,
        api_key=api_key,
        upstream_authorization=upstream_auth,
    )


def _is_private_host(host: str) -> bool:
    """True if host resolves to a loopback/private/link-local address (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Can't resolve — treat as unsafe to be conservative.
        return True
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


def _validate_upstream(upstream: str) -> None:
    parts = urlsplit(upstream)
    if parts.scheme not in {"http", "https"}:
        raise HTTPException(status_code=503, detail="代理上游地址协议无效")
    if not parts.hostname:
        raise HTTPException(status_code=503, detail="代理上游地址无效")
    if _is_private_host(parts.hostname):
        raise HTTPException(status_code=502, detail="代理上游地址指向内网，已拒绝")


def _check_proxy_auth(config: ProxyConfig, request: Request) -> None:
    """If a proxy API key is configured, require clients to present it.

    The client sends it via the standard `Authorization: Bearer <key>` header
    (as OpenAI SDKs do); the real upstream key is injected separately by the
    server, so this client header never reaches the upstream."""
    if not config.api_key:
        return
    presented = request.headers.get("authorization", "")
    scheme, _, value = presented.partition(" ")
    if scheme.lower() != "bearer" or value.strip() != config.api_key:
        raise HTTPException(status_code=401, detail="代理鉴权失败")


async def proxy_openai_request(path: str, request: Request) -> Response:
    config = get_proxy_config()
    if not config.enabled:
        raise HTTPException(status_code=503, detail="LLM-Guard 代理未启用")
    if not config.upstream:
        raise HTTPException(status_code=503, detail="未配置 LLM_GUARD_PROXY_UPSTREAM")
    _validate_upstream(config.upstream)
    _check_proxy_auth(config, request)
    _validate_proxy_path(path)

    try:
        redaction = await redact_request_body(request, config.mode)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="代理脱敏失败，请检查请求格式") from exc

    upstream_url = build_upstream_url(config.upstream, path, request.url.query)
    headers = filtered_request_headers(request.headers)
    if config.upstream_authorization:
        headers["Authorization"] = config.upstream_authorization

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


def _validate_proxy_path(path: str) -> None:
    # Reject anything that could turn a relative path into an absolute URL or
    # escape the upstream base (SSRF / path confusion).
    if "://" in path or ".." in path or "@" in path:
        raise HTTPException(status_code=400, detail="非法的代理路径")


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
        if key.lower() not in DROP_REQUEST_HEADERS
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
    if len(body) > MAX_PROXY_BODY_BYTES:
        raise HTTPException(status_code=413, detail="代理请求体过大")
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
    async with httpx.AsyncClient(timeout=PROXY_TIMEOUT, follow_redirects=False) as client:
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
    client = httpx.AsyncClient(timeout=PROXY_TIMEOUT, follow_redirects=False)
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
