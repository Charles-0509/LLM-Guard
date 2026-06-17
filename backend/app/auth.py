from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


BASE_DIR = Path(__file__).resolve().parents[1]
STORAGE_DIR = BASE_DIR / "storage"
DB_PATH = STORAGE_DIR / "llm_guard.sqlite3"
PBKDF2_ITERATIONS = 260_000
SESSION_SECONDS = int(os.getenv("LLM_GUARD_SESSION_SECONDS", str(8 * 60 * 60)))
MIN_PASSWORD_LENGTH = 8

_db_lock = threading.Lock()
_bearer = HTTPBearer(auto_error=False)


def init_auth_db() -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                iterations INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(username) REFERENCES users(username)
            )
            """
        )
        _ensure_initial_user(conn)


def record_file_owner(file_id: str, username: str) -> None:
    now = int(time.time())
    with _db_lock:
        with _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO files (file_id, username, created_at) VALUES (?, ?, ?)",
                (file_id, username, now),
            )


def file_belongs_to(file_id: str, username: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM files WHERE file_id = ? AND username = ?",
            (file_id, username),
        ).fetchone()
    return row is not None


def _load_dotenv() -> dict[str, str]:
    """Minimal, zero-dependency .env parser. Returns key/value pairs found in
    BASE_DIR/.env. Lines that are blank, comments, or malformed are ignored."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _resolve_initial_credentials() -> tuple[str, str]:
    """Resolve initial admin credentials with no insecure default.

    Priority: process env vars > backend/.env > interactive terminal prompt.
    If none of these yield a username and a password >= MIN_PASSWORD_LENGTH,
    raise SystemExit so the server refuses to boot with a weak/empty account."""
    dotenv = _load_dotenv()

    def _lookup(name: str) -> str:
        return (os.getenv(name) or dotenv.get(name, "")).strip()

    username = _lookup("LLM_GUARD_INITIAL_USERNAME")
    password = os.getenv("LLM_GUARD_INITIAL_PASSWORD") or dotenv.get("LLM_GUARD_INITIAL_PASSWORD", "")

    if not username or not password:
        username, password = _prompt_for_credentials(username, password)

    username = username.strip()
    if not username:
        raise SystemExit(
            "未配置初始账号。请在 backend/.env 中设置 LLM_GUARD_INITIAL_USERNAME "
            "与 LLM_GUARD_INITIAL_PASSWORD，或在交互式终端启动以手动输入。"
        )
    if len(password) < MIN_PASSWORD_LENGTH:
        raise SystemExit(
            f"初始密码长度不足（至少 {MIN_PASSWORD_LENGTH} 位）。"
            "请在 backend/.env 中设置一个更强的 LLM_GUARD_INITIAL_PASSWORD。"
        )
    return username, password


def _prompt_for_credentials(username: str, password: str) -> tuple[str, str]:
    """Ask for missing credentials on an interactive terminal. On a
    non-interactive boot (Docker/systemd/CI) this is impossible, so refuse."""
    if not sys.stdin or not sys.stdin.isatty():
        raise SystemExit(
            "首次启动需要初始账号，但未检测到 backend/.env 凭据，且当前不是交互式终端。"
            "请在 backend/.env 中设置 LLM_GUARD_INITIAL_USERNAME 与 "
            "LLM_GUARD_INITIAL_PASSWORD 后重新启动。"
        )

    import getpass

    print("首次启动：请设置 LLM-Guard 初始管理员账号。", file=sys.stderr)
    if not username:
        username = input("初始账号: ").strip()
    if not password:
        password = getpass.getpass("初始密码: ")
        confirm = getpass.getpass("再次输入密码: ")
        if password != confirm:
            raise SystemExit("两次输入的密码不一致，已退出。")
    return username, password


def authenticate_user(username: str, password: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT salt, password_hash, iterations FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        _verify_password(password, secrets.token_hex(16), secrets.token_hex(32), PBKDF2_ITERATIONS)
        return False
    return _verify_password(password, row["salt"], row["password_hash"], row["iterations"])


def create_session(username: str) -> tuple[str, int]:
    token = secrets.token_urlsafe(32)
    token_hash = _token_hash(token)
    now = int(time.time())
    expires_at = now + SESSION_SECONDS
    with _db_lock:
        with _connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            conn.execute(
                "INSERT INTO sessions (token_hash, username, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (token_hash, username, expires_at, now),
            )
    return token, expires_at


def revoke_session(token: str) -> None:
    token_hash = _token_hash(token)
    with _db_lock:
        with _connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def require_user(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="请先登录")

    username = _username_for_token(credentials.credentials)
    if username is None:
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
    return username


def require_token(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    """Like require_user but returns the raw bearer token (needed for logout)."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="请先登录")
    if _username_for_token(credentials.credentials) is None:
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
    return credentials.credentials


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _ensure_initial_user(conn: sqlite3.Connection) -> None:
    # Only create an account on a fresh database. Once any user exists we never
    # prompt or fall back to a default, so restarts stay non-interactive.
    any_user = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if any_user:
        return
    username, password = _resolve_initial_credentials()
    salt, password_hash = _hash_password(password)
    conn.execute(
        """
        INSERT INTO users (username, salt, password_hash, iterations, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, salt, password_hash, PBKDF2_ITERATIONS, int(time.time())),
    )


def _hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    ).hex()
    return salt, password_hash


def _verify_password(password: str, salt: str, expected_hash: str, iterations: int) -> bool:
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        iterations,
    ).hex()
    return hmac.compare_digest(actual_hash, expected_hash)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _username_for_token(token: str) -> str | None:
    now = int(time.time())
    token_hash = _token_hash(token)
    with _db_lock:
        with _connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            row = conn.execute(
                "SELECT username, expires_at FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
    if row is None or row["expires_at"] <= now:
        return None
    return row["username"]
