from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


BASE_DIR = Path(__file__).resolve().parents[1]
STORAGE_DIR = BASE_DIR / "storage"
DB_PATH = STORAGE_DIR / "llm_guard.sqlite3"
PBKDF2_ITERATIONS = 260_000
SESSION_SECONDS = int(os.getenv("LLM_GUARD_SESSION_SECONDS", str(24 * 60 * 60)))
INITIAL_USERNAME = os.getenv("LLM_GUARD_INITIAL_USERNAME", "charles")
INITIAL_PASSWORD = os.getenv("LLM_GUARD_INITIAL_PASSWORD", "Charles939433.")

_db_lock = threading.Lock()
_bearer = HTTPBearer(auto_error=False)


def init_auth_db() -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
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
        _ensure_initial_user(conn)


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
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.execute(
            "INSERT INTO sessions (token_hash, username, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token_hash, username, expires_at, now),
        )
    return token, expires_at


def require_user(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="请先登录")

    username = _username_for_token(credentials.credentials)
    if username is None:
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
    return username


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_initial_user(conn: sqlite3.Connection) -> None:
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (INITIAL_USERNAME,)).fetchone()
    if exists:
        return
    salt, password_hash = _hash_password(INITIAL_PASSWORD)
    conn.execute(
        """
        INSERT INTO users (username, salt, password_hash, iterations, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (INITIAL_USERNAME, salt, password_hash, PBKDF2_ITERATIONS, int(time.time())),
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
