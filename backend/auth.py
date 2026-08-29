"""SentinelAI Authentication Module.

Provides:
  - User registration (bcrypt-hashed passwords, stored in MongoDB 'users' collection)
  - JWT login (python-jose, HS256, configurable expiry from .env)
  - FastAPI dependency get_current_user() for protecting endpoints

Environment variables (backend/.env):
  JWT_SECRET       -- required, random hex string, never hardcoded
  JWT_ALGORITHM    -- default HS256
  JWT_EXPIRE_HOURS -- default 8

Uses bcrypt directly (not passlib) for Python 3.13 / bcrypt 4.x compatibility.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

import database as db

# ---------------------------------------------------------------------------
# Load config from .env
# ---------------------------------------------------------------------------

load_dotenv()

_JWT_SECRET: str = os.getenv("JWT_SECRET", "")
_JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
_JWT_EXPIRE_HOURS: int = int(os.getenv("JWT_EXPIRE_HOURS", "8"))

if not _JWT_SECRET:
    raise EnvironmentError(
        "JWT_SECRET is not set in backend/.env. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(64))\""
    )

# ---------------------------------------------------------------------------
# Password hashing (bcrypt 4.x directly — no passlib)
# ---------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt. Never store plaintext."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time comparison of plaintext against stored bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# JWT utilities
# ---------------------------------------------------------------------------

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def create_access_token(data: dict[str, Any]) -> str:
    """Create a signed JWT with an expiry claim."""
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=_JWT_EXPIRE_HOURS)
    payload["exp"] = expire
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises HTTP 401 on any failure."""
    try:
        payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def get_current_user(token: str = Depends(_oauth2_scheme)) -> dict:
    """FastAPI dependency — inject into protected endpoints.

    Returns the decoded token payload dict (contains 'sub', 'role', etc.).
    Raises HTTP 401 if the token is missing, invalid, or expired.
    """
    payload = decode_token(token)
    username: str | None = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": username, "role": payload.get("role", "analyst")}


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


# ---------------------------------------------------------------------------
# Auth route handlers (called from main.py)
# ---------------------------------------------------------------------------


async def register_user(req: RegisterRequest) -> dict:
    """Register a new user. Returns 409 if username already exists."""
    database = db._get_db()

    existing = await database.users.find_one({"username": req.username})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{req.username}' is already taken.",
        )

    # Minimum validation — never log the raw password
    if len(req.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 6 characters.",
        )

    doc = {
        "username": req.username,
        "hashed_password": hash_password(req.password),
        "role": "analyst",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await database.users.insert_one(doc)
    # Ensure unique index (idempotent)
    await database.users.create_index("username", unique=True)

    print(f"  [auth] New user registered: {req.username} (role=analyst)")
    return {"status": "registered", "username": req.username, "role": "analyst"}


async def login_user(req: LoginRequest) -> TokenResponse:
    """Authenticate and return a JWT. Never logs raw password or secret."""
    database = db._get_db()

    user = await database.users.find_one({"username": req.username})
    if not user or not verify_password(req.password, user["hashed_password"]):
        # Same error for both fields — do not reveal which was wrong
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({
        "sub": user["username"],
        "role": user.get("role", "analyst"),
    })
    print(f"  [auth] Login successful: {req.username}")
    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=user.get("role", "analyst"),
    )
