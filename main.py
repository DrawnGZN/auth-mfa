"""Central de Autenticação Segura com MFA (TOTP).

Argon2id para senhas, JWT de acesso curto, refresh token com rotação
(armazenado apenas como hash) e 2FA compatível com Google Authenticator.
"""
import hashlib
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("Defina JWT_SECRET com pelo menos 32 caracteres.")

ACCESS_TTL = timedelta(minutes=5)
REFRESH_TTL = timedelta(days=7)
MAX_FAILS = 5
LOCK_SECONDS = 300
DB_PATH = os.environ.get("DB_PATH", "auth.db")

ph = PasswordHasher()  # Argon2id por padrão
app = FastAPI(title="Auth MFA")
bearer = HTTPBearer(auto_error=False)


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                fails INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            """
        )


init_db()


# ---------- modelos ----------
class Credentials(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=128)


class LoginIn(Credentials):
    totp_code: str | None = None


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class RefreshIn(BaseModel):
    refresh_token: str


# ---------- helpers ----------
def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def make_access(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(user_id), "iat": now, "exp": now + ACCESS_TTL, "type": "access"},
        JWT_SECRET,
        algorithm="HS256",
    )


def make_refresh(user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    with db() as con:
        con.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?,?,?)",
            (sha256(token), user_id, time.time() + REFRESH_TTL.total_seconds()),
        )
    return token


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> sqlite3.Row:
    if creds is None or not creds.credentials:
        raise HTTPException(401, "Token ausente")
    token = creds.credentials
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if data.get("type") != "access":
            raise jwt.InvalidTokenError
    except jwt.PyJWTError:
        raise HTTPException(401, "Token inválido ou expirado")
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (data["sub"],)).fetchone()
    if not user:
        raise HTTPException(401, "Usuário não encontrado")
    return user


# ---------- rotas ----------
@app.post("/register", status_code=201)
def register(body: Credentials):
    email = body.email.strip().lower()
    try:
        with db() as con:
            con.execute(
                "INSERT INTO users (email, password_hash) VALUES (?,?)",
                (email, ph.hash(body.password)),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "E-mail já cadastrado")
    return {"message": "Usuário criado"}


@app.post("/login")
def login(body: LoginIn):
    email = body.email.strip().lower()
    generic = HTTPException(401, "Credenciais inválidas")
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            raise generic
        if user["locked_until"] > time.time():
            raise HTTPException(429, "Conta temporariamente bloqueada")

        ok = True
        try:
            ph.verify(user["password_hash"], body.password)
        except VerifyMismatchError:
            ok = False
        if ok and user["mfa_enabled"]:
            ok = bool(body.totp_code) and pyotp.TOTP(user["totp_secret"]).verify(
                body.totp_code, valid_window=1
            )

        if not ok:
            fails = user["fails"] + 1
            locked = time.time() + LOCK_SECONDS if fails >= MAX_FAILS else 0
            con.execute(
                "UPDATE users SET fails=?, locked_until=? WHERE id=?",
                (0 if locked else fails, locked, user["id"]),
            )
            raise generic
        con.execute("UPDATE users SET fails=0 WHERE id=?", (user["id"],))

    return {
        "access_token": make_access(user["id"]),
        "refresh_token": make_refresh(user["id"]),
        "token_type": "bearer",
        "expires_in": int(ACCESS_TTL.total_seconds()),
    }


@app.post("/refresh")
def refresh(body: RefreshIn):
    h = sha256(body.refresh_token)
    with db() as con:
        row = con.execute("SELECT * FROM refresh_tokens WHERE token_hash=?", (h,)).fetchone()
        if not row or row["revoked"] or row["expires_at"] < time.time():
            raise HTTPException(401, "Refresh token inválido")
        # rotação: o token usado é revogado e um novo é emitido
        con.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (h,))
    return {
        "access_token": make_access(row["user_id"]),
        "refresh_token": make_refresh(row["user_id"]),
        "token_type": "bearer",
    }


@app.post("/logout")
def logout(body: RefreshIn):
    with db() as con:
        con.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (sha256(body.refresh_token),))
    return {"message": "Sessão encerrada"}


@app.post("/mfa/setup")
def mfa_setup(user=Depends(current_user)):
    if user["mfa_enabled"]:
        raise HTTPException(400, "MFA já ativado")
    secret = pyotp.random_base32()
    with db() as con:
        con.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user["id"]))
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="Auth MFA")
    return {"secret": secret, "otpauth_uri": uri}


@app.post("/mfa/enable")
def mfa_enable(body: CodeIn, user=Depends(current_user)):
    if not user["totp_secret"]:
        raise HTTPException(400, "Execute /mfa/setup primeiro")
    if not pyotp.TOTP(user["totp_secret"]).verify(body.code, valid_window=1):
        raise HTTPException(400, "Código inválido")
    with db() as con:
        con.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (user["id"],))
    return {"message": "MFA ativado"}


@app.get("/me")
def me(user=Depends(current_user)):
    return {"email": user["email"], "mfa_enabled": bool(user["mfa_enabled"])}
