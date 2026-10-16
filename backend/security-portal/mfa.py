"""Two-factor authentication (TOTP) for portal logins.

Flow: /api/auth/login checks the password; for an MFA user it returns a
short-lived ``mfa_token`` instead of a session, which /api/auth/mfa/verify
exchanges for a session once a code is right. Codes are 6-digit TOTP (any
authenticator app) or single-use backup codes. TOTP secrets are encrypted with
the portal key; backup codes are stored hashed.

Admins can require MFA for admin accounts (mfa_required_for_admins). An admin
without MFA then gets a session that only reaches the MFA endpoints until they
set it up (auth.MFA_ENROLL_PATHS).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timezone

import pyotp
import segno
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

import audit
from auth import (
    authenticated_by_cookie,
    set_session_cookie,
    SessionUser, create_jwt_token, decode_mfa_pending_token, get_current_user_from_token, revoke_jti,
    MFA_PENDING_TTL_SECONDS,
)
from database import get_session
from models.mfa import UserMFA
from models.setting import PortalSetting

ISSUER = "AuthRecon"


def account_label(username: str) -> str:
    """The account name the authenticator app shows: the part before the @.
    Apps such as 2FAS guess a brand logo from any text in the entry, so an
    email domain (example.org, gmail.com, ...) could put a stranger's logo
    and name on AuthRecon's entry. The issuer still says AuthRecon."""
    return username.split("@", 1)[0] or username
BACKUP_CODE_COUNT = 10
MAX_CODE_ATTEMPTS = 5
POLICY_KEY = "mfa_required_for_admins"

router = APIRouter()
_encryptor = None
_user_store = None
_failures: dict[str, int] = {}  # pending-token jti -> wrong codes
# Spent pending tokens (jti -> expiry). Redis revocation is the main record;
# this keeps them single-use even when Redis is unavailable.
_spent: dict[str, float] = {}


def _spend(jti: str) -> None:
    now = time.time()
    for old in [k for k, exp in _spent.items() if exp < now]:
        _spent.pop(old, None)
    _spent[jti] = now + MFA_PENDING_TTL_SECONDS
    revoke_jti(jti, MFA_PENDING_TTL_SECONDS)


def configure(encryptor, user_store) -> None:
    global _encryptor, _user_store
    _encryptor, _user_store = encryptor, user_store


# --- state -------------------------------------------------------------------------

def is_enabled(user_id: str | None) -> bool:
    if not user_id:
        return False
    with get_session() as session:
        row = session.get(UserMFA, user_id)
        return bool(row and row.enabled)


def required_for_admins() -> bool:
    with get_session() as session:
        row = session.get(PortalSetting, POLICY_KEY)
        return bool(row and row.value == "true")


def enrollment_required(record: dict) -> bool:
    """An admin without MFA while MFA is required for admins."""
    return bool(record.get("is_admin")) and required_for_admins() and not is_enabled(record.get("id"))


def _hash(code: str) -> str:
    return hashlib.sha256(_clean(code).encode()).hexdigest()


def _clean(code: str) -> str:
    return (code or "").strip().replace(" ", "").replace("-", "").lower()


def _new_backup_codes() -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/l/i
    return ["".join(secrets.choice(alphabet) for _ in range(10)) for _ in range(BACKUP_CODE_COUNT)]


def _format(code: str) -> str:
    return f"{code[:5]}-{code[5:]}"


def check_code(user_id: str, code: str, *, allow_backup: bool = True) -> bool:
    """True if ``code`` is a current TOTP code (not used before) or an unused
    backup code (which is then spent)."""
    code = _clean(code)
    with get_session() as session:
        row = session.get(UserMFA, user_id)
        if not row or not row.enabled:
            return False
        if code.isdigit() and len(code) == 6:
            totp = pyotp.TOTP(_encryptor.decrypt(row.secret_encrypted))
            now_step = int(time.time() // 30)
            for step in (now_step - 1, now_step, now_step + 1):
                if secrets.compare_digest(totp.at(step * 30), code) and (row.last_step is None or step > row.last_step):
                    row.last_step = step
                    session.commit()
                    return True
            return False
        if allow_backup and len(code) == 10:
            hashes = json.loads(row.backup_codes or "[]")
            digest = _hash(code)
            if digest in hashes:
                hashes.remove(digest)
                row.backup_codes = json.dumps(hashes)
                session.commit()
                return True
        return False


def _record(user: SessionUser) -> dict:
    record = _user_store.get_user(user.user_id) if user.user_id else None
    if not record:
        raise HTTPException(status_code=401, detail="Unknown user")
    return record


# --- endpoints -------------------------------------------------------------------------

class CodeIn(BaseModel):
    code: str


class DisableIn(BaseModel):
    password: str
    code: str


class VerifyIn(BaseModel):
    mfa_token: str
    code: str


class PolicyIn(BaseModel):
    require_for_admins: bool


@router.get("/auth/mfa")
async def mfa_status(user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    with get_session() as session:
        row = session.get(UserMFA, user.user_id)
        enabled = bool(row and row.enabled)
        left = len(json.loads(row.backup_codes or "[]")) if enabled else 0
    return {"enabled": enabled, "backup_codes_left": left,
            "required": bool(user.is_admin) and required_for_admins(),
            "required_for_admins": required_for_admins()}


@router.post("/auth/mfa/setup")
async def mfa_setup(user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    """Start (or restart) enrolment: a new secret, shown once as a QR code and text."""
    if is_enabled(user.user_id):
        raise HTTPException(status_code=409, detail="Two-factor authentication is already on.")
    secret = pyotp.random_base32()
    with get_session() as session:
        row = session.get(UserMFA, user.user_id) or UserMFA(user_id=user.user_id, created_at=datetime.now(timezone.utc))
        row.secret_encrypted = _encryptor.encrypt(secret)
        row.enabled = False
        row.backup_codes = "[]"
        row.last_step = None
        session.merge(row)
        session.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=account_label(user.username), issuer_name=ISSUER)
    # A data: URI the UI shows as an <img> (an image cannot run script).
    qr = segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#0f172a", light="#ffffff")
    return {"secret": secret, "otpauth_uri": uri, "qr_data_uri": qr}


@router.post("/auth/mfa/enable")
async def mfa_enable(payload: CodeIn, request: Request, response: Response, user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    """Confirm enrolment with a code from the app; returns the backup codes (shown once)."""
    with get_session() as session:
        row = session.get(UserMFA, user.user_id)
        if not row or row.enabled:
            raise HTTPException(status_code=409, detail="Start setup first.")
        if not pyotp.TOTP(_encryptor.decrypt(row.secret_encrypted)).verify(_clean(payload.code), valid_window=1):
            raise HTTPException(status_code=400, detail="That code is not right. Check the time on your phone and try again.")
        codes = _new_backup_codes()
        row.enabled = True
        row.enabled_at = datetime.now(timezone.utc)
        row.last_step = int(time.time() // 30)
        row.backup_codes = json.dumps([_hash(c) for c in codes])
        session.commit()
    audit.emit(audit.MFA_ENABLED, actor_username=user.username, actor_ip=request.client.host if request.client else None)
    record = _record(user)
    # A fresh full session: an enrolment-only session becomes a normal one.
    token = create_jwt_token(username=record["username"], is_admin=record["is_admin"], user_id=record["id"])
    set_session_cookie(response, request, token)
    out = {"backup_codes": [_format(c) for c in codes]}
    if not authenticated_by_cookie(request):
        out["token"] = token  # scripts; the web UI gets the cookie only
    return out


@router.post("/auth/mfa/backup-codes")
async def mfa_new_backup_codes(payload: CodeIn, user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    if not check_code(user.user_id, payload.code, allow_backup=False):
        raise HTTPException(status_code=400, detail="That code is not right.")
    codes = _new_backup_codes()
    with get_session() as session:
        row = session.get(UserMFA, user.user_id)
        row.backup_codes = json.dumps([_hash(c) for c in codes])
        session.commit()
    audit.emit(audit.MFA_BACKUP_CODES, actor_username=user.username)
    return {"backup_codes": [_format(c) for c in codes]}


@router.post("/auth/mfa/disable")
async def mfa_disable(payload: DisableIn, request: Request, user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    if user.is_admin and required_for_admins():
        raise HTTPException(status_code=403, detail="Two-factor authentication is required for admins.")
    if not _user_store.verify_credentials(user.username, payload.password):
        raise HTTPException(status_code=400, detail="Password is not right.")
    if not check_code(user.user_id, payload.code):
        raise HTTPException(status_code=400, detail="That code is not right.")
    with get_session() as session:
        row = session.get(UserMFA, user.user_id)
        if row:
            session.delete(row)
            session.commit()
    audit.emit(audit.MFA_DISABLED, actor_username=user.username, actor_ip=request.client.host if request.client else None)
    return {"enabled": False}


@router.post("/auth/mfa/verify")
async def mfa_verify(payload: VerifyIn, request: Request, response: Response) -> dict:
    """Second login step: exchange the mfa_token and a code for a session."""
    from app import _throttle  # same per-IP throttle as the password step

    ip = request.client.host if request.client else "unknown"
    _throttle(f"mfa:{ip}", max_attempts=10, window_seconds=60)
    pending = decode_mfa_pending_token(payload.mfa_token)
    jti, user_id = pending["jti"], pending.get("user_id")
    if jti in _spent:
        raise HTTPException(status_code=401, detail="Sign-in expired. Enter your password again.")
    record = _user_store.get_user(user_id) if user_id else None
    if not record or not record.get("is_active", False):
        raise HTTPException(status_code=401, detail="Sign-in expired. Enter your password again.")
    if not check_code(user_id, payload.code):
        _failures[jti] = _failures.get(jti, 0) + 1
        audit.emit(audit.MFA_FAILURE, actor_username=record["username"], actor_ip=ip)
        if _failures[jti] >= MAX_CODE_ATTEMPTS:
            _spend(jti)
            _failures.pop(jti, None)
            raise HTTPException(status_code=401, detail="Too many wrong codes. Enter your password again.")
        raise HTTPException(status_code=401, detail="That code is not right.")
    _spend(jti)  # single use
    _failures.pop(jti, None)
    token = create_jwt_token(username=record["username"], is_admin=record["is_admin"], user_id=record["id"])
    set_session_cookie(response, request, token)
    audit.emit(audit.LOGIN_SUCCESS, actor_username=record["username"], actor_ip=ip, detail="with two-factor code")
    return {"token": token, "user": {"username": record["username"], "is_admin": record["is_admin"], "id": record["id"]}}


@router.post("/auth/mfa/reset/{user_id}")
async def mfa_reset(user_id: str, request: Request, user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    """Admin: turn off another user's MFA (lost phone). They set it up again."""
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only.")
    target = _user_store.get_user(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    with get_session() as session:
        row = session.get(UserMFA, user_id)
        if row:
            session.delete(row)
            session.commit()
    audit.emit(audit.MFA_RESET, actor_username=user.username, target_username=target["username"],
               actor_ip=request.client.host if request.client else None)
    return {"enabled": False}


@router.put("/auth/mfa/policy")
async def mfa_policy(payload: PolicyIn, user: SessionUser = Depends(get_current_user_from_token)) -> dict:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only.")
    if payload.require_for_admins and not is_enabled(user.user_id):
        raise HTTPException(status_code=409, detail="Turn on two-factor authentication for your own account first.")
    with get_session() as session:
        session.merge(PortalSetting(key=POLICY_KEY, value="true" if payload.require_for_admins else "false"))
        session.commit()
    audit.emit(audit.MFA_POLICY, actor_username=user.username,
               detail=f"required for admins: {payload.require_for_admins}")
    return {"require_for_admins": payload.require_for_admins}
