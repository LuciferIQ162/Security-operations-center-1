import time
import bcrypt
import jwt
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException
from config import settings

ALGORITHM = "HS256"

failed_attempts_ip: Dict[str, Dict[str, Any]] = {}

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def create_session_token(user_id: str, role: str) -> str:
    exp = int(time.time()) + settings.session_exp_minutes * 60
    payload = {"sub": user_id, "role": role, "exp": exp}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)

def decode_session_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid session")

def generate_csrf_token() -> str:
    return bcrypt.gensalt().decode()

def validate_csrf(request: Request):
    header = request.headers.get("X-CSRF-Token")
    cookie = request.cookies.get("csrf_token")
    if not header or not cookie or header != cookie:
        raise HTTPException(status_code=403, detail="CSRF validation failed")

def rate_limit_login(ip: str):
    now = time.time()
    window = 300
    limit = 10
    rec = failed_attempts_ip.get(ip, {"count": 0, "ts": now})
    if now - rec["ts"] > window:
        rec = {"count": 0, "ts": now}
    if rec["count"] >= limit:
        raise HTTPException(status_code=429, detail="Too many login attempts")
    rec["count"] += 1
    failed_attempts_ip[ip] = rec
