"""Cookie Analysis Service - Decode and analyze session cookies."""
import base64
import json
import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import jwt
from pydantic import BaseModel


class CookieAnalysis(BaseModel):
    """Analyzed cookie data."""
    name: str
    value: str
    decoded_value: Optional[str] = None
    cookie_type: str  # "jwt", "base64", "flask_session", "encrypted", "plain"
    claims: Optional[Dict[str, Any]] = None
    entropy: float
    security_notes: List[str]
    expires: Optional[str] = None
    is_secure: bool = False
    is_httponly: bool = False
    same_site: Optional[str] = None


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (measure of randomness)."""
    if not data:
        return 0.0

    # Count frequency of each character
    counts = Counter(data)
    total = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT token without verification (just read claims)."""
    try:
        # JWT format: header.payload.signature (3 base64-encoded parts)
        parts = token.split('.')
        if len(parts) != 3:
            return None

        # Decode without verification (we just want to see the data, not validate)
        decoded = jwt.decode(token, options={"verify_signature": False})

        # Also decode header
        header = jwt.get_unverified_header(token)

        return {
            "header": header,
            "payload": decoded
        }
    except Exception:
        return None


def try_base64_decode(value: str) -> Optional[str]:
    """Attempt to decode base64 string."""
    try:
        # Try standard base64
        decoded_bytes = base64.b64decode(value, validate=True)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

        # Only return if it looks like meaningful text
        if decoded_str and decoded_str.isprintable():
            return decoded_str
        return None
    except Exception:
        return None


def detect_flask_session(value: str) -> Optional[Dict[str, Any]]:
    """Detect and decode Flask session cookie (itsdangerous format)."""
    try:
        # Flask sessions start with "eyJ" after base64 decode (JSON object)
        decoded = try_base64_decode(value)
        if decoded and decoded.startswith('{'):
            # Try to parse as JSON
            data = json.loads(decoded)
            return {
                "type": "flask_session",
                "data": data
            }
        return None
    except Exception:
        return None


def analyze_cookie_security(name: str, value: str, cookie_attrs: Dict[str, Any]) -> List[str]:
    """Analyze cookie for security issues."""
    notes = []

    # Check for session cookie indicators
    session_keywords = ['session', 'sid', 'sess', 'token', 'auth', 'login']
    is_session_cookie = any(keyword in name.lower() for keyword in session_keywords)

    if is_session_cookie:
        if not cookie_attrs.get('httponly'):
            notes.append("⚠️ Session cookie missing HttpOnly flag (XSS risk)")

        if not cookie_attrs.get('secure'):
            notes.append("⚠️ Session cookie missing Secure flag (MITM risk)")

        same_site = cookie_attrs.get('samesite', '').lower()
        if same_site not in ['strict', 'lax']:
            notes.append("⚠️ Session cookie missing SameSite protection (CSRF risk)")

    # Check entropy
    entropy = calculate_entropy(value)
    if entropy < 2.0:
        notes.append(f"🔓 Low entropy ({entropy:.1f}) - cookie value may be predictable")
    elif entropy > 4.5:
        notes.append(f"🔐 High entropy ({entropy:.1f}) - likely encrypted or securely random")

    return notes


def analyze_cookie(name: str, value: str, cookie_attrs: Optional[Dict[str, Any]] = None) -> CookieAnalysis:
    """
    Analyze a cookie and try to decode it.

    Args:
        name: Cookie name
        value: Cookie value
        cookie_attrs: Optional cookie attributes (secure, httponly, samesite, expires)

    Returns:
        CookieAnalysis with decoded information
    """
    if cookie_attrs is None:
        cookie_attrs = {}

    decoded_value = None
    cookie_type = "plain"
    claims = None
    security_notes = []

    # 1. Try JWT decode
    jwt_data = decode_jwt_token(value)
    if jwt_data:
        cookie_type = "jwt"
        claims = jwt_data["payload"]
        decoded_value = json.dumps(jwt_data, indent=2)

        # Analyze JWT claims
        if "exp" in claims:
            exp_timestamp = claims["exp"]
            exp_date = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            if exp_date < now:
                security_notes.append("⏰ JWT token is expired")
            else:
                time_left = exp_date - now
                if time_left.days < 1:
                    security_notes.append(f"⏰ JWT expires in {time_left.seconds // 3600} hours")
        else:
            security_notes.append("⚠️ JWT has no expiry claim (security risk)")

        if "roles" in claims:
            security_notes.append(f"👤 Roles: {', '.join(claims['roles'])}")

        if "is_admin" in claims and claims["is_admin"]:
            security_notes.append("🔑 Admin privileges detected")

    # 2. Try Flask session decode
    elif (flask_data := detect_flask_session(value)):
        cookie_type = "flask_session"
        decoded_value = json.dumps(flask_data["data"], indent=2)
        security_notes.append("🐍 Flask session cookie (signed with server secret)")

    # 3. Try base64 decode
    elif (b64_decoded := try_base64_decode(value)):
        # Check if it looks like JSON
        try:
            json_data = json.loads(b64_decoded)
            cookie_type = "base64_json"
            decoded_value = json.dumps(json_data, indent=2)
            security_notes.append("📦 Base64-encoded JSON data")
        except Exception:
            cookie_type = "base64"
            decoded_value = b64_decoded
            security_notes.append("📦 Base64-encoded text")

    # 4. Check if encrypted (high entropy, not decodable)
    else:
        entropy = calculate_entropy(value)
        if entropy > 4.5:
            cookie_type = "encrypted"
            security_notes.append("🔒 Appears to be encrypted (high entropy, cannot decode)")

    # Add general security analysis
    security_notes.extend(analyze_cookie_security(name, value, cookie_attrs))

    return CookieAnalysis(
        name=name,
        value=value,
        decoded_value=decoded_value,
        cookie_type=cookie_type,
        claims=claims,
        entropy=calculate_entropy(value),
        security_notes=security_notes,
        expires=cookie_attrs.get('expires'),
        is_secure=cookie_attrs.get('secure', False),
        is_httponly=cookie_attrs.get('httponly', False),
        same_site=cookie_attrs.get('samesite')
    )


def analyze_cookies_from_har(cookies: List[Dict[str, Any]]) -> List[CookieAnalysis]:
    """
    Analyze cookies from HAR file format.

    Args:
        cookies: List of cookie dicts from HAR (name, value, httpOnly, secure, etc.)

    Returns:
        List of analyzed cookies
    """
    results = []

    for cookie in cookies:
        name = cookie.get('name', '')
        value = cookie.get('value', '')

        cookie_attrs = {
            'httponly': cookie.get('httpOnly', False),
            'secure': cookie.get('secure', False),
            'samesite': cookie.get('sameSite'),
            'expires': cookie.get('expires')
        }

        analysis = analyze_cookie(name, value, cookie_attrs)
        results.append(analysis)

    return results
