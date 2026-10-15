"""
JSON API Authentication Scenario
REST API with JSON payload and JWT token response.
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, HTTPException, status
from pydantic import BaseModel
from jose import jwt

from ...main import verify_credentials, telemetry

router = APIRouter()

# JWT settings
SECRET_KEY = "loginlab-jwt-secret-key-for-testing-only"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


class APILoginRequest(BaseModel):
    username: str
    password: str


class APITokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: dict


def create_access_token(username: str, role: str) -> tuple[str, str]:
    """Create JWT access token."""
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, expire.isoformat()


@router.post("/api/auth", response_model=APITokenResponse)
async def api_auth_endpoint(request: Request, credentials: APILoginRequest):
    """
    JSON API authentication endpoint.
    Returns JWT token on successful authentication.
    """
    telemetry_data = {
        "method": request.method,
        "path": str(request.url.path),
        "content_type": request.headers.get("content-type"),
        "username": credentials.username,
    }

    # Verify credentials
    user = verify_credentials(credentials.username, credentials.password)

    if not user:
        telemetry.record(
            scenario="api-auth",
            request_data=telemetry_data,
            response_data={
                "status": 401,
                "error": "Invalid credentials",
            },
            detection_hints={
                "auth_type": "api_token",
                "auth_failed": True,
                "content_type": "application/json",
            },
            success=False,
            run_id=request.headers.get("X-AuthRecon-Run-ID"),
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Create JWT token
    access_token, expires_at = create_access_token(
        username=credentials.username,
        role=user["role"],
    )

    telemetry.record(
        scenario="api-auth",
        request_data=telemetry_data,
        response_data={
            "status": 200,
            "token_type": "Bearer",
            "expires_at": expires_at,
        },
        detection_hints={
            "auth_type": "api_token",
            "auth_successful": True,
            "token_format": "JWT",
            "user_role": user["role"],
        },
        success=True,
        run_id=request.headers.get("X-AuthRecon-Run-ID"),
    )

    return APITokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
        user={
            "username": credentials.username,
            "display_name": user["display_name"],
            "role": user["role"],
        },
    )


@router.get("/api/auth/verify")
async def api_auth_verify(request: Request):
    """Verify JWT token (for testing)."""
    authorization = request.headers.get("Authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
        )

    token = authorization[7:]  # Remove "Bearer " prefix

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {
            "valid": True,
            "username": payload.get("sub"),
            "role": payload.get("role"),
            "expires_at": payload.get("exp"),
        }
    except jwt.JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        )
