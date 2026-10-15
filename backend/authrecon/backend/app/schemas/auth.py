from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str
    password: str = Field(..., min_length=1)


class PortalLoginRequest(BaseModel):
    token: str = Field(..., min_length=10)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class TokenPayload(BaseModel):
    sub: str
    exp: int
