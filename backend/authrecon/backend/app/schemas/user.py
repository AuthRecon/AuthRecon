from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class AuthProvider(str, Enum):
    local = "local"
    ldap = "ldap"
    azure_ad = "azure_ad"
    portal = "portal"


class UserBase(BaseModel):
    email: EmailStr
    full_name: str | None = None
    auth_provider: AuthProvider = Field(default=AuthProvider.local)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    is_admin: bool = False
    is_active: bool = True


class UserUpdate(BaseModel):
    full_name: str | None = None
    password: str | None = Field(default=None, min_length=8)
    is_admin: bool | None = None
    is_active: bool | None = None


class UserRead(UserBase):
    id: str
    is_admin: bool
    is_active: bool
    llm_enabled: bool = True
    last_login_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
