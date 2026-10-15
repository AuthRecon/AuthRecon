"""Portal user management API endpoints."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from auth import SessionUser, get_current_user_from_token
from validation import validate_password
import audit


router = APIRouter()


class UserCreate(BaseModel):
    """Request model for creating a new user."""

    username: str = Field(..., min_length=3, max_length=255, description="Username (email format recommended)")
    password: str = Field(..., min_length=12, description="Password (minimum 12 characters, must include uppercase, digit, and special character)")
    full_name: str | None = Field(None, max_length=255, description="Full name")
    is_admin: bool = Field(False, description="Admin role flag")
    is_active: bool = Field(True, description="Account active status")


class UserUpdate(BaseModel):
    """Request model for updating a user."""

    full_name: str | None = Field(None, max_length=255, description="Full name")
    is_admin: bool | None = Field(None, description="Admin role flag")
    is_active: bool | None = Field(None, description="Account active status")
    password: str | None = Field(None, min_length=12, description="New password (optional, must meet complexity policy if provided)")


class PasswordChangeRequest(BaseModel):
    """Request model for user self-service password change."""

    current_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(..., min_length=12, description="New password (must meet complexity policy)")


class AdminPasswordResetRequest(BaseModel):
    """Request model for admin to reset a user's password."""

    new_password: str = Field(..., min_length=12, description="New password (must meet complexity policy)")


class UserResponse(BaseModel):
    """Response model for user data."""

    id: str
    username: str
    full_name: str | None
    is_admin: bool
    is_active: bool
    created_at: str
    last_login_at: str | None


def require_admin(current_user: Annotated[SessionUser, Depends(get_current_user_from_token)]) -> SessionUser:
    """Dependency to require admin role."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


def _audit_user_update(actor: str, before: dict | None, after: dict, *, password_changed: bool) -> None:
    """Record exactly what changed, so role and status changes stand out."""
    target = after["username"]
    if before is not None and before["is_admin"] != after["is_admin"]:
        audit.emit(audit.ROLE_CHANGED, actor_username=actor, target_username=target,
                   detail="granted admin" if after["is_admin"] else "removed admin")
    if before is not None and before["is_active"] != after["is_active"]:
        audit.emit(audit.USER_ACTIVATED if after["is_active"] else audit.USER_DEACTIVATED,
                   actor_username=actor, target_username=target)
    if password_changed:
        audit.emit(audit.PASSWORD_RESET, actor_username=actor, target_username=target)
    if before is not None and before.get("full_name") != after.get("full_name"):
        audit.emit(audit.USER_UPDATED, actor_username=actor, target_username=target, detail="full_name")


@router.get("/users", response_model=list[UserResponse])
def list_users(
    request: Request,
    current_user: Annotated[SessionUser, Depends(require_admin)],
) -> list[UserResponse]:
    """List all portal users (admin only)."""
    user_store = request.app.state.user_store
    users = user_store.list_users()
    return [
        UserResponse(
            id=u["id"],
            username=u["username"],
            full_name=u.get("full_name"),
            is_admin=u["is_admin"],
            is_active=u["is_active"],
            created_at=u["created_at"].isoformat() if u.get("created_at") else None,
            last_login_at=u["last_login_at"].isoformat() if u.get("last_login_at") else None,
        )
        for u in users
    ]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    request: Request,
    payload: UserCreate,
    current_user: Annotated[SessionUser, Depends(require_admin)],
) -> UserResponse:
    """Create a new portal user (admin only)."""
    user_store = request.app.state.user_store
    pw_error = validate_password(payload.password)
    if pw_error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_error)
    try:
        user = user_store.add_user(
            username=payload.username,
            password=payload.password,
            full_name=payload.full_name,
            is_admin=payload.is_admin,
            is_active=payload.is_active,
        )
        audit.emit(audit.USER_CREATED, actor_username=current_user.username, target_username=user["username"])
        return UserResponse(
            id=user["id"],
            username=user["username"],
            full_name=user.get("full_name"),
            is_admin=user["is_admin"],
            is_active=user["is_active"],
            created_at=user["created_at"].isoformat() if user.get("created_at") else None,
            last_login_at=user["last_login_at"].isoformat() if user.get("last_login_at") else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    request: Request,
    user_id: str,
    current_user: Annotated[SessionUser, Depends(require_admin)],
) -> UserResponse:
    """Get user by ID (admin only)."""
    user_store = request.app.state.user_store
    user = user_store.get_user(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse(
        id=user["id"],
        username=user["username"],
        full_name=user.get("full_name"),
        is_admin=user["is_admin"],
        is_active=user["is_active"],
        created_at=user["created_at"].isoformat() if user.get("created_at") else None,
        last_login_at=user["last_login_at"].isoformat() if user.get("last_login_at") else None,
    )


@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user(
    request: Request,
    user_id: str,
    payload: UserUpdate,
    current_user: Annotated[SessionUser, Depends(require_admin)],
) -> UserResponse:
    """Update user (admin only)."""
    user_store = request.app.state.user_store

    # Self-protection rules
    if user_id == current_user.user_id:
        if payload.is_admin is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote yourself from admin",
            )
        if payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate yourself",
            )

    # Check if this is the last admin
    if payload.is_admin is False:
        all_users = user_store.list_users()
        admin_count = sum(1 for u in all_users if u["is_admin"] and u["id"] != user_id)
        if admin_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last admin user",
            )

    if payload.password is not None:
        pw_error = validate_password(payload.password)
        if pw_error:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_error)

    before = user_store.get_user(user_id)
    try:
        user = user_store.update_user(
            user_id=user_id,
            full_name=payload.full_name,
            is_admin=payload.is_admin,
            is_active=payload.is_active,
            password=payload.password,
        )
        _audit_user_update(current_user.username, before, user, password_changed=payload.password is not None)
        return UserResponse(
            id=user["id"],
            username=user["username"],
            full_name=user.get("full_name"),
            is_admin=user["is_admin"],
            is_active=user["is_active"],
            created_at=user["created_at"].isoformat() if user.get("created_at") else None,
            last_login_at=user["last_login_at"].isoformat() if user.get("last_login_at") else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    request: Request,
    user_id: str,
    current_user: Annotated[SessionUser, Depends(require_admin)],
):
    """Delete user (admin only)."""
    user_store = request.app.state.user_store

    # Self-protection
    if user_id == current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself",
        )

    # Check if this is the last admin
    user = user_store.get_user(user_id)
    if user and user["is_admin"]:
        all_users = user_store.list_users()
        admin_count = sum(1 for u in all_users if u["is_admin"] and u["id"] != user_id)
        if admin_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last admin user",
            )

    deleted_username = user["username"] if user else user_id
    try:
        user_store.delete_user(user_id)
        audit.emit(audit.USER_DELETED, actor_username=current_user.username, target_username=deleted_username)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/users/me/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_own_password(
    request: Request,
    payload: PasswordChangeRequest,
    current_user: Annotated[SessionUser, Depends(get_current_user_from_token)],
):
    """Change own password (requires current password verification)."""
    user_store = request.app.state.user_store

    # Verify current password
    user = user_store.get_user(current_user.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not user_store.verify_password(payload.current_password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    pw_error = validate_password(payload.new_password)
    if pw_error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_error)

    # Update to new password
    try:
        user_store.update_user(
            user_id=current_user.user_id,
            password=payload.new_password,
        )
        audit.emit(audit.PASSWORD_CHANGED, actor_username=current_user.username)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/users/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_user_password(
    request: Request,
    user_id: str,
    payload: AdminPasswordResetRequest,
    current_user: Annotated[SessionUser, Depends(require_admin)],
):
    """Reset user password (admin only, no current password required)."""
    user_store = request.app.state.user_store

    # Verify target user exists
    user = user_store.get_user(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    pw_error = validate_password(payload.new_password)
    if pw_error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_error)

    # Update to new password
    try:
        user_store.update_user(
            user_id=user_id,
            password=payload.new_password,
        )
        audit.emit(audit.PASSWORD_RESET, actor_username=current_user.username, target_username=user["username"])
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
