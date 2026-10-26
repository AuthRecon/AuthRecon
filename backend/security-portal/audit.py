"""Security audit log helper — write audit events to the database.

Call emit() at any security-relevant event. Fails silently so a DB hiccup
never blocks a login or user operation.

Event types (use these constants):
  LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT
  USER_CREATED, USER_DELETED, USER_UPDATED
  PASSWORD_CHANGED, PASSWORD_RESET
  ROLE_CHANGED, USER_DEACTIVATED, USER_ACTIVATED
  SETUP_COMPLETED
  CREDENTIAL_REVEALED
  LOGINLAB_ENABLED, LOGINLAB_DISABLED
  SECURITY_NOTICE_ACKNOWLEDGED
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("portal.audit")

LOGIN_SUCCESS = "login_success"
LOGIN_FAILURE = "login_failure"
LOGOUT = "logout"
USER_CREATED = "user_created"
USER_DELETED = "user_deleted"
USER_UPDATED = "user_updated"
PASSWORD_CHANGED = "password_changed"
PASSWORD_RESET = "password_reset"
SETUP_COMPLETED = "setup_completed"
CREDENTIAL_REVEALED = "credential_revealed"
ROLE_CHANGED = "role_changed"
USER_DEACTIVATED = "user_deactivated"
USER_ACTIVATED = "user_activated"
LOGINLAB_ENABLED = "loginlab_enabled"
LOGINLAB_DISABLED = "loginlab_disabled"
SECURITY_NOTICE_ACKNOWLEDGED = "security_notice_acknowledged"
MFA_ENABLED = "mfa_enabled"
MFA_DISABLED = "mfa_disabled"
MFA_FAILURE = "mfa_failure"
MFA_RESET = "mfa_reset"
MFA_BACKUP_CODES = "mfa_backup_codes_regenerated"
MFA_POLICY = "mfa_policy_changed"


def emit(
    event_type: str,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    try:
        from database import get_session
        from models.audit_log import AuditLog

        session = get_session()
        try:
            entry = AuditLog(
                event_type=event_type,
                actor_username=actor_username,
                actor_ip=actor_ip,
                target_username=target_username,
                detail=detail,
            )
            session.add(entry)
            session.commit()
        finally:
            session.close()
    except Exception:
        logger.warning("Failed to write audit log event: %s actor=%s", event_type, actor_username, exc_info=True)
