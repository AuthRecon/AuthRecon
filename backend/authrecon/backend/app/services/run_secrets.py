"""Resolve the passwords a run used, so they can be scrubbed from its HARs.

Mirrors how the worker obtains them (app/worker.py process_run/_build_variants):
the stored credential (``options.credential_id``), a one-time secret
(``options.one_time_secret``) and per-role secrets (``options.scope.roles[].secret``).
Values are only ever used for redaction: never logged, returned to clients or
stored. Anything that can't be resolved (e.g. a deleted credential) is skipped.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _decrypt_master(token: Any) -> str | None:
    if not isinstance(token, str) or not token:
        return None
    try:
        from app.core.security import get_credential_cipher

        return get_credential_cipher().decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return None


def known_secrets_for_run(db, run) -> list[str]:
    options = run.options if isinstance(getattr(run, "options", None), dict) else {}
    secrets: list[str] = []

    credential_id = options.get("credential_id")
    if credential_id:
        try:
            from app.models import StoredCredential
            from app.services.credentials import get_plain_secret

            credential = db.get(StoredCredential, credential_id)
            if credential is not None:
                secrets.append(get_plain_secret(credential))
        except Exception:
            logger.warning("Could not resolve the stored credential for run %s", getattr(run, "id", "?"))

    one_time = _decrypt_master(options.get("one_time_secret"))
    if one_time:
        secrets.append(one_time)

    scope = options.get("scope") if isinstance(options.get("scope"), dict) else {}
    for role in scope.get("roles") or []:
        if isinstance(role, dict):
            value = _decrypt_master(role.get("secret"))
            if value:
                secrets.append(value)

    # De-duplicate, keep order; drop empties.
    return list(dict.fromkeys(s for s in secrets if s))
