"""At-rest encryption for run artifacts.

On-disk format (ASCII):  ``ARENC:<key-id>:<fernet-token>``

``key-id`` names the key that encrypted the file, so keys can be rotated later
without guessing:
- ``p1``: the run owner's per-profile artifact key (``artifact_key_encrypted``),
  version 1. The same per-user Fernet key that already protected ``.side`` files.
- ``m1``: the deployment master key (``get_credential_cipher``), version 1. Used
  only for runs with no owner profile, so nothing is ever stored in plaintext.

A rotation adds e.g. ``p2``: new writes use the new id, reads look the id up,
and the migration helper can re-wrap old files.

Legacy formats, still readable until the migration has run:
- raw Fernet token with ``Artifact.is_encrypted = True`` (old ``.side`` files)
- plaintext (everything else written before this change)

Decryption happens only in ``read_artifact_bytes``, which callers reach after
their owner-or-admin check.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

MAGIC = b"ARENC:"
PROFILE_KEY_V1 = "p1"
MASTER_KEY_V1 = "m1"
CURRENT_PROFILE_KEY_ID = PROFILE_KEY_V1
CURRENT_MASTER_KEY_ID = MASTER_KEY_V1
_KEY_ID_RE = re.compile(rb"^[a-z][0-9]{1,4}$")


class ArtifactDecryptError(Exception):
    """The artifact exists but cannot be decrypted (missing owner/key, bad token)."""


@dataclass(frozen=True)
class ArtifactKey:
    key_id: str
    cipher: Fernet


def is_wrapped(data: bytes) -> bool:
    return data.startswith(MAGIC)


def wrap(data: bytes, key: ArtifactKey) -> bytes:
    if is_wrapped(data):
        raise ValueError("Artifact is already encrypted")
    return MAGIC + key.key_id.encode("ascii") + b":" + key.cipher.encrypt(data)


def parse(data: bytes) -> tuple[str, bytes]:
    if not is_wrapped(data):
        raise ValueError("Not an encrypted artifact")
    rest = data[len(MAGIC):]
    key_id, sep, token = rest.partition(b":")
    if not sep or not _KEY_ID_RE.match(key_id):
        raise ArtifactDecryptError("Malformed encrypted artifact header")
    return key_id.decode("ascii"), token


def unwrap(data: bytes, resolve_cipher: Callable[[str], Fernet]) -> bytes:
    key_id, token = parse(data)
    try:
        return resolve_cipher(key_id).decrypt(token)
    except InvalidToken as exc:
        raise ArtifactDecryptError(f"Unable to decrypt artifact with key {key_id}") from exc


# --- key resolution -----------------------------------------------------------


def _profile_cipher(db, profile) -> Fernet:
    from app.services.profiles import get_profile_artifact_cipher

    return get_profile_artifact_cipher(db, profile)


def _master_cipher() -> Fernet:
    from app.core.security import get_credential_cipher

    return get_credential_cipher()


def write_key_for_run(db, run) -> ArtifactKey:
    """The key new artifacts of ``run`` are encrypted with."""
    owner = getattr(run, "submitted_by", None)
    if owner is not None:
        return ArtifactKey(CURRENT_PROFILE_KEY_ID, _profile_cipher(db, owner))
    return ArtifactKey(CURRENT_MASTER_KEY_ID, _master_cipher())


def write_key_for_profile(db, profile) -> ArtifactKey:
    """Key for owner-scoped files that don't belong to a run (e.g. scan exports)."""
    return ArtifactKey(CURRENT_PROFILE_KEY_ID, _profile_cipher(db, profile))


def unwrap_for_profile(data: bytes, *, db, profile) -> bytes:
    """Decrypt an owner-scoped file. Call only after an owner-or-admin check."""

    def resolve(key_id: str) -> Fernet:
        if key_id == PROFILE_KEY_V1:
            return _profile_cipher(db, profile)
        if key_id == MASTER_KEY_V1:
            return _master_cipher()
        raise ArtifactDecryptError(f"Unknown artifact key id {key_id!r}")

    return unwrap(data, resolve)


def cipher_resolver_for_run(db, run) -> Callable[[str], Fernet]:
    """Map a key id from a file header to the cipher that can decrypt it."""

    def resolve(key_id: str) -> Fernet:
        if key_id == PROFILE_KEY_V1:
            owner = getattr(run, "submitted_by", None)
            if owner is None:
                raise ArtifactDecryptError("Owner profile unavailable for this artifact")
            return _profile_cipher(db, owner)
        if key_id == MASTER_KEY_V1:
            return _master_cipher()
        raise ArtifactDecryptError(f"Unknown artifact key id {key_id!r}")

    return resolve


def run_key_resolver(run_id: str) -> ArtifactKey:
    """Fallback resolver for ArtifactStorage when the worker did not bind a key.

    Read-only: it never provisions a profile key (doing that in a second session
    could race the worker's session and orphan one of two keys). Workers bind the
    key up front with ``storage.bind_run_key`` in their own session.
    """
    from app.db import SessionLocal
    from app.models import Run

    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if run is None:
            raise ArtifactDecryptError(f"Run {run_id} not found; refusing to store an unencrypted artifact")
        owner = getattr(run, "submitted_by", None)
        if owner is not None and not owner.artifact_key_encrypted:
            raise ArtifactDecryptError("Owner has no artifact key yet; bind the run key first")
        return write_key_for_run(db, run)
    finally:
        db.close()


# --- reading ------------------------------------------------------------------


def decode_artifact_payload(data: bytes, *, db, run, artifact) -> bytes:
    """Decrypt stored bytes for ``artifact`` (new, legacy-encrypted or legacy-plain)."""
    if is_wrapped(data):
        return unwrap(data, cipher_resolver_for_run(db, run))
    if getattr(artifact, "is_encrypted", False):
        owner = getattr(run, "submitted_by", None)
        if owner is None:
            raise ArtifactDecryptError("Owner profile unavailable for this artifact")
        try:
            return _profile_cipher(db, owner).decrypt(data)
        except InvalidToken as exc:
            raise ArtifactDecryptError("Unable to decrypt artifact with the current owner key") from exc
    # Legacy plaintext (pre-migration). Never hand out an unmasked HAR:
    # requests and response bodies, using the run's own known passwords.
    if _is_har(artifact):
        return scrub_har_for_run(data, db=db, run=run)
    return data


def scrub_har_for_run(data: bytes, *, db, run) -> bytes:
    """Mask a plaintext HAR with the run's known passwords (same bytes if clean)."""
    from app.services.har_redaction import mask_har_bytes
    from app.services.run_secrets import known_secrets_for_run

    return mask_har_bytes(data, known_secrets=known_secrets_for_run(db, run))


def read_artifact_bytes(db, run, artifact, storage) -> bytes:
    """Read and decrypt an artifact. Call only after an owner-or-admin check."""
    if not artifact.storage_path:
        raise FileNotFoundError("Artifact missing storage path")
    try:
        path = storage.resolve(artifact.storage_path)
    except (ValueError, FileNotFoundError) as exc:
        raise FileNotFoundError("Artifact file missing") from exc
    return decode_artifact_payload(path.read_bytes(), db=db, run=run, artifact=artifact)


def _is_har(artifact: Any) -> bool:
    name = (getattr(artifact, "name", "") or "").lower()
    return getattr(artifact, "type", None) == "har" or name.endswith(".har")


# --- keep Artifact.is_encrypted truthful --------------------------------------


def _sync_is_encrypted(mapper, connection, target) -> None:
    if not target.storage_path:
        return
    try:
        from app.services.storage import get_artifact_storage

        with get_artifact_storage().resolve(target.storage_path).open("rb") as fh:
            target.is_encrypted = is_wrapped(fh.read(len(MAGIC))) or bool(target.is_encrypted)
    except Exception:  # missing file etc. - leave the flag as the caller set it
        pass


def register_model_hooks() -> None:
    from sqlalchemy import event

    from app.models import Artifact

    if not event.contains(Artifact, "before_insert", _sync_is_encrypted):
        event.listen(Artifact, "before_insert", _sync_is_encrypted)
        event.listen(Artifact, "before_update", _sync_is_encrypted)


# --- session cookies on the run row -------------------------------------------

def encrypt_run_cookies(db, run, cookies: list) -> str:
    """Encrypt a run's captured session cookies for ``Run.session_cookies_enc``.

    Uses the same key choice as artifacts: the owner's profile key, or the
    master key for runs with no owner, so cookies are never stored in plaintext.
    """
    import json

    return wrap(json.dumps(cookies).encode(), write_key_for_run(db, run)).decode("ascii")


def decrypt_run_cookies(db, run) -> list:
    """Decrypt ``Run.session_cookies_enc``. Call only after an owner-or-admin check.

    Reads both the ``ARENC:`` format and the older bare Fernet token written
    with the owner's profile key. Returns [] if there is nothing to decrypt.
    """
    import json

    enc = getattr(run, "session_cookies_enc", None)
    if not enc:
        return []
    data = enc.encode("ascii")
    if is_wrapped(data):
        plain = unwrap(data, cipher_resolver_for_run(db, run))
    else:
        owner = getattr(run, "submitted_by", None)
        if owner is None:
            raise ArtifactDecryptError("Owner profile unavailable for these cookies")
        try:
            plain = _profile_cipher(db, owner).decrypt(data)
        except InvalidToken as exc:
            raise ArtifactDecryptError("Unable to decrypt session cookies") from exc
    cookies = json.loads(plain)
    return cookies if isinstance(cookies, list) else []
