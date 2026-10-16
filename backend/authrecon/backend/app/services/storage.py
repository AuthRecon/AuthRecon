from __future__ import annotations

import os
import re
from functools import lru_cache
import shutil
from pathlib import Path

from contextlib import contextmanager
from typing import Callable, Iterable, Iterator

from app.core.config import get_settings
from app.services.artifact_crypto import ArtifactKey, is_wrapped, run_key_resolver, wrap
from app.services.har_redaction import mask_har_bytes


class ArtifactStorage:
    """
    Filesystem-backed artifact storage. Every artifact is encrypted at rest
    (see app/services/artifact_crypto.py) and every ``*.har`` has password
    values masked before it is written. There is no plaintext write path.
    """

    def __init__(
        self,
        base_path: Path,
        *,
        key_resolver: Callable[[str], ArtifactKey] = run_key_resolver,
    ) -> None:
        self.base_path = base_path
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._key_resolver = key_resolver
        self._run_keys: dict[str, ArtifactKey] = {}
        self._run_secrets: dict[str, list[str]] = {}

    def bind_run_key(self, run_id: str, key: ArtifactKey) -> None:
        """Use ``key`` for this run's artifacts (the worker binds it in its own session)."""
        self._run_keys[run_id] = key

    @contextmanager
    def redacting(self, run_id: str, secrets: Iterable[str | None]) -> Iterator[None]:
        """While active, exact occurrences of ``secrets`` are masked in this run's HARs."""
        values = [s for s in secrets if s]
        self._run_secrets[run_id] = values
        try:
            yield
        finally:
            self._run_secrets.pop(run_id, None)

    def release_run(self, run_id: str) -> None:
        self._run_keys.pop(run_id, None)
        self._run_secrets.pop(run_id, None)

    def _key_for(self, run_id: str) -> ArtifactKey:
        key = self._run_keys.get(run_id)
        if key is None:
            key = self._key_resolver(run_id)  # raises rather than allow plaintext
            self._run_keys[run_id] = key
        return key

    def prepare_bytes(self, run_id: str, file_name: str, data: bytes) -> bytes:
        """Mask (HARs) and encrypt ``data`` exactly as ``save_bytes`` stores it."""
        if is_wrapped(data):
            raise ValueError("Pass plaintext to storage; it encrypts artifacts itself")
        if file_name.lower().endswith(".har"):
            data = mask_har_bytes(data, known_secrets=self._run_secrets.get(run_id, ()))
        return wrap(data, self._key_for(run_id))

    def save_bytes(self, run_id: str, file_name: str, data: bytes) -> str:
        """
        Mask, encrypt and persist artifact bytes beneath
        <base>/<run_id>/<safe_file_name>; return the relative storage path.
        """
        safe_run_id = self._sanitize_segment(run_id) or "run"
        safe_name = self._sanitize_filename(file_name) or "artifact.bin"
        relative_path = Path(safe_run_id) / safe_name
        storage_path = self._resolve(relative_path)
        payload = self.prepare_bytes(run_id, file_name, data)
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(storage_path, payload)
        return str(relative_path.as_posix())

    def read_stored(self, relative_path: str) -> bytes:
        """The stored (still encrypted) bytes at a path ``save_bytes`` returned."""
        return self._resolve(Path(relative_path)).read_bytes()

    def replace_bytes(self, relative_path: str, payload: bytes) -> None:
        """Atomically overwrite an existing artifact with already-prepared bytes (migration)."""
        self._atomic_write(self._resolve(Path(relative_path)), payload)

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, path)

    def resolve(self, relative_path: str) -> Path:
        """
        Resolve a stored artifact path to an absolute filesystem path.
        """
        storage_path = self._resolve(Path(relative_path))
        if not storage_path.exists():
            raise FileNotFoundError(relative_path)
        return storage_path

    def delete_run(self, run_id: str) -> None:
        """
        Remove all artifacts for a run.
        """
        safe_run_id = self._sanitize_segment(run_id) or "run"
        run_dir = (self.base_path / safe_run_id).resolve()
        try:
            if run_dir.is_relative_to(self.base_path) and run_dir.exists():
                shutil.rmtree(run_dir, ignore_errors=True)
        except Exception:
            pass

    def _resolve(self, suffix: Path) -> Path:
        candidate = (self.base_path / suffix).resolve()
        if not candidate.is_relative_to(self.base_path):
            raise ValueError("Invalid artifact path outside storage root")
        return candidate

    @staticmethod
    def _sanitize_segment(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "-", value)

    @staticmethod
    def _sanitize_filename(value: str) -> str:
        name = re.sub(r"[\\/]", "-", value)
        return re.sub(r"[^A-Za-z0-9._-]", "-", name)


@lru_cache
def get_artifact_storage() -> ArtifactStorage:
    settings = get_settings()
    base = settings.artifact_storage_dir
    if not base.is_absolute():
        base = (Path(os.getcwd()) / base).resolve()
    return ArtifactStorage(base)
