"""Artifacts are encrypted at rest with a versioned per-user key; decrypted only on read."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet

from app.models import Artifact
from app.services import artifact_crypto as ac
from app.services.profiles import get_profile_artifact_cipher

SECRET = "Sup3r-Secret!pw"
HAR = json.dumps({"log": {"entries": [{"request": {"url": "https://t.invalid/login", "postData": {
    "mimeType": "application/x-www-form-urlencoded",
    "params": [{"name": "password", "value": SECRET}], "text": f"user=a&password={SECRET}"}}}]}}).encode()
SIDE = json.dumps({"tests": [{"commands": [{"command": "type", "target": "id=password", "value": SECRET}]}]}).encode()


def _artifact(db, run, path, name, type_, is_encrypted=False):
    art = Artifact(id=str(uuid.uuid4())[:40], run_id=run.id, name=name, type=type_, size_bytes=0,
                   storage_path=path, created_at=datetime.now(timezone.utc), is_encrypted=is_encrypted)
    db.add(art)
    db.commit()
    return art


def test_saved_artifacts_are_versioned_ciphertext(db_session, artifact_storage, make_run):
    run, _ = make_run()
    path = artifact_storage.save_bytes(run.id, "login.side", SIDE)
    raw = artifact_storage.resolve(path).read_bytes()
    assert raw.startswith(b"ARENC:p1:") and SECRET.encode() not in raw


def test_side_keeps_plaintext_credentials_inside_the_encrypted_file(db_session, artifact_storage, make_run):
    run, _ = make_run()
    art = _artifact(db_session, run, artifact_storage.save_bytes(run.id, "login.side", SIDE), "login.side", "side_file")
    assert ac.read_artifact_bytes(db_session, run, art, artifact_storage) == SIDE  # Tenable gets the creds


def test_har_is_masked_then_encrypted(db_session, artifact_storage, make_run):
    run, _ = make_run()
    with artifact_storage.redacting(run.id, [SECRET]):
        path = artifact_storage.save_bytes(run.id, "network.har", HAR)
    art = _artifact(db_session, run, path, "network.har", "har")
    plain = ac.read_artifact_bytes(db_session, run, art, artifact_storage)
    assert SECRET.encode() not in plain and b"[REDACTED]" in plain


def test_is_encrypted_flag_follows_the_file(db_session, artifact_storage, make_run):
    ac.register_model_hooks()
    run, _ = make_run()
    art = _artifact(db_session, run, artifact_storage.save_bytes(run.id, "shot.png", b"\x89PNG"), "shot.png", "screenshot",
                    is_encrypted=False)
    assert art.is_encrypted is True


def test_ownerless_run_uses_master_key(db_session, artifact_storage, make_run):
    run, _ = make_run(owned=False)
    path = artifact_storage.save_bytes(run.id, "page.html", b"<html>")
    assert artifact_storage.resolve(path).read_bytes().startswith(b"ARENC:m1:")
    art = _artifact(db_session, run, path, "page.html", "html")
    assert ac.read_artifact_bytes(db_session, run, art, artifact_storage) == b"<html>"


def test_fail_closed_when_no_key(tmp_path):
    from app.services.storage import ArtifactStorage

    def no_key(_run_id):
        raise ac.ArtifactDecryptError("no key")

    store = ArtifactStorage(tmp_path / "a", key_resolver=no_key)
    with pytest.raises(ac.ArtifactDecryptError):
        store.save_bytes("run-1", "x.txt", b"secret")
    assert not any((tmp_path / "a").rglob("x.txt"))


def test_refuses_double_encryption(artifact_storage, make_run):
    run, _ = make_run()
    blob = artifact_storage.prepare_bytes(run.id, "x.bin", b"data")
    with pytest.raises(ValueError):
        artifact_storage.prepare_bytes(run.id, "x.bin", blob)


def test_another_users_key_cannot_decrypt(db_session, artifact_storage, make_run):
    run, _ = make_run()
    other_run, other = make_run()
    blob = artifact_storage.prepare_bytes(run.id, "x.bin", b"data")
    _, token = ac.parse(blob)
    with pytest.raises(Exception):
        get_profile_artifact_cipher(db_session, other).decrypt(token)


def test_unknown_key_id_and_tampering_are_rejected(db_session, artifact_storage, make_run):
    run, _ = make_run()
    good = artifact_storage.prepare_bytes(run.id, "x.bin", b"data")
    resolve = ac.cipher_resolver_for_run(db_session, run)
    with pytest.raises(ac.ArtifactDecryptError):
        ac.unwrap(good.replace(b"ARENC:p1:", b"ARENC:p9:", 1), resolve)
    with pytest.raises(ac.ArtifactDecryptError):
        ac.unwrap(good[:-4] + b"AAAA", resolve)
    with pytest.raises(ac.ArtifactDecryptError):
        ac.parse(b"ARENC:no-colon-token")


def test_legacy_formats_still_readable(db_session, artifact_storage, make_run):
    run, profile = make_run()
    run_dir = artifact_storage.base_path / run.id
    run_dir.mkdir(parents=True)
    legacy_side = get_profile_artifact_cipher(db_session, profile).encrypt(SIDE)
    (run_dir / "old.side").write_bytes(legacy_side)
    (run_dir / "old.har").write_bytes(HAR)
    side = _artifact(db_session, run, f"{run.id}/old.side", "old.side", "side_file", is_encrypted=True)
    har = _artifact(db_session, run, f"{run.id}/old.har", "old.har", "har")
    assert ac.read_artifact_bytes(db_session, run, side, artifact_storage) == SIDE
    assert SECRET.encode() not in ac.read_artifact_bytes(db_session, run, har, artifact_storage)


def test_wrap_format_and_key_versions():
    key = ac.ArtifactKey("p1", Fernet(Fernet.generate_key()))
    blob = ac.wrap(b"hello", key)
    assert ac.parse(blob)[0] == "p1"
    assert ac.unwrap(blob, lambda kid: key.cipher) == b"hello"


def test_worker_removes_unmasked_temp_hars(tmp_path, monkeypatch):
    import tempfile

    from app import worker

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    run_id = str(uuid.uuid4())
    names = [f"{run_id}-playwright.har", f"{run_id}-okta-network.har", f"manual-{run_id}.har", "other-run.har"]
    for name in names:
        (tmp_path / name).write_text("{}")
    worker._remove_temp_hars(run_id)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["other-run.har"]
