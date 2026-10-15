"""One-time migration: encrypt existing artifacts and mask passwords in existing HARs."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from app.models import Artifact
from app.models.profile import AuthReconProfile
from app.services import artifact_crypto as ac
from app.services.artifact_migration import migrate_artifacts
from app.services.profiles import get_profile_artifact_cipher

SECRET = "Sup3r-Secret!pw"
HAR = json.dumps({"log": {"entries": [{"request": {"url": "https://t.invalid/login", "postData": {
    "params": [{"name": "password", "value": SECRET}]}}}]}}).encode()
SIDE = json.dumps({"value": SECRET}).encode()


def _legacy(db, storage, run, name, type_, data, is_encrypted=False):
    run_dir = storage.base_path / run.id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / name).write_bytes(data)
    art = Artifact(id=str(uuid.uuid4())[:40], run_id=run.id, name=name, type=type_, size_bytes=len(data),
                   storage_path=f"{run.id}/{name}", created_at=datetime.now(timezone.utc), is_encrypted=is_encrypted)
    db.add(art)
    db.commit()
    return art


def _setup(db, storage, make_run):
    run, profile = make_run()
    ownerless, _ = make_run(owned=False)
    arts = {
        "har": _legacy(db, storage, run, "manual-recording.har", "har", HAR),
        "side_enc": _legacy(db, storage, run, "login.side", "side_file",
                            get_profile_artifact_cipher(db, profile).encrypt(SIDE), is_encrypted=True),
        "side_plain": _legacy(db, storage, run, "manual.side", "side_file", SIDE),
        "png": _legacy(db, storage, ownerless, "shot.png", "screenshot", b"\x89PNG"),
    }
    missing = Artifact(id="missing-1", run_id=run.id, name="gone.txt", type="log", size_bytes=0,
                       storage_path=f"{run.id}/gone.txt", created_at=datetime.now(timezone.utc))
    db.add(missing)
    db.commit()
    return run, ownerless, arts


def test_migration_encrypts_everything_and_masks_hars(db_session, artifact_storage, make_run):
    run, ownerless, arts = _setup(db_session, artifact_storage, make_run)

    report = migrate_artifacts(db_session, artifact_storage)
    assert (report.encrypted, report.har_masked, report.missing_file, report.failed) == (4, 1, 1, 0)

    for art in arts.values():
        raw = artifact_storage.resolve(art.storage_path).read_bytes()
        assert ac.is_wrapped(raw) and SECRET.encode() not in raw
        db_session.refresh(art)
        assert art.is_encrypted is True
    assert artifact_storage.resolve(arts["png"].storage_path).read_bytes().startswith(b"ARENC:m1:")

    read = lambda art, r=run: ac.read_artifact_bytes(db_session, r, art, artifact_storage)  # noqa: E731
    assert SECRET.encode() not in read(arts["har"]) and b"[REDACTED]" in read(arts["har"])
    assert read(arts["side_enc"]) == SIDE and read(arts["side_plain"]) == SIDE  # creds kept inside .side
    assert read(arts["png"], ownerless) == b"\x89PNG"


def test_migration_is_idempotent(db_session, artifact_storage, make_run):
    _setup(db_session, artifact_storage, make_run)
    migrate_artifacts(db_session, artifact_storage)
    snapshot = {p: p.read_bytes() for p in artifact_storage.base_path.rglob("*") if p.is_file()}
    again = migrate_artifacts(db_session, artifact_storage)
    assert (again.encrypted, again.already_encrypted) == (0, 4)
    assert snapshot == {p: p.read_bytes() for p in artifact_storage.base_path.rglob("*") if p.is_file()}


def test_dry_run_writes_nothing(db_session, artifact_storage, make_run):
    _, _, arts = _setup(db_session, artifact_storage, make_run)
    before = artifact_storage.resolve(arts["har"].storage_path).read_bytes()
    report = migrate_artifacts(db_session, artifact_storage, dry_run=True)
    assert report.encrypted == 4
    assert artifact_storage.resolve(arts["har"].storage_path).read_bytes() == before


def test_profiles_without_a_key_are_provisioned_first(db_session, artifact_storage, make_run):
    run, profile = make_run()
    profile.artifact_key_encrypted = None
    db_session.commit()
    art = _legacy(db_session, artifact_storage, run, "notes.txt", "log", b"hello")
    migrate_artifacts(db_session, artifact_storage)
    db_session.refresh(profile)
    assert profile.artifact_key_encrypted
    assert ac.read_artifact_bytes(db_session, run, art, artifact_storage) == b"hello"


def test_a_bad_file_does_not_stop_the_migration(db_session, artifact_storage, make_run):
    run, profile = make_run()
    bad = _legacy(db_session, artifact_storage, run, "corrupt.side", "side_file", b"not-a-fernet-token", is_encrypted=True)
    good = _legacy(db_session, artifact_storage, run, "ok.txt", "log", b"fine")
    report = migrate_artifacts(db_session, artifact_storage)
    assert report.failed == 1 and report.failed_ids == [bad.id] and report.encrypted == 1
    assert ac.is_wrapped(artifact_storage.resolve(good.storage_path).read_bytes())


# --- second pass: response bodies of already-encrypted HARs (revision 0021) ---

import base64  # noqa: E402

from app.services.artifact_migration import run_migration, scrub_existing_hars  # noqa: E402

PAGE_SECRET = "SuperSecretPassword!"


def _wrapped_legacy(db, storage, run, name, type_, plaintext):
    """An artifact as the first 0020 left it: encrypted, but response bodies unscrubbed."""
    from app.services.artifact_crypto import wrap, write_key_for_run

    run_dir = storage.base_path / run.id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / name).write_bytes(wrap(plaintext, write_key_for_run(db, run)))
    art = Artifact(id=str(uuid.uuid4())[:40], run_id=run.id, name=name, type=type_, size_bytes=0,
                   storage_path=f"{run.id}/{name}", created_at=datetime.now(timezone.utc), is_encrypted=True)
    db.add(art)
    db.commit()
    return art


def _secret_run(db, make_run):
    from app.core.security import get_credential_cipher

    run, _ = make_run()
    run.options = {"one_time_secret": get_credential_cipher().encrypt(PAGE_SECRET.encode()).decode()}
    db.commit()
    return run


def _har_with_page(text, *, b64=False):
    content = {"mimeType": "text/html", "text": base64.b64encode(text.encode()).decode() if b64 else text}
    if b64:
        content["encoding"] = "base64"
    return json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "https://t.invalid/login"},
                                             "response": {"content": content}}]}}).encode()


def test_second_pass_scrubs_response_bodies_and_skips_side_and_html(db_session, artifact_storage, make_run):
    run = _secret_run(db_session, make_run)
    leaky = _wrapped_legacy(db_session, artifact_storage, run, "network.har", "har",
                            _har_with_page(f"<em>{PAGE_SECRET}</em> for the password"))
    leaky_b64 = _wrapped_legacy(db_session, artifact_storage, run, "playwright-network.har", "har",
                                _har_with_page(f"<em>{PAGE_SECRET}</em>", b64=True))
    clean = _wrapped_legacy(db_session, artifact_storage, run, "clean.har", "har", _har_with_page("<p>hi</p>"))
    side = _wrapped_legacy(db_session, artifact_storage, run, "login.side", "side_file",
                           json.dumps({"value": PAGE_SECRET}).encode())
    page = _wrapped_legacy(db_session, artifact_storage, run, "pre_auth.html", "html",
                           f"<em>{PAGE_SECRET}</em>".encode())
    untouched = {a.id: artifact_storage.resolve(a.storage_path).read_bytes() for a in (clean, side, page)}

    report = scrub_existing_hars(db_session, artifact_storage)
    assert (report.har_scrubbed, report.har_clean, report.failed) == (2, 1, 0)

    read = lambda a: ac.read_artifact_bytes(db_session, run, a, artifact_storage)  # noqa: E731
    assert PAGE_SECRET.encode() not in read(leaky) and b"[REDACTED]" in read(leaky)
    b64_text = json.loads(read(leaky_b64))["log"]["entries"][0]["response"]["content"]["text"]
    assert PAGE_SECRET.encode() not in base64.b64decode(b64_text)
    for art in (clean, side, page):  # clean HAR, .side and HTML snapshots: same bytes on disk
        assert artifact_storage.resolve(art.storage_path).read_bytes() == untouched[art.id]
    assert PAGE_SECRET.encode() in read(side) and PAGE_SECRET.encode() in read(page)

    again = scrub_existing_hars(db_session, artifact_storage)
    assert (again.har_scrubbed, again.har_clean) == (0, 3)


def test_second_pass_dry_run_writes_nothing(db_session, artifact_storage, make_run):
    run = _secret_run(db_session, make_run)
    art = _wrapped_legacy(db_session, artifact_storage, run, "network.har", "har", _har_with_page(PAGE_SECRET))
    before = artifact_storage.resolve(art.storage_path).read_bytes()
    assert scrub_existing_hars(db_session, artifact_storage, dry_run=True).har_scrubbed == 1
    assert artifact_storage.resolve(art.storage_path).read_bytes() == before


def test_first_pass_scrubs_response_bodies_of_plaintext_hars(db_session, artifact_storage, make_run):
    run = _secret_run(db_session, make_run)
    art = _legacy(db_session, artifact_storage, run, "manual-recording.har", "har", _har_with_page(f"<b>{PAGE_SECRET}</b>"))
    migrate_artifacts(db_session, artifact_storage)
    assert PAGE_SECRET.encode() not in ac.read_artifact_bytes(db_session, run, art, artifact_storage)


def test_run_migration_does_both_passes(db_session, artifact_storage, make_run):
    run = _secret_run(db_session, make_run)
    _legacy(db_session, artifact_storage, run, "plain.har", "har", _har_with_page(PAGE_SECRET))
    _wrapped_legacy(db_session, artifact_storage, run, "enc.har", "har", _har_with_page(PAGE_SECRET))
    report = run_migration(session_factory=db_session.factory, storage=artifact_storage)
    assert report.encrypted == 1 and report.har_scrubbed == 1 and report.failed == 0
