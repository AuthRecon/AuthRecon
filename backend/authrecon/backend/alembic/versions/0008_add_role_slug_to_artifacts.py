"""Track artifact ownership per role for multi-role runs."""
from __future__ import annotations

import re

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "0008_add_role_slug_to_artifacts"
down_revision = "0007_add_llm_enabled_to_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("artifacts", sa.Column("role_slug", sa.String(length=64), nullable=True))
    op.create_index("ix_artifacts_role_slug", "artifacts", ["role_slug"])
    _backfill_role_slugs()


def downgrade() -> None:
    op.drop_index("ix_artifacts_role_slug", table_name="artifacts")
    op.drop_column("artifacts", "role_slug")


def _backfill_role_slugs() -> None:
    conn = op.get_bind()
    artifacts = sa.table(
        "artifacts",
        sa.column("id", sa.String(40)),
        sa.column("run_id", sa.String(36)),
        sa.column("name", sa.String(255)),
        sa.column("role_slug", sa.String(64)),
    )
    runs = sa.table(
        "runs",
        sa.column("id", sa.String(36)),
        sa.column("options", postgresql.JSONB),
    )
    run_rows = conn.execute(sa.select(runs.c.id, runs.c.options)).fetchall()
    for run_id, options in run_rows:
        role_slugs = _extract_role_slugs(options)
        if not role_slugs:
            continue
        artifact_rows = conn.execute(
            sa.select(artifacts.c.id, artifacts.c.name).where(artifacts.c.run_id == run_id)
        ).fetchall()
        for artifact_id, name in artifact_rows:
            slug = _infer_role_slug(artifact_id, name, run_id, role_slugs)
            if slug:
                conn.execute(
                    artifacts.update().where(artifacts.c.id == artifact_id).values(role_slug=slug)
                )


def _extract_role_slugs(payload: dict | None) -> list[str]:
    if not isinstance(payload, dict):
        return []
    scope = payload.get("scope")
    if not isinstance(scope, dict):
        return []
    roles = scope.get("roles")
    if not isinstance(roles, list):
        return []
    slugs: list[str] = []
    for index, entry in enumerate(roles, start=1):
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug")
        if isinstance(slug, str) and slug.strip():
            slugs.append(slug.strip())
            continue
        label = entry.get("label") or entry.get("username") or f"role-{index}"
        slugs.append(_slugify(label, index))
    return slugs


def _slugify(value: str, index: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", (value or "").strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or f"role-{index:02d}"


def _infer_role_slug(artifact_id: str, name: str | None, run_id: str, slugs: list[str]) -> str | None:
    prefix = f"{run_id}-"
    if artifact_id and artifact_id.startswith(prefix):
        remainder = artifact_id[len(prefix):]
        candidate = remainder.split("-", 1)[0]
        if candidate in slugs:
            return candidate
    if name:
        for slug in slugs:
            if name.startswith(f"{slug}-"):
                return slug
    return None
