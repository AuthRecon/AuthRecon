"""Migrate users table to authrecon_profiles table.

This migration transforms the shadow user identity table into a lightweight
profile table that only stores AuthRecon-specific data. User identity moves
to Portal database as the single source of truth.

Revision ID: 0010
Revises: 0009
Create Date: 2025-11-27

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0010_migrate_users_to_profiles'
down_revision = '0009_add_error_message_to_runs'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Transform users table into authrecon_profiles table.

    Strategy:
    1. Create new authrecon_profiles table
    2. Migrate data: users.id → profiles.portal_user_id
    3. Update foreign key columns in related tables
    4. Drop old users table
    """

    # Step 1: Create authrecon_profiles table
    op.create_table(
        'authrecon_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('portal_user_id', sa.String(length=36), nullable=False, comment='Foreign key to Portal database PortalUser.id'),
        sa.Column('artifact_key_encrypted', sa.Text(), nullable=True, comment='Encrypted per-user key for credential artifacts'),
        sa.Column('llm_enabled', sa.Boolean(), server_default='false', nullable=False, comment='Enable LLM features for this user'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True, comment='Last login timestamp for this profile'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('portal_user_id')
    )
    op.create_index(op.f('ix_authrecon_profiles_portal_user_id'), 'authrecon_profiles', ['portal_user_id'], unique=True)

    # Step 2: Migrate existing user data to profiles
    # Use users.id as portal_user_id (assuming they match Portal user IDs)
    op.execute("""
        INSERT INTO authrecon_profiles (id, portal_user_id, artifact_key_encrypted, llm_enabled, created_at, updated_at, last_login_at)
        SELECT
            gen_random_uuid()::text AS id,
            id AS portal_user_id,
            artifact_key_encrypted,
            COALESCE(llm_enabled, false) AS llm_enabled,
            created_at,
            updated_at,
            last_login_at
        FROM users
    """)

    # Step 3: Add new foreign key columns to related tables (nullable initially)
    op.add_column('stored_credentials', sa.Column('owner_profile_id', sa.String(length=36), nullable=True))
    op.add_column('runs', sa.Column('submitted_by_profile_id', sa.String(length=36), nullable=True))
    op.add_column('audit_log', sa.Column('actor_profile_id', sa.String(length=36), nullable=True))

    # Step 4: Migrate foreign key references from user_id to profile_id
    op.execute("""
        UPDATE stored_credentials sc
        SET owner_profile_id = p.id
        FROM authrecon_profiles p
        WHERE sc.owner_user_id = p.portal_user_id
    """)

    op.execute("""
        UPDATE runs r
        SET submitted_by_profile_id = p.id
        FROM authrecon_profiles p
        WHERE r.submitted_by_user_id = p.portal_user_id
    """)

    op.execute("""
        UPDATE audit_log al
        SET actor_profile_id = p.id
        FROM authrecon_profiles p
        WHERE al.actor_user_id = p.portal_user_id
    """)

    # Step 5: Drop old foreign key constraints and columns
    op.drop_constraint('stored_credentials_owner_user_id_fkey', 'stored_credentials', type_='foreignkey')
    op.drop_constraint('runs_submitted_by_user_id_fkey', 'runs', type_='foreignkey')
    op.drop_constraint('audit_log_actor_user_id_fkey', 'audit_log', type_='foreignkey')

    op.drop_column('stored_credentials', 'owner_user_id')
    op.drop_column('runs', 'submitted_by_user_id')
    op.drop_column('audit_log', 'actor_user_id')

    # Step 6: Create new foreign key constraints
    op.create_foreign_key(
        'stored_credentials_owner_profile_id_fkey',
        'stored_credentials', 'authrecon_profiles',
        ['owner_profile_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index('ix_stored_credentials_owner_profile_id', 'stored_credentials', ['owner_profile_id'])

    op.create_foreign_key(
        'runs_submitted_by_profile_id_fkey',
        'runs', 'authrecon_profiles',
        ['submitted_by_profile_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index('ix_runs_submitted_by_profile_id', 'runs', ['submitted_by_profile_id'])

    op.create_foreign_key(
        'audit_log_actor_profile_id_fkey',
        'audit_log', 'authrecon_profiles',
        ['actor_profile_id'], ['id'],
        ondelete='SET NULL'
    )
    op.create_index('ix_audit_log_actor_profile_id', 'audit_log', ['actor_profile_id'])

    # Step 7: Drop additional foreign keys that reference users table
    op.drop_constraint('fk_artifacts_encryption_owner_user_id_users', 'artifacts', type_='foreignkey')
    op.drop_constraint('scanner_runs_triggered_by_user_id_fkey', 'scanner_runs', type_='foreignkey')

    # Step 8: Drop old users table
    op.drop_table('users')


def downgrade() -> None:
    """
    Revert authrecon_profiles back to users table.

    WARNING: This will lose Portal integration. Only use for rollback testing.
    """

    # Recreate users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('llm_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('auth_provider', sa.String(length=50), nullable=False, server_default='local'),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('artifact_key_encrypted', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # Migrate profiles back to users (portal_user_id → id)
    op.execute("""
        INSERT INTO users (id, email, full_name, hashed_password, is_active, is_admin, llm_enabled, auth_provider, artifact_key_encrypted, created_at, updated_at, last_login_at)
        SELECT
            portal_user_id AS id,
            portal_user_id AS email,
            NULL AS full_name,
            '' AS hashed_password,
            true AS is_active,
            false AS is_admin,
            llm_enabled,
            'portal' AS auth_provider,
            artifact_key_encrypted,
            created_at,
            updated_at,
            last_login_at
        FROM authrecon_profiles
    """)

    # Add old foreign key columns back
    op.add_column('stored_credentials', sa.Column('owner_user_id', sa.String(length=36), nullable=True))
    op.add_column('runs', sa.Column('submitted_by_user_id', sa.String(length=36), nullable=True))
    op.add_column('audit_log', sa.Column('actor_user_id', sa.String(length=36), nullable=True))

    # Migrate foreign keys back
    op.execute("""
        UPDATE stored_credentials sc
        SET owner_user_id = p.portal_user_id
        FROM authrecon_profiles p
        WHERE sc.owner_profile_id = p.id
    """)

    op.execute("""
        UPDATE runs r
        SET submitted_by_user_id = p.portal_user_id
        FROM authrecon_profiles p
        WHERE r.submitted_by_profile_id = p.id
    """)

    op.execute("""
        UPDATE audit_log al
        SET actor_user_id = p.portal_user_id
        FROM authrecon_profiles p
        WHERE al.actor_profile_id = p.id
    """)

    # Drop profile foreign keys
    op.drop_constraint('stored_credentials_owner_profile_id_fkey', 'stored_credentials', type_='foreignkey')
    op.drop_constraint('runs_submitted_by_profile_id_fkey', 'runs', type_='foreignkey')
    op.drop_constraint('audit_log_actor_profile_id_fkey', 'audit_log', type_='foreignkey')

    op.drop_index('ix_stored_credentials_owner_profile_id', 'stored_credentials')
    op.drop_index('ix_runs_submitted_by_profile_id', 'runs')
    op.drop_index('ix_audit_log_actor_profile_id', 'audit_log')

    op.drop_column('stored_credentials', 'owner_profile_id')
    op.drop_column('runs', 'submitted_by_profile_id')
    op.drop_column('audit_log', 'actor_profile_id')

    # Recreate old foreign keys
    op.create_foreign_key('stored_credentials_owner_user_id_fkey', 'stored_credentials', 'users', ['owner_user_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key('runs_submitted_by_user_id_fkey', 'runs', 'users', ['submitted_by_user_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key('audit_log_actor_user_id_fkey', 'audit_log', 'users', ['actor_user_id'], ['id'], ondelete='SET NULL')

    # Drop profiles table
    op.drop_index('ix_authrecon_profiles_portal_user_id', 'authrecon_profiles')
    op.drop_table('authrecon_profiles')
