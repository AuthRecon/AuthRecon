#!/usr/bin/env bash
set -euo pipefail

PORTAL_DB_USER=${PORTAL_DB_USER:-portal}
PORTAL_DB_PASSWORD=${PORTAL_DB_PASSWORD:-portal}
AUTHRECON_DB_USER=${AUTHRECON_DB_USER:-authrecon}
AUTHRECON_DB_PASSWORD=${AUTHRECON_DB_PASSWORD:-authrecon}

function create_role_and_db() {
  local db="$1"
  local user="$2"
  local pass="$3"

  # Create role if it doesn't exist
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    DO
    \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${user}') THEN
        CREATE ROLE ${user} LOGIN PASSWORD '${pass}';
      END IF;
    END
    \$\$;
EOSQL

  # Create database if it doesn't exist (cannot be done in DO block)
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    SELECT 'CREATE DATABASE ${db} OWNER ${user}'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${db}')\gexec

    GRANT ALL PRIVILEGES ON DATABASE ${db} TO ${user};
EOSQL
}

create_role_and_db "portal" "$PORTAL_DB_USER" "$PORTAL_DB_PASSWORD"
create_role_and_db "authrecon" "$AUTHRECON_DB_USER" "$AUTHRECON_DB_PASSWORD"
