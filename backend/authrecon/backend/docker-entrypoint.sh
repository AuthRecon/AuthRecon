#!/bin/bash
set -e

echo "🚀 AuthRecon - Starting up..."

# Wait for PostgreSQL to be ready (health check should handle this, but double-check)
echo "⏳ Waiting for PostgreSQL..."
# Convert SQLAlchemy URL to psycopg2 format (strip +psycopg2 part)
PSYCOPG2_URL="${DATABASE_URL/+psycopg2/}"
until python -c "import psycopg2; psycopg2.connect('$PSYCOPG2_URL')" 2>/dev/null; do
    sleep 1
done
echo "✅ PostgreSQL is ready"

# Run database migrations. authrecon-api and authrecon-worker both start here,
# so the upgrade runs under a Postgres advisory lock (app/db/migrate.py): one
# container migrates, the other waits and then finds the DB already at head.
echo "📊 Running database migrations..."
python -m app.db.migrate
echo "✅ Migrations complete"

# Live browser views are started per run by the worker (app/services/vnc_session.py);
# there is no shared display at boot.

# Start the application
echo "🎯 Starting application..."
exec "$@"
