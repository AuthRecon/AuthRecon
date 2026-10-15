#!/bin/sh
# Start the portal as the unprivileged "portal" user. The one root step is
# taking ownership of the data volume, which older installs created as root
# (it holds portal.key, so it must stay readable across upgrades).
set -e
if [ "$(id -u)" = "0" ]; then
    mkdir -p /app/data /app/logs
    chown -R portal:portal /app/data /app/logs
    exec setpriv --reuid=portal --regid=portal --init-groups "$@"
fi
exec "$@"
