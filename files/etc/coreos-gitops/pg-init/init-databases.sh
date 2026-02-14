#!/bin/bash
# init-databases.sh — Create per-app databases and users
# Runs automatically on first PostgreSQL start (empty data directory).
# Environment variables are passed from postgres.env via the container.

set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname postgres <<-EOSQL
    -- Firefly database and user
    CREATE USER ${FIREFLY_DB_USER} WITH PASSWORD '${FIREFLY_DB_PASSWORD}';
    CREATE DATABASE ${FIREFLY_DB_NAME} OWNER ${FIREFLY_DB_USER};
    GRANT ALL PRIVILEGES ON DATABASE ${FIREFLY_DB_NAME} TO ${FIREFLY_DB_USER};

    -- Glow Worm database and user
    CREATE USER ${GLOW_WORM_DB_USER} WITH PASSWORD '${GLOW_WORM_DB_PASSWORD}';
    CREATE DATABASE ${GLOW_WORM_DB_NAME} OWNER ${GLOW_WORM_DB_USER};
    GRANT ALL PRIVILEGES ON DATABASE ${GLOW_WORM_DB_NAME} TO ${GLOW_WORM_DB_USER};
EOSQL

echo "Init complete: created databases '${FIREFLY_DB_NAME}' and '${GLOW_WORM_DB_NAME}'"
