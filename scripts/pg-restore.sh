#!/usr/bin/env bash
# scripts/pg-restore.sh — Restore PostgreSQL from a Backblaze B2 backup
#
# Usage:
#   ./pg-restore.sh <database>                    # Restore latest backup for a database
#   ./pg-restore.sh <database> <backup-file>      # Restore a specific backup file
#
# Examples:
#   ./pg-restore.sh firefly
#   ./pg-restore.sh glow_worm pg-backup-glow_worm-20260213-030000.sql.gz.age
#
# This will:
#   1. Download the backup from B2
#   2. Decrypt with age
#   3. Decompress
#   4. Restore to the Postgres container
#
# WARNING: This will overwrite the current database contents!

set -euo pipefail

RCLONE_REMOTE="${PG_BACKUP_RCLONE_REMOTE:-b2}"
RCLONE_BUCKET="${PG_BACKUP_RCLONE_BUCKET:-homelab-pg-backups}"
RCLONE_CONFIG="${RCLONE_CONFIG:-/etc/homelab-gitops/rclone.conf}"
AGE_KEY_FILE="${PG_BACKUP_AGE_KEY:-/etc/homelab-gitops/age-key.txt}"
PG_CONTAINER="${PG_BACKUP_CONTAINER:-postgres}"
PG_ENV_FILE="/etc/homelab-gitops/postgres.env"

log() { echo "[INFO]  $*"; }
err() { echo "[ERROR] $*" >&2; }
die() { err "$*"; exit 1; }

# Database name is required
PG_DB="${1:-}"
if [[ -z "${PG_DB}" ]]; then
    echo "Usage: $0 <database> [backup-file]"
    echo ""
    echo "Available databases: firefly, glow_worm"
    exit 1
fi

# Load Postgres credentials
# shellcheck source=/dev/null
source "${PG_ENV_FILE}"
PG_USER="${POSTGRES_USER:-postgres}"

# Determine which backup to restore
BACKUP_FILE="${2:-}"

if [[ -z "${BACKUP_FILE}" ]]; then
    log "No file specified. Finding latest backup for '${PG_DB}'..."
    BACKUP_FILE=$(rclone --config "${RCLONE_CONFIG}" \
        lsf "${RCLONE_REMOTE}:${RCLONE_BUCKET}/" \
        --files-only 2>/dev/null | grep "pg-backup-${PG_DB}-" | sort | tail -1)

    if [[ -z "${BACKUP_FILE}" ]]; then
        die "No backups found for database '${PG_DB}' in ${RCLONE_REMOTE}:${RCLONE_BUCKET}/"
    fi
    log "Latest backup: ${BACKUP_FILE}"
fi

# Confirmation
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  WARNING: This will DROP and RECREATE the database!         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Database:  ${PG_DB}"
echo "  Backup:    ${BACKUP_FILE}"
echo "  Container: ${PG_CONTAINER}"
echo ""
read -rp "Type 'yes' to continue: " confirm
if [[ "${confirm}" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

# Download
TMP_DIR=$(mktemp -d)
trap "rm -rf '${TMP_DIR}'" EXIT

log "Downloading ${BACKUP_FILE}..."
rclone --config "${RCLONE_CONFIG}" \
    copy "${RCLONE_REMOTE}:${RCLONE_BUCKET}/${BACKUP_FILE}" "${TMP_DIR}/"

# Decrypt
log "Decrypting..."
age --decrypt --identity "${AGE_KEY_FILE}" \
    "${TMP_DIR}/${BACKUP_FILE}" > "${TMP_DIR}/backup.sql.gz"

# Decompress
log "Decompressing..."
gzip -d "${TMP_DIR}/backup.sql.gz"

# Determine the owner user for the database
case "${PG_DB}" in
    firefly)    DB_OWNER="${FIREFLY_DB_USER:-firefly}" ;;
    glow_worm)  DB_OWNER="${GLOW_WORM_DB_USER:-glow_worm}" ;;
    *)          DB_OWNER="${PG_USER}" ;;
esac

# Restore
log "Restoring to database '${PG_DB}'..."

# Drop and recreate the database
podman exec "${PG_CONTAINER}" psql -U "${PG_USER}" -d postgres -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${PG_DB}' AND pid <> pg_backend_pid();" 2>/dev/null || true

podman exec "${PG_CONTAINER}" dropdb -U "${PG_USER}" --if-exists "${PG_DB}"
podman exec "${PG_CONTAINER}" createdb -U "${PG_USER}" --owner="${DB_OWNER}" "${PG_DB}"

# Pipe the SQL into psql
cat "${TMP_DIR}/backup.sql" | podman exec -i "${PG_CONTAINER}" psql -U "${PG_USER}" -d "${PG_DB}" --quiet

log "Restore complete."
log ""
log "Verify with: podman exec ${PG_CONTAINER} psql -U ${PG_USER} -d ${PG_DB} -c '\\dt'"
