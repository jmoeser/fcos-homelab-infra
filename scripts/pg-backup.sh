#!/usr/bin/env bash
# scripts/pg-backup.sh — Automated PostgreSQL backup to Backblaze B2
#
# Workflow:
#   1. pg_dump from the Postgres container
#   2. Compress with gzip
#   3. Encrypt with age (same key used for SOPS secrets)
#   4. Upload to Backblaze B2 via rclone
#   5. Prune backups older than retention period
#
# Deployed to: /var/lib/homelab-gitops/scripts/pg-backup.sh
# Triggered by: pg-backup.timer (systemd)

set -euo pipefail

# ---------------------------------------------------------------------------
# Config — overridable via environment
# ---------------------------------------------------------------------------
BACKUP_DIR="${PG_BACKUP_DIR:-/var/lib/homelab-gitops/backups}"
RCLONE_REMOTE="${PG_BACKUP_RCLONE_REMOTE:-b2}"
RCLONE_BUCKET="${PG_BACKUP_RCLONE_BUCKET:-homelab-pg-backups}"
RCLONE_CONFIG="${RCLONE_CONFIG:-/etc/homelab-gitops/rclone.conf}"
AGE_RECIPIENT_FILE="${PG_BACKUP_AGE_RECIPIENTS:-/etc/homelab-gitops/age-recipients.txt}"
AGE_KEY_FILE="${PG_BACKUP_AGE_KEY:-/etc/homelab-gitops/age-key.txt}"
RETENTION_DAYS="${PG_BACKUP_RETENTION_DAYS:-30}"
PG_CONTAINER="${PG_BACKUP_CONTAINER:-postgres}"
LOG_ID="pg-backup"

# Read Postgres credentials from the deployed env file
PG_ENV_FILE="/etc/homelab-gitops/postgres.env"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "$*" | systemd-cat -t "${LOG_ID}" -p info;  echo "[INFO]  $*"; }
warn() { echo "$*" | systemd-cat -t "${LOG_ID}" -p warning; echo "[WARN]  $*"; }
err()  { echo "$*" | systemd-cat -t "${LOG_ID}" -p err;   echo "[ERROR] $*"; }
die()  { err "$*"; exit 1; }

cleanup() {
    rm -f "${BACKUP_DIR}/.tmp_"* 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
preflight() {
    for cmd in podman rclone age gzip; do
        if ! command -v "${cmd}" &>/dev/null; then
            die "Required command not found: ${cmd}"
        fi
    done

    if [[ ! -f "${PG_ENV_FILE}" ]]; then
        die "Postgres env file not found: ${PG_ENV_FILE}"
    fi

    if [[ ! -f "${AGE_RECIPIENT_FILE}" ]]; then
        die "Age recipients file not found: ${AGE_RECIPIENT_FILE}"
    fi

    if [[ ! -f "${RCLONE_CONFIG}" ]]; then
        die "Rclone config not found: ${RCLONE_CONFIG}"
    fi

    # Ensure Postgres is running
    if ! podman exec "${PG_CONTAINER}" pg_isready -q 2>/dev/null; then
        die "PostgreSQL container '${PG_CONTAINER}' is not ready."
    fi

    mkdir -p "${BACKUP_DIR}"
}

# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------
do_backup() {
    local timestamp
    timestamp=$(date -u +"%Y%m%d-%H%M%S")

    # Read Postgres credentials
    # shellcheck source=/dev/null
    source "${PG_ENV_FILE}"
    local pg_user="${POSTGRES_USER:-postgres}"

    # Databases to back up
    local databases=("${FIREFLY_DB_NAME:-firefly}" "${GLOW_WORM_DB_NAME:-glow_worm}")

    for pg_db in "${databases[@]}"; do
        local basename="pg-backup-${pg_db}-${timestamp}"

        log "Starting backup: ${basename}"

        # Step 1: pg_dump from container → compressed SQL
        local dump_file="${BACKUP_DIR}/.tmp_${basename}.sql.gz"
        log "  Dumping database '${pg_db}' as user '${pg_user}'..."

        if ! podman exec "${PG_CONTAINER}" \
            pg_dump -U "${pg_user}" -d "${pg_db}" --format=plain --no-owner --no-acl \
            | gzip -9 > "${dump_file}"; then
            err "pg_dump failed for '${pg_db}'"
            continue
        fi

        local dump_size
        dump_size=$(du -h "${dump_file}" | cut -f1)
        log "  Dump complete: ${dump_size} compressed"

        # Step 2: Encrypt with age
        local encrypted_file="${BACKUP_DIR}/${basename}.sql.gz.age"
        log "  Encrypting with age..."

        if ! age --encrypt --recipients-file "${AGE_RECIPIENT_FILE}" \
            --output "${encrypted_file}" "${dump_file}"; then
            err "age encryption failed for '${pg_db}'"
            continue
        fi

        rm -f "${dump_file}"

        local enc_size
        enc_size=$(du -h "${encrypted_file}" | cut -f1)
        log "  Encrypted: ${enc_size}"

        # Step 3: Upload to B2
        log "  Uploading to ${RCLONE_REMOTE}:${RCLONE_BUCKET}..."

        if ! rclone --config "${RCLONE_CONFIG}" \
            copy "${encrypted_file}" "${RCLONE_REMOTE}:${RCLONE_BUCKET}/" \
            --progress --transfers 1; then
            warn "Upload failed for '${pg_db}'. Local backup retained at: ${encrypted_file}"
            continue
        fi

        log "  Upload complete."

        # Step 4: Remove local file (it's in B2 now)
        rm -f "${encrypted_file}"

        log "Backup '${basename}' completed successfully."
    done
}

# ---------------------------------------------------------------------------
# Prune old backups
# ---------------------------------------------------------------------------
prune_remote() {
    log "Pruning backups older than ${RETENTION_DAYS} days..."

    # Calculate cutoff date
    local cutoff
    cutoff=$(date -u -d "${RETENTION_DAYS} days ago" +"%Y%m%d")

    # List remote files and delete old ones
    rclone --config "${RCLONE_CONFIG}" \
        lsf "${RCLONE_REMOTE}:${RCLONE_BUCKET}/" \
        --files-only 2>/dev/null | while IFS= read -r file; do

        # Extract date from filename: pg-backup-<dbname>-YYYYMMDD-HHMMSS.sql.gz.age
        local file_date
        file_date=$(echo "${file}" | grep -oP 'pg-backup-\w+-\K\d{8}' || echo "")

        if [[ -z "${file_date}" ]]; then
            continue
        fi

        if [[ "${file_date}" < "${cutoff}" ]]; then
            log "  Deleting old backup: ${file}"
            rclone --config "${RCLONE_CONFIG}" \
                deletefile "${RCLONE_REMOTE}:${RCLONE_BUCKET}/${file}" 2>/dev/null || \
                warn "  Failed to delete: ${file}"
        fi
    done

    # Also clean up any leftover local backups
    find "${BACKUP_DIR}" -name "pg-backup-*.sql.gz.age" -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true

    log "Pruning complete."
}

# ---------------------------------------------------------------------------
# Verify (optional — run manually to test a restore)
# ---------------------------------------------------------------------------
verify_latest() {
    log "Verifying latest backup..."

    local latest
    latest=$(rclone --config "${RCLONE_CONFIG}" \
        lsf "${RCLONE_REMOTE}:${RCLONE_BUCKET}/" \
        --files-only 2>/dev/null | sort | tail -1)

    if [[ -z "${latest}" ]]; then
        warn "No backups found in remote."
        return 1
    fi

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf '${tmp_dir}'" RETURN

    log "  Downloading: ${latest}"
    rclone --config "${RCLONE_CONFIG}" \
        copy "${RCLONE_REMOTE}:${RCLONE_BUCKET}/${latest}" "${tmp_dir}/"

    log "  Decrypting..."
    if age --decrypt --identity "${AGE_KEY_FILE}" \
        "${tmp_dir}/${latest}" | gzip -d | head -5 > /dev/null 2>&1; then
        log "  Verification passed — backup is valid."
    else
        err "  Verification FAILED — backup may be corrupted."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    case "${1:-backup}" in
        backup)
            preflight
            do_backup
            prune_remote
            ;;
        prune)
            prune_remote
            ;;
        verify)
            verify_latest
            ;;
        *)
            echo "Usage: $0 {backup|prune|verify}"
            exit 1
            ;;
    esac
}

main "$@"
