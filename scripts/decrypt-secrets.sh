#!/usr/bin/env bash
# scripts/decrypt-secrets.sh
# Decrypt all secret files in secrets/ for local editing.
# Supports .env (dotenv) and .conf (ini) formats.
#
# Usage:
#   ./scripts/decrypt-secrets.sh              # Decrypt all secrets
#   ./scripts/decrypt-secrets.sh postgres.env  # Decrypt a single file
#   ./scripts/decrypt-secrets.sh rclone.conf   # Decrypt a single .conf file
#
# After editing, re-encrypt with: ./scripts/encrypt-secrets.sh
#
# Or use sops directly to edit in-place:
#   sops secrets/postgres.env

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="${REPO_ROOT}/secrets"

cd "${REPO_ROOT}"

if ! command -v sops &>/dev/null; then
    echo "Error: sops is not installed."
    exit 1
fi

sops_type_for_file() {
    case "$1" in
        *.env) echo "dotenv" ;;
        *.conf) echo "ini" ;;
        *) echo "unknown" ;;
    esac
}

decrypt_file() {
    local file="$1"
    local basename
    basename=$(basename "${file}")
    local sops_type
    sops_type=$(sops_type_for_file "${basename}")

    if [[ "${sops_type}" == "unknown" ]]; then
        echo "  [skip] ${basename} — unsupported file type"
        return 0
    fi

    # Check if actually encrypted
    if ! grep -q "ENC\[AES256_GCM" "${file}" 2>/dev/null; then
        echo "  [skip] ${basename} — not encrypted"
        return 0
    fi

    echo "  [decrypt] ${basename}"
    sops decrypt --input-type "${sops_type}" --output-type "${sops_type}" --in-place "${file}"
}

if [[ $# -gt 0 ]]; then
    target="${SECRETS_DIR}/${1}"
    if [[ ! -f "${target}" ]]; then
        echo "Error: ${target} not found."
        exit 1
    fi
    decrypt_file "${target}"
else
    echo "Decrypting all secrets in ${SECRETS_DIR}..."
    for f in "${SECRETS_DIR}"/*.env "${SECRETS_DIR}"/*.conf; do
        [[ -f "${f}" ]] || continue
        decrypt_file "${f}"
    done
fi

echo "Done. Remember to re-encrypt before committing!"
