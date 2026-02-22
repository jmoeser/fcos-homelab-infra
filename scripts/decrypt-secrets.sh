#!/usr/bin/env bash
# scripts/decrypt-secrets.sh
# Decrypt secret files in hosts/<hostname>/secrets/ for local editing.
# Supports .env (dotenv) and .conf (ini) formats.
#
# Usage:
#   ./scripts/decrypt-secrets.sh <hostname>              # Decrypt all secrets for a host
#   ./scripts/decrypt-secrets.sh <hostname> postgres.env  # Decrypt a single file
#
# After editing, re-encrypt with: ./scripts/encrypt-secrets.sh <hostname>
#
# Or use sops directly to edit in-place:
#   sops hosts/<hostname>/secrets/postgres.env

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${REPO_ROOT}"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <hostname> [file]"
    echo "Available hosts:"
    for d in hosts/*/; do
        echo "  ${d#hosts/}"
    done
    exit 1
fi

HOSTNAME="$1"
SECRETS_DIR="${REPO_ROOT}/hosts/${HOSTNAME}/secrets"

if [[ ! -d "${SECRETS_DIR}" ]]; then
    echo "Error: ${SECRETS_DIR} not found."
    exit 1
fi

if ! command -v sops &>/dev/null; then
    echo "Error: sops is not installed."
    exit 1
fi

sops_type_for_file() {
    case "$1" in
        *.env) echo "dotenv" ;;
        *.conf) echo "ini" ;;
        *.json) echo "json" ;;
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

if [[ $# -gt 1 ]]; then
    target="${SECRETS_DIR}/${2}"
    if [[ ! -f "${target}" ]]; then
        echo "Error: ${target} not found."
        exit 1
    fi
    decrypt_file "${target}"
else
    echo "Decrypting all secrets in ${SECRETS_DIR}..."
    for f in "${SECRETS_DIR}"/*.env "${SECRETS_DIR}"/*.conf "${SECRETS_DIR}"/*.json; do
        [[ -f "${f}" ]] || continue
        decrypt_file "${f}"
    done
fi

echo "Done. Remember to re-encrypt before committing!"
