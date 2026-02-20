#!/usr/bin/env bash
# scripts/encrypt-secrets.sh
# Encrypt secret files in hosts/<hostname>/secrets/ using SOPS + age.
# Supports .env (dotenv) and .conf (ini) formats.
#
# Usage:
#   ./scripts/encrypt-secrets.sh <hostname>              # Encrypt all secrets for a host
#   ./scripts/encrypt-secrets.sh <hostname> postgres.env  # Encrypt a single file
#
# Prerequisites:
#   - sops and age installed locally
#   - .sops.yaml configured with the host's age public key
#   - Run from the repo root

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
    echo "Error: sops is not installed. Install with: brew install sops (macOS) or your package manager."
    exit 1
fi

if [[ ! -f ".sops.yaml" ]]; then
    echo "Error: .sops.yaml not found in repo root."
    exit 1
fi

sops_type_for_file() {
    case "$1" in
        *.env) echo "dotenv" ;;
        *.conf) echo "ini" ;;
        *) echo "unknown" ;;
    esac
}

encrypt_file() {
    local file="$1"
    local basename
    basename=$(basename "${file}")
    local sops_type
    sops_type=$(sops_type_for_file "${basename}")

    if [[ "${sops_type}" == "unknown" ]]; then
        echo "  [skip] ${basename} — unsupported file type"
        return 0
    fi

    # Check if already encrypted (SOPS adds metadata)
    if head -1 "${file}" | grep -q "sops_" 2>/dev/null || grep -q "ENC\[AES256_GCM" "${file}" 2>/dev/null; then
        echo "  [skip] ${basename} — already encrypted"
        return 0
    fi

    echo "  [encrypt] ${basename}"
    sops encrypt --input-type "${sops_type}" --output-type "${sops_type}" --in-place "${file}"
}

if [[ $# -gt 1 ]]; then
    # Encrypt specific file
    target="${SECRETS_DIR}/${2}"
    if [[ ! -f "${target}" ]]; then
        echo "Error: ${target} not found."
        exit 1
    fi
    encrypt_file "${target}"
else
    # Encrypt all secret files
    echo "Encrypting all secrets in ${SECRETS_DIR}..."
    for f in "${SECRETS_DIR}"/*.env "${SECRETS_DIR}"/*.conf; do
        [[ -f "${f}" ]] || continue
        encrypt_file "${f}"
    done
fi

echo "Done."
