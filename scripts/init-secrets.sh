#!/usr/bin/env bash
# scripts/init-secrets.sh
# One-time setup: generates an age keypair and configures .sops.yaml.
#
# Run this once when setting up the repo for the first time.
# The public key goes into .sops.yaml (committed to git).
# The private key must be:
#   1. Saved in your password manager
#   2. Deployed to the CoreOS host at /etc/coreos-gitops/age-key.txt via Ignition
#
# Usage: ./scripts/init-secrets.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v age-keygen &>/dev/null; then
    echo "Error: age is not installed. Install with: brew install age (macOS) or your package manager."
    exit 1
fi

if ! command -v sops &>/dev/null; then
    echo "Error: sops is not installed. Install with: brew install sops"
    exit 1
fi

echo "=== CoreOS GitOps Secret Setup ==="
echo ""

# Generate age keypair
KEY_FILE=$(mktemp)
age-keygen -o "${KEY_FILE}" 2>&1

PUBLIC_KEY=$(grep "public key:" "${KEY_FILE}" | awk '{print $NF}')
echo ""
echo "Generated age keypair."
echo ""
echo "  Public key:  ${PUBLIC_KEY}"
echo "  Private key file: ${KEY_FILE}"
echo ""

# Update .sops.yaml with the real public key
if [[ -f "${REPO_ROOT}/.sops.yaml" ]]; then
    sed -i.bak "s/age1REPLACE_WITH_YOUR_AGE_PUBLIC_KEY/${PUBLIC_KEY}/g" "${REPO_ROOT}/.sops.yaml"
    rm -f "${REPO_ROOT}/.sops.yaml.bak"
    echo "Updated .sops.yaml with your public key."
else
    echo "Warning: .sops.yaml not found. Create it manually."
fi

echo ""
echo "=== IMPORTANT: Save your private key ==="
echo ""
echo "1. Copy the private key to your password manager:"
echo ""
cat "${KEY_FILE}"
echo ""
echo "2. Add the private key to your Butane/Ignition config:"
echo ""
echo "   storage:"
echo "     files:"
echo "       - path: /etc/coreos-gitops/age-key.txt"
echo "         mode: 0600"
echo "         contents:"
echo "           inline: |"
sed 's/^/             /' "${KEY_FILE}"
echo ""
echo "3. For local SOPS usage, copy the key to the default location:"
echo ""
echo "   mkdir -p ~/.config/sops/age/"
echo "   cp ${KEY_FILE} ~/.config/sops/age/keys.txt"
echo ""
echo "4. Now encrypt your secrets:"
echo "   ./scripts/encrypt-secrets.sh"
echo ""

# Clean up temp file reminder
echo "The private key is at: ${KEY_FILE}"
echo "Delete it after saving to your password manager and Ignition config."
