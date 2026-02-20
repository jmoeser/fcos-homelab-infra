# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A GitOps reconciliation system for a Raspberry Pi running Raspberry Pi OS Lite (Debian Bookworm). The single source of truth is `desired-state.yaml` — a systemd timer runs `reconcile.sh` every 30 minutes, which pulls this repo and converges the system to match the declared state.

After initial bootstrap via `rpi-bootstrap/firstrun.sh`, all configuration is driven entirely through this repo.

## Key Commands

```bash
# Secret management (requires sops + age; installable via aqua or brew)
./scripts/init-secrets.sh                              # One-time: generate age keypair + configure .sops.yaml
./scripts/decrypt-secrets.sh <hostname>                # Decrypt all secrets for a host
./scripts/decrypt-secrets.sh <hostname> postgres.env   # Decrypt a single file
./scripts/encrypt-secrets.sh <hostname>                # Re-encrypt all secrets before committing
sops hosts/<hostname>/secrets/postgres.env             # Edit a secret in-place (decrypt → $EDITOR → re-encrypt)

# Database backup/restore
./scripts/pg-backup.sh
./scripts/pg-restore.sh
```

## Architecture

- **`reconcile.sh`** — Main bash script. Runs as root on the Pi. Reconciliation order: secrets → packages → quadlet → user quadlets → systemd → files → firewall → sysctl. All operations are idempotent (diff before copy, skip if unchanged).
- **`hosts/<hostname>/`** — Per-machine directory. Each machine has its own `desired-state.yaml` and subdirectories. The reconciler selects the correct directory using `$(hostname)` at runtime.
- **`hosts/<hostname>/desired-state.yaml`** — Declares everything for that machine: apt packages, SOPS-encrypted secrets, Podman Quadlet units (root and per-user), systemd units, config files, firewall rules, sysctl params, and reconciler settings.
- **`hosts/<hostname>/quadlet/`** — Root-level Podman Quadlet files (`.container`, `.network`, `.volume`) deployed to `/etc/containers/systemd/`.
- **`hosts/<hostname>/quadlet/<user>/`** — Per-user Quadlet files for rootless Podman, deployed to the user's `~/.config/containers/systemd/`. Configured via `user_quadlets` in `desired-state.yaml`. The reconciler ensures linger is enabled and manages services via `systemctl --user`.
- **`hosts/<hostname>/secrets/`** — SOPS-encrypted `.env` files (age encryption). Decrypted at reconciliation time using the age key at `/etc/homelab-gitops/age-key.txt`.
- **`hosts/<hostname>/files/`** — Plaintext config files. Directory structure mirrors the target path on the host (e.g., `files/etc/caddy/Caddyfile` → `/etc/caddy/Caddyfile`).
- **`hosts/<hostname>/systemd/`** — Custom systemd units deployed to `/etc/systemd/system/`.
- **`rpi-bootstrap/`** — First-boot setup script for a fresh Raspberry Pi OS Lite SD card.

## Container Networking Pattern

Apps use Tailscale sidecar containers that share a network namespace with their paired application container. Caddy acts as a LAN reverse proxy on ports 80/443. Two Podman networks: `app-network` (10.89.1.0/24) for general services + postgres, `openclaw-network` (10.89.2.0/24) for OpenClaw.

## Important Conventions

- Secrets are **never committed in plaintext** — always run `./scripts/encrypt-secrets.sh <hostname>` before committing. Files in `hosts/*/secrets/` should always contain SOPS-encrypted ciphertext.
- `yaml_get` and `yaml_get_raw` in `reconcile.sh` use inline Python to parse YAML — the host has no `yq` binary, only `python3` with PyYAML.
- Quadlet units listed in `desired-state.yaml` under `quadlet.units` (root) or `user_quadlets[].units` (per-user) are the only ones deployed. Commenting out a unit disables it without removing the file.
- The `aqua.yaml` pins local dev tool versions (age, sops) via [aqua](https://aquaproj.github.io/).
- Host paths use Debian conventions: user homes are at `/home/<user>`, not `/var/home/`.
- GitOps working directory on the host: `/var/lib/homelab-gitops/`. Age key and decrypted secrets land under `/etc/homelab-gitops/`.
