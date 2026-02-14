# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A GitOps reconciliation system for a Fedora CoreOS homelab server. The single source of truth is `desired-state.yaml` — a systemd timer runs `reconcile.sh` every 30 minutes, which pulls this repo and converges the system to match the declared state.

After initial bootstrap via Ignition (`butane-bootstrap.yaml`), all configuration is driven entirely through this repo.

## Key Commands

```bash
# Compile Butane to Ignition JSON (for bootstrap)
butane --pretty --strict butane-bootstrap.yaml > ignition.json

# Secret management (requires sops + age; installable via aqua or brew)
./scripts/init-secrets.sh              # One-time: generate age keypair + configure .sops.yaml
./scripts/decrypt-secrets.sh           # Decrypt all secrets for local editing
./scripts/decrypt-secrets.sh postgres.env  # Decrypt a single file
./scripts/encrypt-secrets.sh           # Re-encrypt all secrets before committing
sops secrets/postgres.env              # Edit a secret in-place (decrypt → $EDITOR → re-encrypt)

# Database backup/restore
./scripts/pg-backup.sh
./scripts/pg-restore.sh
```

## Architecture

- **`reconcile.sh`** — Main bash script. Runs as root on the CoreOS host. Reconciliation order: secrets → packages → quadlet → user quadlets → systemd → files → firewall → sysctl. All operations are idempotent (diff before copy, skip if unchanged).
- **`desired-state.yaml`** — Declares everything: rpm-ostree packages, SOPS-encrypted secrets, Podman Quadlet units (root and per-user), systemd units, config files, firewall rules, sysctl params, and reconciler settings.
- **`quadlet/`** — Root-level Podman Quadlet files (`.container`, `.network`, `.volume`) deployed to `/etc/containers/systemd/`.
- **`quadlet/<user>/`** — Per-user Quadlet files for rootless Podman, deployed to the user's `~/.config/containers/systemd/`. Configured via `user_quadlets` in `desired-state.yaml`. The reconciler ensures linger is enabled and manages services via `systemctl --user`.
- **`secrets/`** — SOPS-encrypted `.env` files (age encryption). Decrypted at reconciliation time using the age key at `/etc/coreos-gitops/age-key.txt`.
- **`files/`** — Plaintext config files. Directory structure mirrors the target path on the host (e.g., `files/etc/caddy/Caddyfile` → `/etc/caddy/Caddyfile`).
- **`systemd/`** — Custom systemd units deployed to `/etc/systemd/system/`.

## Container Networking Pattern

Apps use Tailscale sidecar containers that share a network namespace with their paired application container. Caddy acts as a LAN reverse proxy on ports 80/443. Two Podman networks: `app-network` (10.89.1.0/24) for general services + postgres, `openclaw-network` (10.89.2.0/24) for OpenClaw.

## Important Conventions

- Secrets are **never committed in plaintext** — always run `./scripts/encrypt-secrets.sh` before committing. Files in `secrets/` should always contain SOPS-encrypted ciphertext.
- `yaml_get` and `yaml_get_raw` in `reconcile.sh` use inline Python to parse YAML — the host has no `yq` binary, only `python3` with PyYAML.
- Quadlet units listed in `desired-state.yaml` under `quadlet.units` (root) or `user_quadlets[].units` (per-user) are the only ones deployed. Commenting out a unit disables it without removing the file.
- The `aqua.yaml` pins local dev tool versions (age, sops) via [aqua](https://aquaproj.github.io/).
