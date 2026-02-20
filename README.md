# Homelab GitOps Reconciler

A lightweight GitOps reconciliation loop for a Raspberry Pi running Raspberry Pi OS Lite (Debian Bookworm). Define your desired machine state in this repo — the reconciler pulls changes and converges the system on a timer.

## Repo Structure

```
.
├── reconcile.sh              # Main reconciliation script
├── desired-state.yaml        # Single source of truth for machine config
├── quadlet/                  # Podman Quadlet unit files (.container, .network, .volume)
│   ├── caddy.container
│   └── ...
├── systemd/                  # Custom systemd units
│   └── pg-backup.timer
├── files/                    # Config files to sync (path mirrors target)
│   └── etc/
│       ├── caddy/Caddyfile
│       └── sysctl.d/99-custom.conf
├── secrets/                  # SOPS-encrypted .env files
├── scripts/                  # Helper scripts (secret management, db backup)
└── rpi-bootstrap/            # First-boot setup for a fresh SD card
    └── firstrun.sh
```

## How It Works

1. A systemd timer runs `reconcile.sh` every 30 minutes.
2. The script pulls this repo and reads `desired-state.yaml`.
3. It converges the system:
   - Installs/removes apt packages.
   - Decrypts SOPS-encrypted secrets and deploys them to target paths.
   - Syncs Quadlet files → reloads systemd → restarts changed containers.
   - Syncs systemd units → reloads and enables/starts them.
   - Syncs arbitrary config files to their target paths.
   - Applies firewall rules and sysctl parameters.
4. All actions are idempotent — no changes means no restarts.
5. Logs go to the journal under `homelab-reconciler`.

## Bootstrap

Copy `rpi-bootstrap/firstrun.sh` to the boot partition of a freshly flashed Raspberry Pi OS Lite SD card and follow the instructions at the top of that file. On first boot it:

- Sets hostname, configures SSH and WiFi
- Installs Podman (from Kubic repo), sops, and age
- Writes the age private key for SOPS decryption
- Downloads `reconcile.sh` and installs the reconciler systemd timer

After the first boot completes and the Pi reboots, the reconciler takes over.

## Secret Management

Secrets are SOPS-encrypted with age. The age private key lives at `/etc/homelab-gitops/age-key.txt` on the host (written by `firstrun.sh`).

```bash
sops secrets/postgres.env              # Edit in-place
./scripts/encrypt-secrets.sh           # Re-encrypt all before committing
./scripts/decrypt-secrets.sh           # Decrypt all for local inspection
```

## Useful Commands

```bash
# Check reconciler status
journalctl -t homelab-reconciler -f

# OpenClaw user service debugging (rootless Podman)
machinectl shell openclaw@ /bin/bash -c 'systemctl --user status openclaw.service ts-openclaw.service'
machinectl shell openclaw@ /bin/bash -c 'journalctl --user -u openclaw.service -n 50 --no-pager'
machinectl shell openclaw@ /bin/bash -c 'podman ps -a --filter name=openclaw'

# Restart services
machinectl shell openclaw@ /bin/bash -c 'systemctl --user restart ts-openclaw.service'
machinectl shell openclaw@ /bin/bash -c 'systemctl --user restart openclaw.service'

# Database backup/restore
./scripts/pg-backup.sh
./scripts/pg-restore.sh
```
