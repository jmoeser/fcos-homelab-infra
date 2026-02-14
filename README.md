# CoreOS GitOps Reconciler

A lightweight GitOps reconciliation loop for Fedora CoreOS. Define your desired
machine state in this repo — the reconciler pulls changes and converges the
system on a timer.

## Repo Structure

```
.
├── reconcile.sh              # Main reconciliation script
├── desired-state.yaml        # Single source of truth for machine config
├── quadlet/                  # Podman Quadlet unit files (.container, .network, .volume)
│   ├── caddy.container
│   └── monitoring.container
├── systemd/                  # Custom systemd units
│   └── my-backup.timer
├── files/                    # Config files to sync (path mirrors target)
│   └── etc/
│       └── sysctl.d/
│           └── 99-custom.conf
└── scripts/                  # Helper scripts deployed to the host
    └── healthcheck.sh
```

## How It Works

1. A systemd timer runs `reconcile.sh` every 30 minutes.
2. The script pulls this repo and reads `desired-state.yaml`.
3. It converges the system:
   - Installs/removes rpm-ostree packages (stages for next boot if needed).
   - Syncs Quadlet files → reloads systemd → restarts changed containers.
   - Syncs systemd units → reloads and enables/starts them.
   - Syncs arbitrary config files to their target paths.
   - Manages systemd-sysext or other overlays if defined.
4. All actions are idempotent — no changes means no restarts.
5. Logs go to the journal under `coreos-reconciler`.

## Bootstrap

Use Ignition to lay down the reconciler itself on first boot. After that,
all further config is driven by this repo.

See the `ignition/` folder for the Butane source and compiled Ignition config.
