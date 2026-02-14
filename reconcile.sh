#!/usr/bin/env bash
# reconcile.sh — Idempotent GitOps reconciler for Fedora CoreOS
# Reads desired-state.yaml and converges the system to match.
# Decrypts SOPS-encrypted secrets using age before deploying.
#
# Dependencies: bash, git, python3, age (installed via rpm-ostree)
#               sops (downloaded as binary by this script)
# Logging: systemd journal under identifier "coreos-reconciler"

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO_DIR="/var/lib/coreos-gitops"
REPO_URL="${COREOS_GITOPS_REPO_URL:-}"
REPO_BRANCH="${COREOS_GITOPS_BRANCH:-main}"
STATE_FILE="${REPO_DIR}/desired-state.yaml"
LOCK_FILE="/run/coreos-reconciler.lock"
LAST_RUN_FILE="/var/lib/coreos-gitops/.last-successful-run"
LOG_ID="coreos-reconciler"

# Age key for SOPS decryption — deployed via Ignition on first boot
AGE_KEY_FILE="/etc/coreos-gitops/age-key.txt"

CHANGES_MADE=0
REBOOT_NEEDED=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "$*" | systemd-cat -t "${LOG_ID}" -p info;  echo "[INFO]  $*"; }
warn() { echo "$*" | systemd-cat -t "${LOG_ID}" -p warning; echo "[WARN]  $*"; }
err()  { echo "$*" | systemd-cat -t "${LOG_ID}" -p err;   echo "[ERROR] $*"; }

die() { err "$*"; exit 1; }

yaml_get() {
    python3 -c "
import yaml, sys, json
with open('${STATE_FILE}') as f:
    data = yaml.safe_load(f)
keys = '${1}'.strip('.').split('.')
node = data
for k in keys:
    if node is None:
        sys.exit(0)
    if isinstance(node, dict):
        node = node.get(k)
    else:
        sys.exit(0)
if node is None:
    sys.exit(0)
if isinstance(node, list):
    for item in node:
        if isinstance(item, dict):
            print(json.dumps(item))
        else:
            print(item)
elif isinstance(node, dict):
    print(json.dumps(node))
else:
    print(node)
"
}

yaml_get_raw() {
    python3 -c "
import yaml, sys, json
with open('${STATE_FILE}') as f:
    data = yaml.safe_load(f)
keys = '${1}'.strip('.').split('.')
node = data
for k in keys:
    if node is None:
        sys.exit(0)
    if isinstance(node, dict):
        node = node.get(k)
    else:
        sys.exit(0)
if node is None:
    sys.exit(0)
print(json.dumps(node))
"
}

acquire_lock() {
    exec 200>"${LOCK_FILE}"
    if ! flock -n 200; then
        die "Another reconciler instance is running. Exiting."
    fi
}

# ---------------------------------------------------------------------------
# Ensure sops binary is installed (not available via Fedora repos)
# ---------------------------------------------------------------------------
ensure_sops() {
    local desired_version
    desired_version=$(yaml_get '.reconciler.sops_version' 2>/dev/null || echo "3.11.0")

    local sops_bin="/usr/local/bin/sops"

    if [[ -x "${sops_bin}" ]]; then
        local current_version
        current_version=$("${sops_bin}" --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || echo "")
        if [[ "${current_version}" == "${desired_version}" ]]; then
            return 0
        fi
        log "sops version mismatch: have ${current_version}, want ${desired_version}"
    fi

    log "Installing sops v${desired_version}..."

    local arch
    arch=$(uname -m)
    case "${arch}" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       die "Unsupported architecture for sops: ${arch}" ;;
    esac

    local url="https://github.com/getsops/sops/releases/download/v${desired_version}/sops-v${desired_version}.linux.${arch}"
    local tmp_bin
    tmp_bin=$(mktemp)

    if curl -fsSL -o "${tmp_bin}" "${url}"; then
        chmod 0755 "${tmp_bin}"
        mv "${tmp_bin}" "${sops_bin}"
        log "sops v${desired_version} installed to ${sops_bin}"
    else
        rm -f "${tmp_bin}"
        err "Failed to download sops v${desired_version} from ${url}"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# SOPS / age secret decryption
# ---------------------------------------------------------------------------
decrypt_secrets() {
    log "Decrypting SOPS-encrypted secrets..."

    local secrets_dir="${REPO_DIR}/secrets"
    local decrypted_dir="/etc/coreos-gitops"

    if [[ ! -d "${secrets_dir}" ]]; then
        log "No secrets directory found. Skipping decryption."
        return 0
    fi

    if [[ ! -f "${AGE_KEY_FILE}" ]]; then
        err "Age key file not found at ${AGE_KEY_FILE}. Cannot decrypt secrets."
        err "Deploy the age private key via Ignition on first boot."
        return 1
    fi

    mkdir -p "${decrypted_dir}"

    local secrets_changed=0

    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue

        local source target mode
        source=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['source'])")
        target=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['target'])")
        mode=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('mode','0600'))")

        local src="${secrets_dir}/${source}"

        if [[ ! -f "${src}" ]]; then
            warn "Secret ${source} listed but not found in repo."
            continue
        fi

        # Decrypt to a temp file, then compare
        local tmp_decrypted
        tmp_decrypted=$(mktemp)
        trap "rm -f '${tmp_decrypted}'" RETURN

        if ! SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}" sops decrypt --input-type dotenv --output-type dotenv "${src}" > "${tmp_decrypted}" 2>/dev/null; then
            # File might not be encrypted (plaintext during dev), try copying as-is
            warn "SOPS decryption failed for ${source} — treating as plaintext."
            cp "${src}" "${tmp_decrypted}"
        fi

        mkdir -p "$(dirname "${target}")"

        if [[ -f "${target}" ]] && diff -q "${tmp_decrypted}" "${target}" &>/dev/null; then
            rm -f "${tmp_decrypted}"
            continue
        fi

        log "Deploying secret: ${source} → ${target}"
        cp "${tmp_decrypted}" "${target}"
        chmod "${mode}" "${target}"
        chown root:root "${target}"
        rm -f "${tmp_decrypted}"
        secrets_changed=1
        CHANGES_MADE=1
    done < <(yaml_get '.secrets')

    if [[ ${secrets_changed} -eq 1 ]]; then
        log "Secrets updated. Affected services will be restarted during reconciliation."
    else
        log "All secrets up to date."
    fi
}

# ---------------------------------------------------------------------------
# Git pull
# ---------------------------------------------------------------------------
sync_repo() {
    if [[ ! -d "${REPO_DIR}/.git" ]]; then
        if [[ -z "${REPO_URL}" ]]; then
            log "No REPO_URL set and repo exists. Running in local mode."
            return 0
        fi
        if [[ -d "${REPO_DIR}" ]]; then
            log "Stale repo dir without .git found — initializing in place"
            cd "${REPO_DIR}"
            git init -b "${REPO_BRANCH}"
            git remote add origin "${REPO_URL}"
            git fetch origin "${REPO_BRANCH}" --quiet
            git reset --hard "origin/${REPO_BRANCH}" --quiet
            log "Repo initialized at $(git rev-parse --short HEAD)"
        else
            log "Cloning repo ${REPO_URL} → ${REPO_DIR}"
            git clone --branch "${REPO_BRANCH}" "${REPO_URL}" "${REPO_DIR}"
        fi
    else
        cd "${REPO_DIR}"
        local before after
        before=$(git rev-parse HEAD)
        git fetch origin "${REPO_BRANCH}" --quiet
        git reset --hard "origin/${REPO_BRANCH}" --quiet
        after=$(git rev-parse HEAD)
        if [[ "${before}" != "${after}" ]]; then
            log "Repo updated: ${before:0:8} → ${after:0:8}"
        else
            log "Repo up to date at ${after:0:8}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# rpm-ostree packages
# ---------------------------------------------------------------------------
reconcile_packages() {
    log "Reconciling rpm-ostree packages..."

    local -a desired_install=()
    while IFS= read -r pkg; do
        [[ -n "${pkg}" ]] && desired_install+=("${pkg}")
    done < <(yaml_get '.packages.install')

    if [[ ${#desired_install[@]} -eq 0 ]]; then
        log "No packages defined. Skipping."
        return 0
    fi

    local -a current_overlays=()
    while IFS= read -r pkg; do
        current_overlays+=("${pkg}")
    done < <(rpm-ostree status --json | python3 -c "
import sys, json
data = json.load(sys.stdin)
deploy = data['deployments'][0]
for p in deploy.get('requested-packages', []):
    print(p)
" 2>/dev/null || true)

    local -a to_install=()
    for pkg in "${desired_install[@]}"; do
        local found=0
        for cur in "${current_overlays[@]}"; do
            if [[ "${cur}" == "${pkg}" ]]; then
                found=1
                break
            fi
        done
        if [[ ${found} -eq 0 ]]; then
            to_install+=("${pkg}")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        log "Installing packages: ${to_install[*]}"
        if rpm-ostree install --idempotent --allow-inactive "${to_install[@]}"; then
            CHANGES_MADE=1
            if rpm-ostree status --json | python3 -c "
import sys, json
data = json.load(sys.stdin)
sys.exit(0 if len(data['deployments']) > 1 else 1)
" 2>/dev/null; then
                warn "rpm-ostree changes staged. Reboot required."
                REBOOT_NEEDED=1
            fi
        else
            err "Failed to install packages: ${to_install[*]}"
        fi
    else
        log "All packages present."
    fi
}

# ---------------------------------------------------------------------------
# Quadlet / container units
# ---------------------------------------------------------------------------
reconcile_quadlet() {
    log "Reconciling Quadlet units..."

    local source_dir target_dir
    source_dir="${REPO_DIR}/$(yaml_get '.quadlet.source_dir')"
    target_dir="$(yaml_get '.quadlet.target_dir')"

    if [[ ! -d "${source_dir}" ]]; then
        log "Quadlet source dir not found. Skipping."
        return 0
    fi

    mkdir -p "${target_dir}"

    local units_changed=0
    local -a changed_containers=()

    while IFS= read -r unit; do
        [[ -z "${unit}" ]] && continue
        local src="${source_dir}/${unit}"
        local dst="${target_dir}/${unit}"

        if [[ ! -f "${src}" ]]; then
            warn "Quadlet unit ${unit} listed but file not found in repo."
            continue
        fi

        if [[ -f "${dst}" ]] && diff -q "${src}" "${dst}" &>/dev/null; then
            continue
        fi

        log "Syncing Quadlet unit: ${unit}"
        cp "${src}" "${dst}"
        chmod 0644 "${dst}"
        units_changed=1
        CHANGES_MADE=1

        # Track changed .container files for restart
        if [[ "${unit}" == *.container ]]; then
            changed_containers+=("${unit}")
        fi
    done < <(yaml_get '.quadlet.units')

    if [[ ${units_changed} -eq 1 ]]; then
        log "Quadlet units changed. Reloading systemd..."
        systemctl daemon-reload

        for unit in "${changed_containers[@]}"; do
            local svc_name="${unit%.container}"
            if systemctl is-active "${svc_name}.service" &>/dev/null; then
                log "Restarting ${svc_name}.service"
                systemctl restart "${svc_name}.service"
            else
                log "Starting ${svc_name}.service"
                systemctl start "${svc_name}.service" || warn "Failed to start ${svc_name}.service"
            fi
        done
    else
        log "All Quadlet units up to date."
    fi
}

# ---------------------------------------------------------------------------
# User-level Quadlet / rootless container units
# ---------------------------------------------------------------------------
reconcile_user_quadlets() {
    log "Reconciling user-level Quadlet units..."

    local entries
    entries=$(yaml_get_raw '.user_quadlets' 2>/dev/null || echo "null")

    if [[ "${entries}" == "null" || -z "${entries}" ]]; then
        log "No user_quadlets defined. Skipping."
        return 0
    fi

    # Iterate over each user quadlet config
    echo "${entries}" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
if isinstance(data, list):
    for item in data:
        print(json.dumps(item))
" | while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue

        local user source_dir target_dir
        user=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['user'])")
        source_dir="${REPO_DIR}/$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['source_dir'])")"
        target_dir=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['target_dir'])")

        if ! id "${user}" &>/dev/null; then
            warn "User ${user} does not exist. Skipping user quadlet."
            continue
        fi

        if [[ ! -d "${source_dir}" ]]; then
            warn "User quadlet source dir ${source_dir} not found. Skipping."
            continue
        fi

        local uid
        uid=$(id -u "${user}")

        # Ensure lingering is enabled so user services run without login
        if [[ ! -f "/var/lib/systemd/linger/${user}" ]]; then
            log "Enabling linger for user ${user}"
            loginctl enable-linger "${user}"
        fi

        mkdir -p "${target_dir}"
        chown "${user}:${user}" "${target_dir}"

        local units_changed=0
        local -a changed_containers=()

        local units_json
        units_json=$(echo "${entry}" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
for u in data.get('units', []):
    print(u)
")

        while IFS= read -r unit; do
            [[ -z "${unit}" ]] && continue
            local src="${source_dir}/${unit}"
            local dst="${target_dir}/${unit}"

            if [[ ! -f "${src}" ]]; then
                warn "User quadlet unit ${unit} (user=${user}) listed but file not found."
                continue
            fi

            if [[ -f "${dst}" ]] && diff -q "${src}" "${dst}" &>/dev/null; then
                continue
            fi

            log "Syncing user quadlet unit: ${unit} → ${target_dir}/ (user=${user})"
            cp "${src}" "${dst}"
            chmod 0644 "${dst}"
            chown "${user}:${user}" "${dst}"
            units_changed=1
            CHANGES_MADE=1

            if [[ "${unit}" == *.container ]]; then
                changed_containers+=("${unit}")
            fi
        done <<< "${units_json}"

        if [[ ${units_changed} -eq 1 ]]; then
            log "User quadlet units changed for ${user}. Reloading user systemd..."
            sudo -u "${user}" XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user daemon-reload

            for unit in "${changed_containers[@]}"; do
                local svc_name="${unit%.container}"
                if sudo -u "${user}" XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user is-active "${svc_name}.service" &>/dev/null; then
                    log "Restarting ${svc_name}.service (user=${user})"
                    sudo -u "${user}" XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user restart "${svc_name}.service"
                else
                    log "Starting ${svc_name}.service (user=${user})"
                    sudo -u "${user}" XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user start "${svc_name}.service" || warn "Failed to start ${svc_name}.service (user=${user})"
                fi
            done
        else
            log "All user quadlet units up to date for ${user}."
        fi
    done
}

# ---------------------------------------------------------------------------
# Systemd units
# ---------------------------------------------------------------------------
reconcile_systemd() {
    log "Reconciling systemd units..."

    local source_dir target_dir
    source_dir="${REPO_DIR}/$(yaml_get '.systemd.source_dir')"
    target_dir="$(yaml_get '.systemd.target_dir')"

    if [[ ! -d "${source_dir}" ]]; then
        log "Systemd source dir not found. Skipping."
        return 0
    fi

    local units_changed=0

    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue

        local name enabled
        name=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['name'])")
        enabled=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('enabled','true'))")

        local src="${source_dir}/${name}"
        local dst="${target_dir}/${name}"

        if [[ ! -f "${src}" ]]; then
            warn "Systemd unit ${name} listed but file not found in repo."
            continue
        fi

        if [[ -f "${dst}" ]] && diff -q "${src}" "${dst}" &>/dev/null; then
            if [[ "${enabled}" == "True" || "${enabled}" == "true" ]]; then
                systemctl enable "${name}" 2>/dev/null || true
            fi
            continue
        fi

        log "Syncing systemd unit: ${name}"
        cp "${src}" "${dst}"
        chmod 0644 "${dst}"
        units_changed=1
        CHANGES_MADE=1

        if [[ "${enabled}" == "True" || "${enabled}" == "true" ]]; then
            systemctl enable "${name}"
        fi
    done < <(yaml_get '.systemd.units')

    if [[ ${units_changed} -eq 1 ]]; then
        log "Systemd units changed. Reloading daemon..."
        systemctl daemon-reload

        while IFS= read -r entry; do
            [[ -z "${entry}" ]] && continue
            local name
            name=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['name'])")
            if [[ "${name}" == *.timer ]]; then
                systemctl start "${name}" 2>/dev/null || true
            elif [[ "${name}" == *.service ]]; then
                systemctl restart "${name}" 2>/dev/null || true
            fi
        done < <(yaml_get '.systemd.units')
    else
        log "All systemd units up to date."
    fi
}

# ---------------------------------------------------------------------------
# Config files (non-secret)
# ---------------------------------------------------------------------------
reconcile_files() {
    log "Reconciling config files..."

    local files_dir="${REPO_DIR}/files"

    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue

        local source target mode reload_cmd
        source=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['source'])")
        target=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['target'])")
        mode=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('mode','0644'))")
        reload_cmd=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('reload_cmd',''))")

        local src="${files_dir}/${source}"

        if [[ ! -f "${src}" ]]; then
            warn "File ${source} listed but not found in repo."
            continue
        fi

        mkdir -p "$(dirname "${target}")"

        if [[ -f "${target}" ]] && diff -q "${src}" "${target}" &>/dev/null; then
            continue
        fi

        log "Syncing file: ${source} → ${target}"
        cp "${src}" "${target}"
        chmod "${mode}" "${target}"
        CHANGES_MADE=1

        if [[ -n "${reload_cmd}" ]]; then
            log "Running reload command: ${reload_cmd}"
            eval "${reload_cmd}" || warn "Reload command failed: ${reload_cmd}"
        fi
    done < <(yaml_get '.files')

    log "Config files reconciled."
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
reconcile_firewall() {
    log "Reconciling firewall rules..."

    if ! command -v firewall-cmd &>/dev/null; then
        log "firewalld not available. Skipping."
        return 0
    fi

    local default_zone
    default_zone=$(yaml_get '.firewall.default_zone' 2>/dev/null || echo "")
    if [[ -z "${default_zone}" ]]; then
        return 0
    fi

    local current_zone
    current_zone=$(firewall-cmd --get-default-zone)
    if [[ "${current_zone}" != "${default_zone}" ]]; then
        log "Setting default zone to ${default_zone}"
        firewall-cmd --set-default-zone="${default_zone}"
        CHANGES_MADE=1
    fi

    local current_ports
    current_ports=$(firewall-cmd --zone="${default_zone}" --list-ports 2>/dev/null || echo "")

    local fw_changed=0
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        local port
        port=$(echo "${entry}" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['port'])")

        if echo "${current_ports}" | grep -qw "${port}"; then
            continue
        fi

        log "Opening port: ${port}"
        firewall-cmd --zone="${default_zone}" --add-port="${port}" --permanent
        fw_changed=1
        CHANGES_MADE=1
    done < <(yaml_get '.firewall.open_ports')

    if [[ ${fw_changed} -eq 1 ]]; then
        firewall-cmd --reload
    fi

    log "Firewall reconciled."
}

# ---------------------------------------------------------------------------
# Sysctl
# ---------------------------------------------------------------------------
reconcile_sysctl() {
    log "Reconciling sysctl parameters..."

    local sysctl_json
    sysctl_json=$(yaml_get_raw '.sysctl' 2>/dev/null || echo "null")

    if [[ "${sysctl_json}" == "null" || -z "${sysctl_json}" ]]; then
        return 0
    fi

    echo "${sysctl_json}" | python3 -c "
import sys, json, subprocess
data = json.loads(sys.stdin.read())
if not isinstance(data, dict):
    sys.exit(0)
for key, value in data.items():
    current = subprocess.run(['sysctl', '-n', key], capture_output=True, text=True).stdout.strip()
    if current != str(value):
        print(f'{key}={value}')
" | while IFS= read -r param; do
        [[ -z "${param}" ]] && continue
        log "Setting sysctl: ${param}"
        sysctl -w "${param}" >/dev/null
        CHANGES_MADE=1
    done

    log "Sysctl reconciled."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    acquire_lock
    log "=== Reconciliation started ==="

    cd "${REPO_DIR}" 2>/dev/null || {
        if [[ -n "${REPO_URL}" ]]; then
            mkdir -p "${REPO_DIR}"
            sync_repo
            cd "${REPO_DIR}"
        else
            die "REPO_DIR ${REPO_DIR} does not exist and no REPO_URL set."
        fi
    }

    sync_repo

    if [[ ! -f "${STATE_FILE}" ]]; then
        die "State file not found: ${STATE_FILE}"
    fi

    # Bootstrap: ensure python3-pyyaml is available before any YAML parsing
    if ! python3 -c "import yaml" 2>/dev/null; then
        log "PyYAML not found — bootstrapping python3-pyyaml..."
        rpm-ostree install --idempotent --apply-live python3-pyyaml
        log "python3-pyyaml bootstrapped."
    fi

    # Ensure sops binary is available (not in Fedora repos)
    ensure_sops

    # Decrypt secrets first — env files must be in place before containers start
    decrypt_secrets

    reconcile_packages
    reconcile_quadlet
    reconcile_user_quadlets
    reconcile_systemd
    reconcile_files
    reconcile_firewall
    reconcile_sysctl

    # Record successful run
    date -Iseconds > "${LAST_RUN_FILE}"

    if [[ ${CHANGES_MADE} -eq 1 ]]; then
        log "=== Reconciliation complete. Changes were applied. ==="
    else
        log "=== Reconciliation complete. System in desired state. ==="
    fi

    if [[ ${REBOOT_NEEDED} -eq 1 ]]; then
        local auto_reboot
        auto_reboot=$(yaml_get '.reconciler.auto_reboot' 2>/dev/null || echo "false")
        if [[ "${auto_reboot}" == "True" || "${auto_reboot}" == "true" ]]; then
            warn "Auto-reboot enabled. Rebooting in 60 seconds..."
            shutdown -r +1 "CoreOS reconciler: rpm-ostree changes require reboot"
        else
            warn "Reboot required for rpm-ostree changes. Auto-reboot is disabled."
        fi
    fi
}

main "$@"
