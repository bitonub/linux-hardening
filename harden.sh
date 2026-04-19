#!/usr/bin/env bash
# =============================================================================
#  Linux Hardening Script
#  Author : Gilberto (github.com/tu-usuario)
#  Version: 1.0.0
#  License: MIT
# =============================================================================
# DISCLAIMER: Run this script only on systems you own or have explicit
# written permission to administer. Review every section before executing.
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Log helpers ───────────────────────────────────────────────────────────────
LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"
log()     { echo -e "${GREEN}[OK]${RESET}  $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERR]${RESET}  $*" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${CYAN}${BOLD}══ $* ══${RESET}" | tee -a "$LOG_FILE"; }

# ── Defaults (override via CLI flags or config file) ─────────────────────────
SSH_PORT="${SSH_PORT:-2222}"
ALLOWED_PORTS="${ALLOWED_PORTS:-80,443}"   # comma-separated
CONFIG_FILE="./hardening.conf"

# ── Parse optional config file ────────────────────────────────────────────────
[[ -f "$CONFIG_FILE" ]] && { log "Loading config: $CONFIG_FILE"; source "$CONFIG_FILE"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────
check_root() {
    [[ $EUID -ne 0 ]] && { error "This script must be run as root."; exit 1; }
}

check_distro() {
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt-get"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    else
        error "Unsupported package manager. Only apt/dnf/yum are supported."
        exit 1
    fi
    log "Detected package manager: $PKG_MGR"
}

# ── 1. USER MANAGEMENT ────────────────────────────────────────────────────────
harden_users() {
    section "1 · User Management"

    # Lock root login (password-based)
    passwd -l root
    log "root account locked (password login disabled)"

    # Enforce strong password policy via PAM (Debian/Ubuntu)
    if [[ "$PKG_MGR" == "apt-get" ]]; then
        apt-get install -y libpam-pwquality &>/dev/null
        PAM_PWQUALITY="/etc/security/pwquality.conf"
        cat > "$PAM_PWQUALITY" <<'EOF'
minlen   = 14
dcredit  = -1
ucredit  = -1
ocredit  = -1
lcredit  = -1
maxrepeat = 3
EOF
        log "Password quality policy applied ($PAM_PWQUALITY)"
    fi

    # Set strict umask globally
    grep -q "umask 027" /etc/profile || echo "umask 027" >> /etc/profile
    log "Global umask set to 027"

    # Lock inactive system accounts (no shell, no password)
    SYSTEM_SHELLS=("sync" "halt" "shutdown")
    for acct in "${SYSTEM_SHELLS[@]}"; do
        if id "$acct" &>/dev/null; then
            usermod -s /usr/sbin/nologin -L "$acct" 2>/dev/null || true
            log "Account '$acct' set to nologin and locked"
        fi
    done

    # Report accounts with empty passwords (do NOT auto-delete)
    EMPTY_PASS=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$EMPTY_PASS" ]]; then
        warn "Accounts with empty/locked passwords (review manually): $EMPTY_PASS"
    fi
}

# ── 2. SSH HARDENING ──────────────────────────────────────────────────────────
harden_ssh() {
    section "2 · SSH Configuration"

    SSHD_CFG="/etc/ssh/sshd_config"
    SSHD_BACKUP="${SSHD_CFG}.bak_$(date +%Y%m%d)"
    cp "$SSHD_CFG" "$SSHD_BACKUP"
    log "SSH config backed up → $SSHD_BACKUP"

    declare -A SSH_SETTINGS=(
        [Port]="$SSH_PORT"
        [PermitRootLogin]="no"
        [PasswordAuthentication]="no"
        [ChallengeResponseAuthentication]="no"
        [UsePAM]="yes"
        [X11Forwarding]="no"
        [MaxAuthTries]="3"
        [LoginGraceTime]="30"
        [AllowAgentForwarding]="no"
        [AllowTcpForwarding]="no"
        [PermitEmptyPasswords]="no"
        [ClientAliveInterval]="300"
        [ClientAliveCountMax]="2"
        [Protocol]="2"
        [LogLevel]="VERBOSE"
    )

    for key in "${!SSH_SETTINGS[@]}"; do
        value="${SSH_SETTINGS[$key]}"
        # Replace or append the setting
        if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "$SSHD_CFG"; then
            sed -i "s|^#\?[[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$SSHD_CFG"
        else
            echo "${key} ${value}" >> "$SSHD_CFG"
        fi
        log "  SSH: $key = $value"
    done

    # Validate config before restarting
    if sshd -t -f "$SSHD_CFG"; then
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
        log "SSHD restarted on port $SSH_PORT"
    else
        error "SSHD config validation FAILED. Restoring backup..."
        cp "$SSHD_BACKUP" "$SSHD_CFG"
        exit 1
    fi

    warn "ACTION REQUIRED: Open port $SSH_PORT in your firewall AND add your public key"
    warn "  before closing this session. Test SSH in a second terminal first!"
}

# ── 3. FIREWALL ───────────────────────────────────────────────────────────────
harden_firewall() {
    section "3 · Firewall (UFW)"

    if ! command -v ufw &>/dev/null; then
        log "Installing UFW..."
        $PKG_MGR install -y ufw &>/dev/null
    fi

    # Reset to clean state
    ufw --force reset &>/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    log "Default policy: DENY incoming / ALLOW outgoing"

    # Always allow new SSH port
    ufw allow "$SSH_PORT/tcp" comment "Custom SSH"
    log "Allowed port $SSH_PORT/tcp (SSH)"

    # Allow user-defined ports
    IFS=',' read -ra PORTS <<< "$ALLOWED_PORTS"
    for port in "${PORTS[@]}"; do
        port="${port// /}"  # trim spaces
        ufw allow "$port" comment "User-defined"
        log "Allowed port $port"
    done

    # Enable UFW
    ufw --force enable
    log "UFW enabled"
    ufw status verbose | tee -a "$LOG_FILE"
}

# ── 4. AUTOMATIC SECURITY UPDATES ────────────────────────────────────────────
harden_updates() {
    section "4 · Unattended Security Updates"

    if [[ "$PKG_MGR" == "apt-get" ]]; then
        apt-get install -y unattended-upgrades apt-listchanges &>/dev/null

        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
EOF

        cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        log "Unattended security upgrades configured (Debian/Ubuntu)"

    elif [[ "$PKG_MGR" == "dnf" || "$PKG_MGR" == "yum" ]]; then
        $PKG_MGR install -y dnf-automatic &>/dev/null 2>&1 || true
        sed -i 's/^apply_updates = .*/apply_updates = yes/' \
            /etc/dnf/automatic.conf 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer 2>/dev/null || true
        log "dnf-automatic enabled (RHEL/CentOS/Fedora)"
    fi
}

# ── 5. DISABLE INSECURE SERVICES ─────────────────────────────────────────────
harden_services() {
    section "5 · Disable Insecure Services"

    INSECURE_SERVICES=(
        "telnet"
        "telnetd"
        "rsh"
        "rsh-server"
        "rlogin"
        "rexec"
        "ftp"
        "vsftpd"
        "proftpd"
        "pure-ftpd"
        "xinetd"
        "nis"
        "snmp"
        "tftp"
        "tftpd"
        "atd"
    )

    for svc in "${INSECURE_SERVICES[@]}"; do
        if systemctl list-units --all | grep -q "$svc"; then
            systemctl stop    "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            log "Disabled service: $svc"
        else
            : # silent — service not present
        fi

        # Also remove package if installed
        if dpkg -l "$svc" &>/dev/null 2>&1; then
            apt-get remove -y --purge "$svc" &>/dev/null || true
            log "Removed package: $svc"
        fi
    done

    # Disable IPv6 if not needed (optional — comment out if you use IPv6)
    if ! grep -q "net.ipv6.conf.all.disable_ipv6" /etc/sysctl.conf; then
        cat >> /etc/sysctl.conf <<'EOF'

# Hardening: disable IPv6
net.ipv6.conf.all.disable_ipv6     = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6      = 1
EOF
        sysctl -p &>/dev/null
        log "IPv6 disabled via sysctl (edit /etc/sysctl.conf to re-enable)"
    fi
}

# ── 6. KERNEL / SYSCTL HARDENING (BONUS) ─────────────────────────────────────
harden_kernel() {
    section "6 · Kernel Parameters (sysctl)"

    SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
    cat > "$SYSCTL_FILE" <<'EOF'
# ── Network ──────────────────────────────────────────────────────────────────
net.ipv4.ip_forward                   = 0
net.ipv4.conf.all.send_redirects      = 0
net.ipv4.conf.default.send_redirects  = 0
net.ipv4.conf.all.accept_redirects    = 0
net.ipv4.conf.default.accept_redirects= 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians        = 1
net.ipv4.icmp_echo_ignore_broadcasts  = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies               = 1
net.ipv4.tcp_timestamps               = 0

# ── Kernel ────────────────────────────────────────────────────────────────────
kernel.randomize_va_space             = 2
kernel.dmesg_restrict                 = 1
kernel.kptr_restrict                  = 2
kernel.sysrq                          = 0
fs.protected_hardlinks                = 1
fs.protected_symlinks                 = 1
EOF
    sysctl --system &>/dev/null
    log "Kernel hardening parameters applied ($SYSCTL_FILE)"
}

# ── SUMMARY ───────────────────────────────────────────────────────────────────
print_summary() {
    echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════╗"
    echo -e "║   Hardening Complete — Summary       ║"
    echo -e "╚══════════════════════════════════════╝${RESET}"
    echo -e "  ${CYAN}Log file  :${RESET} $LOG_FILE"
    echo -e "  ${CYAN}SSH port  :${RESET} $SSH_PORT"
    echo -e "  ${CYAN}Open ports:${RESET} $SSH_PORT, $ALLOWED_PORTS"
    echo -e ""
    echo -e "  ${YELLOW}NEXT STEPS:${RESET}"
    echo -e "  1. Add your SSH public key to ~/.ssh/authorized_keys"
    echo -e "  2. Test SSH in a new terminal: ssh -p $SSH_PORT user@host"
    echo -e "  3. Review the log for any warnings"
    echo -e "  4. Reboot to apply all kernel parameters\n"
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    echo -e "${BOLD}${CYAN}"
    echo "  ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗"
    echo "  ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║"
    echo "  ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║"
    echo "  ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║"
    echo "  ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║"
    echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝"
    echo -e "${RESET}"
    echo -e "  Linux Hardening Script v1.0 — SSH port: ${YELLOW}$SSH_PORT${RESET}\n"

    check_root
    check_distro

    harden_users
    harden_ssh
    harden_firewall
    harden_updates
    harden_services
    harden_kernel

    print_summary
}

main "$@"
