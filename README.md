# 🛡️ Linux Hardening Script

A comprehensive Bash script that automates security hardening for Debian/Ubuntu and RHEL/CentOS/Fedora Linux systems. Built as a practical cybersecurity tool to reduce attack surface on freshly provisioned servers.

---

## ✨ Features

| # | Module | What it does |
|---|--------|-------------|
| 1 | **User Management** | Locks the `root` account, enforces password quality policy (14+ chars, mixed types), sets secure `umask 027`, disables legacy system accounts |
| 2 | **SSH Hardening** | Moves SSH off port 22, disables password auth (key-only), disables root login, sets strict timeouts and connection limits |
| 3 | **Firewall (UFW)** | Resets to deny-all, opens only the ports you explicitly list, enables UFW persistently |
| 4 | **Unattended Updates** | Configures automatic security patch installation (`unattended-upgrades` on Debian, `dnf-automatic` on RHEL) |
| 5 | **Disable Insecure Services** | Stops and removes Telnet, FTP, RSH, TFTP, SNMP, and other legacy protocols |
| 6 | **Kernel Hardening** | Applies sysctl hardening: disables IP forwarding, ICMP redirects, enables SYN cookies, restricts kernel pointers, and more |

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/tu-usuario/linux-hardening.git
cd linux-hardening

# 2. (Optional) Edit the config file
cp hardening.conf.example hardening.conf
nano hardening.conf

# 3. Make executable and run as root
chmod +x harden.sh
sudo ./harden.sh
```

> ⚠️ **Always test in a VM or staging environment first.**

---

## ⚙️ Configuration

You can customize the script behavior by editing `hardening.conf` (or by setting environment variables):

```bash
# hardening.conf
SSH_PORT=2222          # Custom SSH port (default: 2222)
ALLOWED_PORTS="80,443" # Comma-separated ports to open in UFW
```

Or pass them inline:

```bash
sudo SSH_PORT=4422 ALLOWED_PORTS="80,443,8080" ./harden.sh
```

---

## 📋 Requirements

- **OS**: Debian 11+, Ubuntu 20.04+, CentOS 8+, RHEL 8+, Fedora 36+
- **Privileges**: Must be run as `root` or via `sudo`
- **Dependencies**: Automatically installed if missing (`ufw`, `unattended-upgrades`, `libpam-pwquality`)

---

## 🔒 SSH Key Setup (Required Before Running)

Because the script disables password-based SSH, you **must** add your public key first:

```bash
# On your LOCAL machine — generate a key pair (if you don't have one)
ssh-keygen -t ed25519 -C "your@email.com"

# Copy the public key to the server BEFORE running harden.sh
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server-ip

# After running the script, connect with:
ssh -p 2222 -i ~/.ssh/id_ed25519 user@server-ip
```

---

## 📁 Project Structure

```
linux-hardening/
├── harden.sh            # Main hardening script
├── hardening.conf       # Optional configuration file
├── tests/
│   └── test_harden.sh   # BATS unit tests (coming soon)
├── docs/
│   └── cis_benchmark.md # Mapping to CIS Benchmark controls
└── README.md
```

---

## 🗺️ CIS Benchmark Alignment

This script is loosely based on the [CIS Linux Benchmark](https://www.cisecurity.org/cis-benchmarks). Key controls covered:

| CIS Control | Implemented |
|-------------|-------------|
| 1.1 – Filesystem hardening | Partial |
| 5.2 – SSH Server config | ✅ Full |
| 5.3 – PAM password policy | ✅ Full |
| 3.4 – Uncommon protocols | ✅ Full |
| 4.3 – Log management | Partial |

---

## 🧪 Testing

```bash
# Run in dry-run mode (planned feature)
sudo ./harden.sh --dry-run

# Check log output
cat /var/log/hardening_*.log
```

---

## ⚠️ Disclaimer

This script modifies critical system configurations. **Use it only on systems you own or have explicit written permission to administer.** Always take a snapshot or backup before running. The author assumes no liability for system outages caused by misconfiguration.

---

## 📜 License

MIT — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/add-aide-integration`)
3. Commit your changes (`git commit -m 'feat: add AIDE file integrity monitoring'`)
4. Push and open a Pull Request

---

## 👤 Author

**Gilberto** — Cybersecurity student | Networks & Infrastructure enthusiast

[![GitHub](https://img.shields.io/badge/GitHub-tu--usuario-181717?logo=github)](https://github.com/bitonub)
