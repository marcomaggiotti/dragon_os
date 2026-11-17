# HomeCore OS 2.0

A lightweight, hardened, **headless home-network security appliance** for the
Raspberry Pi 3B. It also runs in Oracle VirtualBox for testing. It discovers
every device on your LAN, finds insecure services and known vulnerabilities,
audits your Wi-Fi, watches for new devices and ARP spoofing, and protects
itself while doing it.

No desktop, no containers, no Python packages to install: Debian, `nmap`,
`iw`, and a stdlib-only Python CLI. Between scans it runs no daemons of its own:
the idle footprint is essentially that of a bare Raspberry Pi OS Lite.

```
┌─────────────────── Raspberry Pi 3B · Raspberry Pi OS Lite 64-bit (text mode) ───────────────────┐
│  homecore CLI ── discover ──► nmap ARP sweep ──► inventory.json ──► alerts (new device,         │
│               │                                                    new port, gateway MAC change)│
│               ├─ scan ─────► nmap SYN/version + safe NSE checks + IoT ports + MQTT/UPnP probes  │
│               │              └─► findings with severity & fix ──► reports/ (+ optional CVEs)    │
│               ├─ wifi ─────► iw scan ──► WEP/WPA1/TKIP, WPS, evil-twin detection                │
│               └─ guard ────► sanitize device-supplied text (terminal & prompt injection)        │
│  Self-protection: nftables default-deny (SSH only) · SSH keys · sysctl · auto security updates   │
│  Lean: zram · KMS/Bluetooth/audio off · no docs/recommends · trimmed boot · timers, no daemons   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Quick start

```bash
scp -r homecore-os-2.0.0 homecore@homecore.local:~/
```

```bash
cd ~/homecore-os-2.0.0 && chmod +x scripts/*.sh && ./scripts/install-host.sh
```

```bash
sudo reboot
```

```bash
sudo homecore discover
```

```bash
sudo homecore scan
```

Guides:

* [docs/INSTALL.md](docs/INSTALL.md): Raspberry Pi
* [docs/VIRTUALBOX.md](docs/VIRTUALBOX.md): test in a VM
* [docs/SCANNING.md](docs/SCANNING.md): what is checked and how to read results

> Scan only networks you own or are authorised to test. HomeCore refuses
> public addresses and uses nmap's *safe* checks only.

## Commands

Run `homecore` with no arguments for the interactive menu, or:

| Command | What it does |
|---|---|
| `homecore discover` | find all devices (IP, MAC, vendor, hostname); alert on new devices / ARP anomalies |
| `homecore scan [quick\|standard\|deep] [--target CIDR…] [--cve-lookup]` | vulnerability scan with severities and fixes |
| `homecore report [--all\|--json]` | last scan report |
| `homecore devices [trust\|untrust\|forget] <mac\|ip> [name]` | device inventory |
| `homecore alerts` | recent alerts |
| `homecore wifi [--ssid NAME]` | Wi-Fi audit: encryption, WPS, evil twins (Pi only) |
| `homecore guard check\|sanitize\|wrap\|report` | prompt/terminal-injection scanner for device-supplied text |
| `homecore network [test\|neighbors\|ports]` | HomeCore's own network view and connectivity test |
| `homecore security` | self-audit of HomeCore's hardening |
| `homecore status` / `boot` | system and security summary / boot-time report |
| `homecore firewall status\|apply` | HomeCore's own firewall (apply with automatic rollback) |
| `homecore logs [scan\|firewall\|ssh\|system] [-f]` | logs |
| `homecore backup` / `restore` / `update` / `harden` / `tailscale` | maintenance |

Commands that scan or read the inventory re-run themselves through `sudo`.

## What it finds

Examples (full list in [docs/SCANNING.md](docs/SCANNING.md)):

* **critical:**
  * Docker API or ADB exposed
  * VNC without a password
  * Redis/MongoDB/Memcached without authentication
  * MQTT brokers open to anonymous clients
  * your Wi-Fi on WEP or open
  * gateway MAC changed (ARP spoofing)
* **high:**
  * Telnet, TFTP, anonymous FTP, SMBv1, SSHv1
  * SNMP `public`
  * rogue DHCP servers
  * nmap `vuln` hits (e.g. MS17-010)
  * WPA1/TKIP
  * evil-twin access points
* **medium:**
  * RDP/VNC/FTP/RTSP cameras/SQL exposed
  * weak SSH/TLS
  * UPnP IGD on the router
  * WPS
  * new devices
  * new open ports
* **optional:** CVE matching of detected versions via vulners.com (`--cve-lookup`, sends versions online)

The usual blind spot of quick scans is covered: IoT ports outside nmap's top 1000
(1883 MQTT, 2375 Docker, 5555 ADB, 7547 TR-069, 34567/37777 cameras, …) are
always checked.

## Built for a Raspberry Pi 3B

* text mode only; no recommends, no docs/man pages; man-db, ModemManager, wait-online and e2scrub disabled
* KMS graphics driver off (frees its CMA memory), `gpu_mem=16`, on-board Bluetooth off, audio/camera/display probing off, quiet boot
* zram compressed swap instead of a swap file; journald capped at 64 MB
* no daemons of its own: discovery and scans are systemd timers with memory caps and sandboxing
* CLI imports heavy modules lazily and is byte-compiled at install

## Security of HomeCore itself

The firewall drops everything inbound except SSH from the LAN, rate-limited per
source in the kernel. SSH is key-only with no root login and modern crypto.
Kernel network hardening, automatic security updates, a size-capped persistent
journal, and root-only reports and backups (optionally AES-256 encrypted)
complete the picture. See [docs/SECURITY.md](docs/SECURITY.md).

## Repository layout

```
cli/      homecore.py (CLI/menu), homecore_scan.py (discovery & assessment), homecore_guard.py
scripts/  install-host, harden, firewall, backup, restore, update, install-tailscale, make-dist
system/   sshd, sysctl, journald, apt/dpkg, systemd units & timers, motd, NetworkManager
docs/     INSTALL, VIRTUALBOX, SCANNING, SECURITY, PROMPT-INJECTION
tests/    python3 -m unittest discover -s tests
```

Build the installable ZIP with `scripts/make-dist.sh` → `dist/homecore-os-2.0.0.zip`.

## License

MIT, see [LICENSE](LICENSE). nmap is distributed under its own licence (Nmap
Public Source License) and is installed from Debian's repositories.
