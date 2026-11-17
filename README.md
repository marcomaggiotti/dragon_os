# HomeCore OS 1.0

A lightweight, security-hardened, **headless** smart-home server kit for the
Raspberry Pi 3B. It also runs in Oracle VirtualBox for testing. It turns
Raspberry Pi OS Lite 64-bit (or Debian 12/13) into a Home Assistant hub with
Zigbee, Bluetooth, Wi-Fi and MQTT devices, private remote access, and a
terminal control centre.

No desktop, no browser on the box, no Node/Python packages on the host. Just
Docker, three small containers and a stdlib-only Python CLI.

```
┌──────────────────────────── Raspberry Pi 3B · Raspberry Pi OS Lite 64-bit ─────────────────────────────┐
│  nftables firewall (default deny, LAN + Tailscale only, SSH rate limit)       Tailscale (WireGuard)  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────────┐                               │
│  │ Home Assistant   │  │ Mosquitto MQTT   │  │ Zigbee2MQTT (optional)│◄── USB Zigbee coordinator     │
│  │ lean config      │◄►│ auth + per-device│◄►│ unprivileged, no caps │                               │
│  │ BLE via D-Bus    │  │ ACL, read-only   │  └───────────────────────┘                               │
│  └──────────────────┘  └──────────────────┘     all host-network, no-new-privileges, memory-capped   │
│  BlueZ · zram swap · journald 64 MB · unattended security updates · SSH keys only                    │
│  homecore CLI: status · network · bluetooth · devices · mqtt · zigbee · security · guard · backup    │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Stack

| Layer | Software |
|---|---|
| Base OS | Raspberry Pi OS Lite 64-bit (Debian 13), text mode only |
| Containers | Docker Engine + Compose plugin (no NAT, no iptables, host networking) |
| Automation | Home Assistant Container, lean configuration |
| Messaging | Eclipse Mosquitto 2 (authentication + per-device ACL) |
| Zigbee | Zigbee2MQTT 2.x (ZBDongle-P → `zstack`, ZBDongle-E → `ember`) |
| Bluetooth | BlueZ, shared with Home Assistant over D-Bus |
| Wi-Fi / DIY | Home Assistant integrations, ESPHome / MQTT |
| Remote access | Tailscale (no router port forwarding) |
| Security | nftables, SSH hardening, sysctl hardening, auto security updates, audit, prompt-injection guard |
| Terminal | `homecore` CLI and menu |

## Quick start

```bash
scp -r homecore-os-1.0.0 homecore@homecore.local:~/
```

```bash
cd ~/homecore-os-1.0.0 && chmod +x scripts/*.sh && ./scripts/install-host.sh
```

```bash
sudo reboot
```

```bash
sudo homecore setup
```

Then open `http://homecore.local:8123`.

* Full guide: **[docs/INSTALL.md](docs/INSTALL.md)**
* Try it first in a VM: **[docs/VIRTUALBOX.md](docs/VIRTUALBOX.md)**

## The `homecore` command

Run `homecore` with no arguments for the interactive menu, or:

| Command | What it does |
|---|---|
| `homecore status` | host, memory/zram, temperature, throttling, services, containers |
| `homecore network [test\|neighbors\|ports]` | interfaces, routes, DNS, Wi-Fi, Tailscale, listening ports; connectivity test; LAN devices |
| `homecore bluetooth [scan]` | adapters, rfkill, BLE scan |
| `homecore devices` | USB, serial ports, Bluetooth adapters, paired Zigbee devices |
| `homecore zigbee detect\|enable\|disable\|pair` | coordinator setup and time-limited pairing |
| `homecore mqtt users\|add\|remove\|listen` | least-privilege MQTT accounts, live traffic |
| `homecore security` | security audit (PASS/WARN/FAIL, `--json`) |
| `homecore guard check\|sanitize\|wrap\|ha\|mqtt` | prompt-injection scanner |
| `homecore firewall status\|apply` | show rules / apply with automatic rollback |
| `homecore logs [ha\|mqtt\|zigbee\|ssh\|firewall\|…] [-f]` | logs |
| `homecore start\|stop\|restart [service]` | control the stack |
| `homecore backup` / `restore` / `update` | maintenance (backup before every update) |
| `homecore tailscale` / `harden` / `setup` | one-off setup tasks |

## Security highlights

* **Firewall**: default-deny nftables. Services are reachable only from the
  LAN and the tailnet. SSH brute force is throttled in the kernel. Docker can't
  open ports behind your back.
* **SSH**: keys only, no root, single allowed user, modern crypto. Changes are
  validated and rolled back automatically if invalid.
* **MQTT**: no anonymous access, and a role per client. A hacked ESPHome node can
  only write its own topics. It cannot unlock your Zigbee lock or impersonate
  other devices.
* **Containers**: none privileged, `no-new-privileges`, dropped capabilities,
  read-only broker, memory limits, Docker socket never mounted.
* **Prompt injection**: `homecore guard` finds instructions hidden in device
  names, MQTT discovery payloads and Zigbee names (incl. invisible Unicode,
  base64 and homoglyphs) before an LLM assistant reads them.
  [docs/PROMPT-INJECTION.md](docs/PROMPT-INJECTION.md)
* **Backups**: checksummed, rotated, optionally AES-256 encrypted, weekly timer.

Details: [docs/SECURITY.md](docs/SECURITY.md) ·
[docs/NETWORKING.md](docs/NETWORKING.md) · [docs/HARDWARE.md](docs/HARDWARE.md)

## Lightweight by design

* text mode only (`multi-user.target`), `APT::Install-Recommends "false"`
* zram swap instead of a swap file, 16 MB GPU memory, audio/camera probing off
* lean Home Assistant config (no `default_config`), recorder tuned for few writes
* kernel rate limiting instead of fail2ban, `docker` log rotation, journald capped at 64 MB
* Zigbee2MQTT only runs when a coordinator is configured
* CLI and guard are pure Python standard library

Measured idle footprint in testing: Home Assistant ≈ 280 MB, Mosquitto ≈ 2 MB.

## Repository layout

```
scripts/   install-host, setup, harden, firewall, mqtt-user, zigbee, backup,
           restore, update, install-tailscale, make-dist
cli/       homecore.py (CLI/menu), homecore_guard.py (prompt-injection scanner)
stack/     docker-compose.yml, env.example, service configuration templates
system/    sshd, sysctl, journald, docker, apt, systemd, motd, NetworkManager
docs/      INSTALL, VIRTUALBOX, SECURITY, NETWORKING, PROMPT-INJECTION, HARDWARE
tests/     unit tests (python3 -m unittest discover -s tests)
```

Build the installable ZIP with `scripts/make-dist.sh` → `dist/homecore-os-1.0.0.zip`.

## License

MIT, see [LICENSE](LICENSE). Home Assistant, Mosquitto, Zigbee2MQTT, Docker and
Tailscale are separate projects under their own licences.
