# HomeCore OS — Security of the appliance itself

A box that maps every weakness of your network is a valuable target. HomeCore
is therefore built to be **invisible from the internet, default-deny on the LAN,
and careful with the data it collects**. `sudo homecore security` audits all of
the following.

## Threat model

| Threat | Main controls |
|---|---|
| Internet attacker | nothing exposed; optional Tailscale for remote access; firewall default-deny |
| Hostile device on the LAN | only SSH open, keys only, kernel rate limiting, `AllowUsers` |
| Malicious data from scanned devices (banners, hostnames, SSIDs) | all device-supplied text sanitised before display; `homecore guard` for prompt injection; nmap XML parsed, never executed |
| Theft of scan results | `/var/lib/homecore` and backups root-only (0700/0600); AES-256 backup encryption |
| Supply chain | packages only from signed Debian (and optionally Tailscale) repositories; no `curl \| sh`; no pip |
| Scanning beyond your authority | targets restricted to private ranges, max /20; safe NSE scripts only |

## Layers

### Network

* **nftables firewall** (`/etc/homecore/firewall.nft`, generated from
  `/etc/homecore/homecore.env`). Inbound policy is *drop*. Allowed:
  * SSH (22) from the LAN, from `ADMIN4` workstations and from Tailscale
  * mDNS (5353) from the LAN
  * replies to HomeCore's own UPnP discovery
  * DHCP and essential ICMP

  Forwarding is dropped. The scanner captures responses with libpcap, so the
  firewall doesn't interfere with scanning.
* **SSH brute-force throttling in the kernel**: more than 8 new connections per
  minute from one address are dropped and logged (`homecore-ssh-flood:`). No
  fail2ban daemon.
* **Safe apply**: `sudo homecore firewall apply` validates the rules and rolls
  back after 120 s unless you confirm from a *new* SSH session.
* **Kernel hardening** (`/etc/sysctl.d/99-homecore.conf`): reverse-path
  filtering, no redirects or source routing, SYN cookies, martian logging,
  `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, unprivileged BPF off.

### Access

* SSH: key-only once a key is installed, no root login, `AllowUsers <you>`, no
  agent/TCP/X11 forwarding, `MaxAuthTries 3`. Legacy ciphers, MACs and key
  exchanges are removed while OpenSSH's modern defaults stay (incl.
  post-quantum `sntrup761x25519` / `mlkem768x25519`). Every change is validated
  with `sshd -t` and rolled back if invalid.
* Scanning needs root (raw sockets). The CLI re-runs itself through `sudo`.
  Nothing is setuid, and there is no `nmap` capability hack.

### Scanner sandbox

`homecore-discover.service` / `homecore-scan.service` run with
`ProtectSystem=strict` (only `/var/lib/homecore` writable), `ProtectHome`,
`PrivateTmp`, `NoNewPrivileges`, `ProtectKernel*`, `RestrictNamespaces` and a
memory cap (120 MB / 250 MB), at low CPU and I/O priority.

### Updates and logs

* Unattended **security** updates daily, with no automatic reboots. `homecore
  status` tells you when a reboot is pending.
* Persistent journal capped at 64 MB.

### Data protection

* Inventory, alerts and reports: `/var/lib/homecore` (0700, files 0600).
* Backups (`homecore backup`, weekly timer): checksummed, rotated, root-only,
  optionally encrypted. To enable encryption:

  ```bash
  sudo sh -c 'umask 077; head -c 48 /dev/urandom | base64 > /root/.homecore-backup-key'
  ```

  Then set `BACKUP_PASSFILE=/root/.homecore-backup-key` and a `BACKUP_DIR`
  outside the SD card in `/etc/homecore/homecore.env`. **Keep a copy of the key
  elsewhere** (password manager). `restore` verifies the checksum and refuses
  any path outside `/etc/homecore` and `/var/lib/homecore`.
* `--cve-lookup` is the only feature that sends data out (product versions to
  vulners.com), and it is off by default.

## Routine

```bash
sudo homecore alerts
```

```bash
sudo homecore report
```

```bash
sudo homecore security
```

```bash
sudo homecore update
```

## Deliberately not installed (to stay light on a Pi 3B)

| Not installed | Why / alternative |
|---|---|
| fail2ban | nftables rate limiting in the kernel, no daemon |
| an IDS (Suricata/Zeek) | far too heavy for 1 GB RAM. HomeCore does active discovery plus change alerts instead. |
| OpenVAS/Greenbone | needs several GB of RAM. nmap safe scripts plus optional vulners cover the essentials. |
| auditd, AIDE | consider them on bigger hardware |
