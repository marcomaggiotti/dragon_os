# Installing HomeCore OS on a Raspberry Pi 3B

> Testing on a PC first? Follow [VIRTUALBOX.md](VIRTUALBOX.md). The steps after
> the first boot are identical.

HomeCore is an **installation kit**, not a prebuilt image. It turns a fresh
Raspberry Pi OS Lite 64-bit into a hardened, headless network-security appliance.

## What you need

* Raspberry Pi 3B, a 5 V / 2.5 A power supply
* **Ethernet cable to your router**. HomeCore scans the LAN it is plugged into,
  and Ethernet leaves the Pi's Wi-Fi free for the Wi-Fi audit.
* microSD card (16 GB is plenty; A1/A2 rated)

## 1. Flash the OS

1. **Raspberry Pi Imager** → *Raspberry Pi 3* → **Raspberry Pi OS Lite (64-bit)**.
2. *Edit settings*:
   * hostname `homecore`
   * user `homecore` with a strong password
   * timezone/keyboard
   * **Services → Enable SSH → "Allow public-key authentication only"**, then
     paste your public key (`~/.ssh/id_ed25519.pub`; create one with
     `ssh-keygen -t ed25519`)
   * Wi-Fi: leave empty if you use Ethernet
3. Write the card, boot the Pi, and wait ~2 minutes.

## 2. Copy the kit and install

```bash
scp -r homecore-os-2.0.0 homecore@homecore.local:~/
```

```bash
ssh homecore@homecore.local
```

```bash
cd ~/homecore-os-2.0.0 && chmod +x scripts/*.sh && ./scripts/install-host.sh
```

```bash
sudo reboot
```

The installer takes 3–10 minutes. Options:

| Option | Effect |
|---|---|
| `--with-tailscale` | private remote access to HomeCore |
| `--keep-bluetooth` | keep the on-board Bluetooth (off by default) |
| `--lan 192.168.1.0/24` | set the LAN instead of auto-detecting it |
| `--no-upgrade` | skip the initial `apt upgrade` |
| `--yes` | don't ask for confirmation |

## 3. First scans

```bash
sudo homecore discover
```

Builds the baseline inventory.

```bash
sudo homecore devices trust <mac> "My laptop"
```

Repeat for each device you recognise.

```bash
sudo homecore scan
```

Runs the standard vulnerability scan (5–15 minutes on a Pi 3B).

```bash
sudo homecore wifi
```

Runs the Wi-Fi audit.

From now on, discovery runs every 30 minutes and a standard scan runs every
Sunday night. `homecore alerts` shows what changed.

## 4. Check HomeCore itself

```bash
sudo homecore security
```

```bash
homecore boot
```

## Backups

Reports describe your network's weak spots, so keep backups private. Set
`BACKUP_DIR` (USB stick or NAS) and optionally `BACKUP_PASSFILE` in
`/etc/homecore/homecore.env` (see [SECURITY.md](SECURITY.md)), then:

```bash
sudo homecore backup
```

## Files HomeCore touches

* `/opt/homecore`, `/etc/homecore`, `/var/lib/homecore`, `/usr/local/bin/homecore`
* `/etc/ssh/sshd_config.d/10-homecore.conf`, `/etc/sysctl.d/99-homecore.conf`
* `/etc/systemd/journald.conf.d/homecore.conf`, `/etc/systemd/system/homecore-*`
* `/etc/apt/apt.conf.d/{20auto-upgrades,52homecore-unattended,99homecore-norecommends}`,
  `/etc/dpkg/dpkg.cfg.d/01-homecore-nodoc`
* a `# >>> homecore` block in `config.txt` (the original `vc4-kms-v3d` line is
  commented out, not deleted)

To start fresh, re-flash the card.
