# Installing HomeCore OS on a Raspberry Pi 3B

> Testing on a PC first? Follow [VIRTUALBOX.md](VIRTUALBOX.md). The steps after
> "first boot" are identical.

HomeCore is an **installation kit**, not a prebuilt image. It turns a fresh
Raspberry Pi OS Lite 64-bit into a hardened, headless HomeCore server.

## What you need

* Raspberry Pi 3B (or newer), a 5 V / 2.5 A power supply, Ethernet recommended
* 64 GB microSD card (A1/A2), or a USB SSD
* Optional: Zigbee USB coordinator (Sonoff ZBDongle-P or ZBDongle-E) and a USB extension cable
* A USB stick or NAS share for backups

## 1. Flash the OS (on your computer)

1. Open **Raspberry Pi Imager** → *Raspberry Pi 3* → **Raspberry Pi OS Lite (64-bit)**.
2. *Edit settings* (OS customisation):
   * hostname: `homecore`
   * username `homecore` and a strong password
   * Wi-Fi only if you can't use Ethernet; set your country
   * timezone / keyboard
   * **Services → Enable SSH → "Allow public-key authentication only"**, then
     paste your public key (`~/.ssh/id_ed25519.pub`; create it with
     `ssh-keygen -t ed25519` if you don't have one)
3. Write the card, insert it into the Pi, power on, and wait ~2 minutes.

## 2. Copy the kit

```bash
unzip homecore-os-1.0.0.zip
```

```bash
scp -r homecore-os-1.0.0 homecore@homecore.local:~/
```

```bash
ssh homecore@homecore.local
```

## 3. Install

```bash
cd ~/homecore-os-1.0.0 && chmod +x scripts/*.sh && ./scripts/install-host.sh
```

The installer (5–15 minutes) will:

* upgrade the OS, install a minimal package set (`--no-install-recommends`)
* force text mode, disable unneeded services, replace the swap file with zram
* tune the Pi (16 MB GPU memory, audio off, memory cgroup for container limits)
* install Docker Engine and Tailscale from their signed repositories
* deploy `/opt/homecore`, the `homecore` command, the login banner and a weekly backup timer
* harden the kernel, journald, SSH and automatic security updates
* generate and load the nftables firewall

Options: `--hostname NAME`, `--lan 192.168.1.0/24`, `--no-bluetooth`,
`--no-tailscale`, `--no-upgrade`, `--yes` (see `--help`).

## 4. Reboot and start

```bash
sudo reboot
```

```bash
sudo homecore setup
```

`setup` pulls the images, creates the MQTT accounts (`homeassistant`,
`hc-cli`), starts Mosquitto and Home Assistant, and prints the MQTT password for
Home Assistant.

The commands from the 1.0 instructions still work and do the same thing:
`sudo /opt/homecore/scripts/create-mqtt-user.sh`, then
`cd /opt/homecore && sudo docker compose up -d`.

## 5. Onboard Home Assistant

Open **http://homecore.local:8123** (the first start takes a few minutes on a Pi 3B):

1. Create the owner account (strong password), then enable **multi-factor
   authentication** in your profile.
2. *Settings → Devices & services → Add integration → MQTT* →
   broker `127.0.0.1`, port `1883`, user `homeassistant`, the password from step 4.

## 6. Zigbee (when the coordinator arrives)

```bash
homecore zigbee detect
```

```bash
sudo homecore zigbee enable
```

```bash
homecore zigbee pair
```

Devices appear in Home Assistant automatically through MQTT discovery.

## 7. Remote access

```bash
sudo homecore tailscale
```

## 8. Check everything

```bash
homecore status
```

```bash
homecore security
```

```bash
homecore network test
```

## 9. Backups off the SD card

Mount a USB stick (e.g. at `/mnt/backup`, via `/etc/fstab` with `nofail`), then set
`BACKUP_DIR=/mnt/backup/homecore` in `/etc/homecore/homecore.env`. Optionally
set `BACKUP_PASSFILE` for encryption (see [SECURITY.md](SECURITY.md#6-backups)).

```bash
sudo homecore backup
```

## Uninstall / reset

HomeCore keeps everything in `/opt/homecore` and `/etc/homecore`, plus these
files:
`/etc/ssh/sshd_config.d/10-homecore.conf`, `/etc/sysctl.d/99-homecore.conf`,
`/etc/systemd/journald.conf.d/homecore.conf`, `/etc/docker/daemon.json`,
`/etc/apt/apt.conf.d/{20auto-upgrades,52homecore-unattended,99homecore-norecommends}`,
`/etc/systemd/system/homecore-*`, `/usr/local/bin/homecore`, and a
`# >>> homecore` block in `config.txt`. To start completely fresh, re-flash the
card: it is quicker.
