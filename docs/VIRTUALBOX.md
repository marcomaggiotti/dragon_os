# Testing HomeCore OS in Oracle VirtualBox

Try the whole stack on your PC before you touch the Raspberry Pi. The installer
and the `homecore` CLI behave the same on a Debian VM (amd64) as on Raspberry Pi
OS Lite (arm64). Only the Pi-specific tuning (`config.txt`, `cmdline.txt`) is
skipped.

## 1. Create the VM

Download the **Debian 13 "trixie" netinst ISO** for amd64 (debian.org → *Download*).
The netinst image installs no desktop unless you ask for one.

| Setting | Value | Why |
|---|---|---|
| Type / Version | Linux / Debian (64-bit) | |
| Memory | **1024 MB** | same as the Pi 3B, so you see real memory pressure. Use 2048 MB if you want headroom. |
| CPUs | 1–2 | the Pi 3B has 4 slow cores; 1–2 fast cores is comparable |
| Disk | 16 GB, VDI, dynamically allocated | |
| Graphics | VMSVGA, 16 MB | headless: you will use SSH |
| Audio | **disabled** | |
| USB | USB 3.0 (xHCI) controller | to pass through the Zigbee dongle / Bluetooth stick later |
| Network | see below | |

Leave *Unattended installation* off so you control the package selection.

### Network: pick one

**Bridged Adapter (recommended).** The VM gets an address from your router,
exactly like the Pi will. `homecore.local` and the LAN auto-detection in the
firewall then work out of the box.
*Settings → Network → Adapter 1 → Attached to: Bridged Adapter → your Ethernet/Wi-Fi card.*
(Some Wi-Fi cards/access points refuse bridged guests. Then use NAT.)

**NAT with port forwarding.** It works everywhere, but the VM is only reachable
from your PC.
*Adapter 1 → NAT → Advanced → Port Forwarding*:

| Name | Protocol | Host port | Guest port |
|---|---|---|---|
| ssh | TCP | 2222 | 22 |
| ha | TCP | 8123 | 8123 |
| z2m | TCP | 8080 | 8080 |

Then connect with `ssh -p 2222 homecore@127.0.0.1` and open `http://127.0.0.1:8123`.
The firewall sees these connections as coming from `10.0.2.2`, which is inside the
auto-detected `10.0.2.0/24`, so they are allowed.

## 2. Install Debian (no GUI)

In the installer:

1. Hostname: `homecore`. Domain: leave empty.
2. **Root password: leave EMPTY.** Debian then installs `sudo` and puts your
   user in the `sudo` group (HomeCore needs that).
3. User: full name *HomeCore*, username `homecore`, a strong password.
4. Partitioning: *Guided – use entire disk*, all files in one partition.
5. **Software selection: untick "Debian desktop environment" and "GNOME"**.
   Tick only **SSH server** and **standard system utilities**.
6. Install GRUB to `/dev/sda`, reboot, remove the ISO.

You now have a text-only Debian using ~150 MB RAM.

## 3. Copy the kit and install

On your PC (use a key, not a password):

```bash
ssh-keygen -t ed25519 -C "homecore-admin"
```

```bash
ssh-copy-id homecore@homecore.local
```

```bash
scp -r homecore-os-1.0.0 homecore@homecore.local:~/
```

(With NAT: `ssh-copy-id -p 2222 homecore@127.0.0.1` and `scp -P 2222 …`.)

On the VM:

```bash
cd ~/homecore-os-1.0.0 && chmod +x scripts/*.sh && ./scripts/install-host.sh
```

```bash
sudo reboot
```

```bash
sudo homecore setup
```

Because you installed an SSH key *before* running the installer, password
logins are turned off automatically. If you skipped `ssh-copy-id`, password
login stays on and `homecore security` will warn you until you add a key and
run `sudo homecore harden ssh`.

## 4. USB passthrough (Zigbee dongle, Bluetooth stick)

1. Plug the dongle into the PC.
2. VM window → *Devices → USB →* tick the dongle (or add a permanent USB filter
   in *Settings → USB*).
3. In the VM: `homecore zigbee detect`, then `sudo homecore zigbee enable`.

Notes:

* USB 2.0/3.0 passthrough needs a VirtualBox release that includes it. Older
  releases need the *Oracle VirtualBox Extension Pack*, which has its own licence.
* The Pi 3B's built-in Bluetooth does not exist in the VM. Pass a USB Bluetooth
  adapter through, or skip Bluetooth testing until you are on the Pi.
* On Linux hosts your user must be in the `vboxusers` group to see USB devices.

## 5. Moving to the Raspberry Pi

Nothing in the kit is VM-specific. To carry your configuration over:

```bash
sudo homecore backup --dest /tmp
```

Copy the archive to the Pi after installing HomeCore there, then run
`sudo homecore restore /path/to/archive.tar.gz` and
`sudo homecore firewall apply`. The firewall re-detects the LAN. A Zigbee network
moves with the coordinator stick and the `data/zigbee2mqtt` folder.

## Snapshots

Take a VirtualBox snapshot after step 2 ("clean Debian") and after step 3
("HomeCore installed"). You can then test hardening changes and roll back in
seconds.
