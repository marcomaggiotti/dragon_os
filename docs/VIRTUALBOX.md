# Testing HomeCore OS in Oracle VirtualBox

The installer and the `homecore` CLI behave the same on a Debian VM (amd64) as
on Raspberry Pi OS Lite (arm64). The Pi-only tuning and the Wi-Fi audit are
skipped, since VirtualBox has no Wi-Fi adapter.

## 1. Create the VM

Use the **Debian 13 "trixie" netinst ISO** (amd64).

| Setting | Value |
|---|---|
| Type / Version | Linux / Debian (64-bit) |
| Memory | **1024 MB** (same as the Pi 3B) |
| CPUs | 1 |
| Disk | 8 GB VDI, dynamically allocated |
| Audio | disabled |
| Network | **Bridged Adapter** (see below) |

### Networking: Bridged is required for real results

HomeCore scans the network it sits on.

* **Bridged Adapter**: the VM joins your real home LAN, so it discovers and
  scans your real devices, exactly like the Pi will. *Settings → Network →
  Adapter 1 → Bridged Adapter → your Ethernet card.* (Some Wi-Fi adapters refuse
  bridging. Use a wired connection on the host if you can.)
* **NAT** (VirtualBox default): the VM only sees VirtualBox's virtual router
  (10.0.2.2/3/4). Fine for checking that the installation works, useless for
  scanning.
* For a safe practice lab, attach a second adapter to an *Internal Network* or
  *Host-only* network and put a deliberately insecure VM there.
  [Metasploitable 2](https://sourceforge.net/projects/metasploitable/) is the
  classic choice. Never bridge such a VM to your LAN.

In *Settings → Network → Advanced*, set **Promiscuous Mode: Allow VMs** (or
"Allow All") on the bridged adapter, so ARP discovery sees every device.

## 2. Install Debian without a GUI

1. Hostname `homecore`, empty domain.
2. **Root password: leave EMPTY.** Your user then gets `sudo`.
3. User `homecore`, strong password.
4. Guided partitioning, one partition.
5. **Software selection: untick "Debian desktop environment" and "GNOME"**.
   Keep only **SSH server** and **standard system utilities**.

## 3. Install HomeCore

From your PC:

```bash
ssh-keygen -t ed25519
```

```bash
ssh-copy-id homecore@homecore.local
```

```bash
scp -r homecore-os-2.0.0 homecore@homecore.local:~/
```

On the VM:

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
sudo homecore scan quick
```

Installing the SSH key first means password logins are switched off
automatically. Otherwise `homecore security` will remind you.

## 4. Compare boot time and memory

```bash
homecore boot
```

```bash
homecore status
```

On the VM, `homecore boot` shows the trimmed boot. The Pi adds firmware time on
top, which HomeCore cuts with `boot_delay=0`, no splash and no KMS.

## Snapshots

Snapshot after "clean Debian" and after "HomeCore installed", so you can test
changes and roll back in seconds.
