# Test HomeCore on an emulated Raspberry Pi 3B (QEMU)

`tools/pi3-emulator.sh` runs the **real Raspberry Pi OS Lite 64-bit image** on an
**emulated Raspberry Pi 3 Model B** (QEMU machine `raspi3b`: ARM Cortex-A53,
1 GB RAM, the Pi 3B device tree). Inside, `/proc/device-tree/model` reads
*"Raspberry Pi 3 Model B"*, so the HomeCore installer takes exactly the same
path as on your real board, Pi-specific tuning included.

| Use it to test | Use VirtualBox or the real Pi for |
|---|---|
| the installer on genuine Pi OS arm64 | scanning your real LAN (the emulator sits behind QEMU's NAT, 10.0.2.0/24) |
| Pi detection and the boot-file changes (`cmdline.txt` is honoured) | the Wi-Fi audit (no Wi-Fi is emulated), Bluetooth |
| SSH hardening, firewall, timers, the CLI | realistic speed (emulation is slower than a real Pi 3B) |

## 1. Requirements

**Windows:** use WSL2 (Ubuntu). In PowerShell as administrator run
`wsl --install`, reboot, open *Ubuntu*, then follow the Linux steps. The
emulator runs fine inside WSL2.

**Linux / WSL2 (Ubuntu, Debian):**

```bash
sudo apt install qemu-system-arm qemu-utils mtools xz-utils curl openssh-client openssl git
```

**macOS (Homebrew):**

```bash
brew install qemu mtools xz openssl
```

You need about 4 GB of free disk space (the downloaded image plus an 8 GB sparse
SD-card image) and an internet connection to `downloads.raspberrypi.com`.

## 2. Get the kit

```bash
git clone -b claude/charming-cray-qu7fmd https://github.com/marcomaggiotti/dragon_os.git
```

```bash
cd dragon_os
```

Alternatively, extract the release ZIP and `cd` into it. The script copies the
kit from the folder it lives in.

## 3. Create the emulated Pi

```bash
tools/pi3-emulator.sh setup
```

This:

1. downloads the latest Raspberry Pi OS Lite 64-bit (~550 MB) and checks its
   SHA-256 against downloads.raspberrypi.com;
2. writes a fresh 8 GB "SD card";
3. adds first-boot settings, as Raspberry Pi Imager would: hostname
   `homecore`, user `homecore` with the password you type, your SSH key, SSH
   enabled.

It creates a dedicated SSH key in `~/.homecore-pi3/` and also adds your own
`~/.ssh/id_ed25519.pub` if you have one.

## 4. Boot it

```bash
tools/pi3-emulator.sh start
```

```bash
tools/pi3-emulator.sh wait
```

The first boot takes several minutes. Pi OS expands the SD card and cloud-init
creates the user, and it may reboot once on its own. `start` handles reboots
like real hardware: each reboot re-reads `cmdline.txt`. To watch the serial
console:

```bash
tools/pi3-emulator.sh log
```

## 5. Install HomeCore inside the emulated Pi

```bash
tools/pi3-emulator.sh copy-kit
```

```bash
tools/pi3-emulator.sh ssh
```

Now you are on the "Pi" (prompt `homecore@homecore`):

```bash
cd ~/homecore-os && ./scripts/install-host.sh
```

The installer prints **"Raspberry Pi 3 Model B"** as the host and applies the Pi
tuning. Then:

```bash
sudo reboot
```

The emulator restarts by itself. Back on your PC:

```bash
tools/pi3-emulator.sh wait
```

```bash
tools/pi3-emulator.sh ssh
```

On the Pi:

```bash
homecore status
```

```bash
sudo homecore security
```

```bash
homecore boot
```

```bash
sudo homecore discover
```

`discover` only sees QEMU's virtual network (10.0.2.2 gateway, 10.0.2.3 DNS).
That is expected: real-LAN scans belong on the VirtualBox VM or the real Pi.

## 6. Daily use

| Command | What it does |
|---|---|
| `tools/pi3-emulator.sh start` / `stop` | power on / clean shutdown |
| `tools/pi3-emulator.sh ssh [command]` | log in, or run one command |
| `tools/pi3-emulator.sh console` | boot in the foreground on the serial console (quit: Ctrl-A, then X) |
| `tools/pi3-emulator.sh copy-kit` | copy your current kit again (after you change it) |
| `tools/pi3-emulator.sh reset` | throw the SD card away and start fresh (the download is kept) |

Settings: `PI_WORK` (default `~/.homecore-pi3`), `PI_SSH_PORT` (default
2222), `PI_SMP` (default 4 cores), `PI_PASSWORD`.

SSH is forwarded only on `127.0.0.1`, so other machines on your LAN can't reach
the emulated Pi.

## Emulation notes

* **Speed:** everything runs on an emulated ARM CPU. Expect apt installs and the
  first boot to be noticeably slower than on a real Pi 3B.
* **`config.txt` is ignored.** QEMU loads the kernel directly; there is no GPU
  firmware. The installer's `config.txt` changes (KMS off, `gpu_mem`, Bluetooth
  off) can be checked in the file, but take effect only on real hardware.
  `cmdline.txt` changes do apply.
* **Watchdog:** QEMU's Pi 3 resets immediately when the hardware watchdog is
  armed (a real Pi starts counting instead). The script therefore tells systemd
  not to use it, through QEMU's kernel command line only. The SD image is
  unchanged.
* **Initramfs:** Pi OS's initramfs fails under QEMU, so the kernel mounts the SD
  card directly. The real Pi uses its initramfs as normal.
