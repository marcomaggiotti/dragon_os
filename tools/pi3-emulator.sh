#!/usr/bin/env bash
# HomeCore OS — Raspberry Pi 3B emulator for testing the kit on your PC.
#
# Emulates a real Raspberry Pi 3 Model B with QEMU (machine "raspi3b": ARM Cortex-A53,
# 1 GB RAM, Pi 3B device tree) running the official Raspberry Pi OS Lite 64-bit image.
# The HomeCore installer detects it as "Raspberry Pi 3 Model B", like the real board.
#
# Runs on Linux, macOS, and Windows through WSL2. No root needed.
#
#   tools/pi3-emulator.sh setup        download + verify Raspberry Pi OS, prepare a fresh SD image
#   tools/pi3-emulator.sh start        boot the emulated Pi in the background (SSH on 127.0.0.1:2222)
#   tools/pi3-emulator.sh console      boot in the foreground on the serial console (Ctrl-A X quits)
#   tools/pi3-emulator.sh wait         wait until SSH answers
#   tools/pi3-emulator.sh ssh [cmd]    log in (or run a command) as user homecore
#   tools/pi3-emulator.sh copy-kit     copy this repository's kit to ~/homecore-os on the Pi
#   tools/pi3-emulator.sh log          follow the serial console log of a background boot
#   tools/pi3-emulator.sh stop         power off
#   tools/pi3-emulator.sh reset        throw the SD image away and prepare a fresh one
#
# Requires: qemu-system-aarch64, qemu-img, mtools, xz, curl, openssl, ssh, fdtput (device-tree-compiler).
#
# Environment: PI_WORK (default ~/.homecore-pi3), PI_SSH_PORT (2222), PI_PASSWORD (asked if unset),
#              PI_SMP (4 emulated cores), PI_IMAGE_URL (default: latest Raspberry Pi OS Lite arm64).
#
# Limits of emulation: no Wi-Fi, no Bluetooth, no GPU firmware (config.txt is ignored; cmdline.txt
# is honoured), networking is QEMU user-mode NAT (the Pi sees 10.0.2.0/24, not your LAN), and it
# runs roughly 2-5x slower than real hardware. Use it to test installation, boot, hardening and
# the CLI on genuine Pi OS arm64; scan your real LAN from the VirtualBox VM or the real Pi.
set -Eeuo pipefail

WORK=${PI_WORK:-$HOME/.homecore-pi3}
PORT=${PI_SSH_PORT:-2222}
SMP=${PI_SMP:-4}
IMAGE_URL=${PI_IMAGE_URL:-https://downloads.raspberrypi.com/raspios_lite_arm64_latest}
REPO=$(cd "$(dirname "$0")/.." && pwd)
IMG="$WORK/sd.img"
KEY="$WORK/id_ed25519"
PIDFILE="$WORK/supervisor.pid"
QEMU_PIDFILE="$WORK/qemu.pid"

say()  { printf '\033[1;36m[pi3]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[pi3]\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  local missing=() c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  if (( ${#missing[@]} )); then
    die "Missing: ${missing[*]}
  Debian/Ubuntu/WSL: sudo apt install qemu-system-arm qemu-utils mtools xz-utils curl openssh-client openssl device-tree-compiler
  macOS (Homebrew):  brew install qemu mtools xz openssl dtc"
  fi
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{ print $1 }'; }

# Byte offset of the FAT boot partition (first MBR entry) — pure shell, no fdisk needed.
boot_offset() { echo $(( $(od -An -tu4 -j454 -N4 "$IMG" | tr -d ' ') * 512 )); }

running() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

hash_password() {
  local pw=$1 h
  h=$(printf '%s' "$pw" | openssl passwd -6 -stdin 2>/dev/null) ||
    die "Your openssl can't create SHA-512 password hashes (macOS: brew install openssl and put it first in PATH)."
  printf '%s' "$h"
}

cmd_setup() {
  need qemu-system-aarch64 qemu-img mcopy mtype xz curl openssl ssh-keygen od fdtput
  mkdir -p "$WORK"
  chmod 700 "$WORK"

  # 1. Download (cached) and verify the official image.
  local url
  url=$(curl -fsSIL -o /dev/null -w '%{url_effective}' "$IMAGE_URL") || die "Cannot reach $IMAGE_URL"
  local xzf="$WORK/${url##*/}"
  if [[ ! -f "$xzf" ]]; then
    say "Downloading ${url##*/} (~550 MB)…"
    curl -fL --progress-bar -o "$xzf.part" "$url" && mv "$xzf.part" "$xzf"
  fi
  say "Verifying SHA-256 against downloads.raspberrypi.com…"
  local expect
  expect=$(curl -fsSL "$url.sha256" | awk '{ print $1 }')
  [[ -n "$expect" && "$(sha256 "$xzf")" == "$expect" ]] || { rm -f "$xzf"; die "Checksum mismatch — download removed, run setup again."; }

  # 2. Fresh SD image, grown to 8 GB (QEMU needs a power-of-two SD size; cloud-init grows the root fs).
  if running; then die "The emulator is running — stop it first."; fi
  say "Preparing a fresh SD card image…"
  xz -dc "$xzf" >"$IMG"
  qemu-img resize -q -f raw "$IMG" 8G
  local off; off=$(boot_offset)

  # 3. Kernel and the Pi 3B device tree come from the image's own boot partition.
  mcopy -o -i "$IMG@@$off" ::/kernel8.img ::/bcm2710-rpi-3-b.dtb "$WORK/"
  make_emulator_dtb

  # 4. First-boot setup through cloud-init (what Raspberry Pi Imager does on a real card).
  [[ -f "$KEY" ]] || ssh-keygen -q -t ed25519 -N '' -C "homecore-pi3-emulator" -f "$KEY"
  local keys pw hash
  keys="      - $(cat "$KEY.pub")"
  for k in "$HOME"/.ssh/id_ed25519.pub "$HOME"/.ssh/id_rsa.pub; do
    [[ -f "$k" ]] && keys+=$'\n'"      - $(cat "$k")"
  done
  pw=${PI_PASSWORD:-}
  if [[ -z "$pw" ]]; then
    read -r -s -p "Password for user 'homecore' on the emulated Pi (needed for sudo): " pw; echo
    [[ -n "$pw" ]] || die "Empty password."
  fi
  hash=$(hash_password "$pw")
  cat >"$WORK/user-data" <<EOF
#cloud-config
# Written by tools/pi3-emulator.sh (same result as Raspberry Pi Imager's settings).
hostname: homecore
manage_etc_hosts: true
users:
  - name: homecore
    gecos: HomeCore
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: false
    passwd: "$hash"
    ssh_authorized_keys:
$keys
ssh_pwauth: true
# Grow the root partition to the whole 8 GB card. On a real Pi the initramfs does this; the
# emulator boots without it, and Pi OS's cloud-init has no growpart/resizefs modules.
write_files:
  # The emulator boots without initramfs, so mkinitramfs can't find the root device and
  # fails every kernel/firmware update (breaking apt). MODULES=most avoids that lookup.
  - path: /etc/initramfs-tools/conf.d/homecore-emulator.conf
    content: |
      MODULES=most
  - path: /usr/local/sbin/homecore-emu-growroot
    permissions: "0755"
    content: |
      #!/bin/sh
      src=\$(findmnt -no SOURCE /)
      [ "\$src" = /dev/root ] && src=/dev/\$(lsblk -rno NAME,MOUNTPOINT | awk '\$2 == "/" { print \$1 }')
      disk=/dev/\$(lsblk -no PKNAME "\$src")
      part=\$(cat "/sys/class/block/\${src##*/}/partition")
      growpart "\$disk" "\$part" || true
      resize2fs "\$src"
runcmd:
  - [systemctl, enable, --now, ssh]
  - [/usr/local/sbin/homecore-emu-growroot]
EOF
  printf 'dsmode: local\ninstance_id: homecore-pi3-%s\n' "$(date +%s)" >"$WORK/meta-data"
  # DHCP on the emulated Ethernet (named eth0 or usb0 depending on boot order); without this
  # NetworkManager may give it only a link-local address.
  printf '%s\n' 'network:' '  version: 2' '  ethernets:' \
    '    eth0:' '      dhcp4: true' '      optional: true' \
    '    usb0:' '      dhcp4: true' '      optional: true' >"$WORK/network-config"
  : >"$WORK/ssh"
  mcopy -o -i "$IMG@@$off" "$WORK/user-data" "$WORK/meta-data" "$WORK/network-config" "$WORK/ssh" ::/
  rm -f "$WORK/known_hosts"
  say "Ready. Next: $0 start   (first boot takes 3-8 minutes)"
}

# The emulator's copy of the Pi 3B device tree, adjusted where QEMU's raspi3b model differs
# from real hardware (nothing on the SD image is changed):
#  - Bluetooth off and serial aliases swapped, like "dtoverlay=disable-bt": the PL011 UART
#    becomes ttyAMA0 = the console (otherwise programs get no console at all);
#  - the SD card on the SDHCI ("mmc") controller instead of SD-host, without DMA: QEMU's
#    SD-host emulation loses interrupts, and its DMA writes corrupt the card.
make_emulator_dtb() {
  local d="$WORK/emu.dtb"
  cp -f "$WORK/bcm2710-rpi-3-b.dtb" "$d"
  fdtput -t s "$d" /soc/serial@7e201000/bluetooth status disabled
  fdtput -t s "$d" /aliases serial0 /soc/serial@7e201000
  fdtput -t s "$d" /aliases serial1 /soc/serial@7e215040
  fdtput -t s "$d" /soc/mmc@7e202000 status disabled
  fdtput -t s "$d" /soc/mmcnr@7e300000 status disabled
  fdtput -t s "$d" /soc/mmc@7e300000 status okay
  fdtput -d "$d" /soc/mmc@7e300000 dmas
  fdtput -d "$d" /soc/mmc@7e300000 dma-names
}

qemu_cmd() {
  [[ -f "$IMG" && -f "$WORK/emu.dtb" ]] || die "No SD image — run: $0 setup"
  local off cmdline
  off=$(boot_offset)
  # Honour the image's own cmdline.txt (so changes made inside the Pi apply on the next boot),
  # pointing the console at the emulated PL011 UART. The kernel mounts the SD card itself
  # (root=PARTUUID=…); Pi OS's initramfs is skipped because it fails under QEMU's raspi3b.
  cmdline=$(mtype -i "$IMG@@$off" ::/cmdline.txt | head -1 | tr -d '\r')
  cmdline=$(printf '%s' "$cmdline" | sed -E 's/console=serial0,[0-9]+/console=ttyAMA0,115200/; s/console=tty1//')
  # QEMU's raspi3b resets the board the moment the BCM2835 watchdog is armed (a real Pi only
  # starts counting), and Pi OS's systemd arms it at boot: keep systemd away from it — in the
  # emulator only, nothing is written to the image.
  cmdline="earlycon=pl011,0x3f201000 $cmdline systemd.watchdog_device=/dev/homecore-no-watchdog"
  QEMU=(qemu-system-aarch64 -M raspi3b -m 1G -smp "$SMP"
        -kernel "$WORK/kernel8.img" -dtb "$WORK/emu.dtb"
        -drive "file=$IMG,if=sd,format=raw"
        -append "$cmdline"
        -device "usb-net,netdev=net0"
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$PORT-:22"
        -no-reboot)
}

cmd_start() {
  need qemu-system-aarch64 mtype
  if running; then say "Already running (pid $(cat "$PIDFILE"))."; return 0; fi
  : >"$WORK/console.log"
  # Background supervisor: QEMU exits on every guest reboot (-no-reboot) so that changes to
  # cmdline.txt take effect like on real hardware; restart it until the Pi powers off.
  nohup "$0" _supervise >>"$WORK/supervisor.log" 2>&1 </dev/null &
  echo $! >"$PIDFILE"
  say "Booting in the background. Console: $0 log   ·   Wait for SSH: $0 wait"
}

cmd_supervise() {
  local boots=0
  while :; do
    boots=$((boots + 1))
    qemu_cmd
    printf '\n===== homecore pi3 emulator: boot %d (%s) =====\n' "$boots" "$(date)" >>"$WORK/console.log"
    "${QEMU[@]}" -display none -monitor none -pidfile "$QEMU_PIDFILE" \
      -chardev "file,id=con,path=$WORK/console.log,append=on" -serial chardev:con || true
    # Kernel prints "reboot: Restarting system" on reboot and "reboot: Power down" on poweroff.
    if tail -n 5 "$WORK/console.log" | grep -q 'Restarting system' && (( boots < 20 )); then
      continue
    fi
    break
  done
  rm -f "$PIDFILE" "$QEMU_PIDFILE"
}

cmd_console() {
  need qemu-system-aarch64 mtype
  if running; then die "Already running in the background — $0 stop first."; fi
  qemu_cmd
  say "Serial console — log in as homecore. Quit QEMU with Ctrl-A then X."
  exec "${QEMU[@]}" -nographic
}

ssh_base() {
  SSH=(ssh -p "$PORT" -i "$KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts"
       -o ConnectTimeout=10 homecore@127.0.0.1)
}

cmd_wait() {
  ssh_base
  local t0=$SECONDS limit=${1:-900}
  say "Waiting for SSH on 127.0.0.1:$PORT (first boot: cloud-init creates the user, can take minutes)…"
  until "${SSH[@]}" -o BatchMode=yes true 2>/dev/null; do
    running || die "QEMU is not running — see $WORK/console.log"
    (( SECONDS - t0 < limit )) || die "No SSH after ${limit}s — see $0 log"
    sleep 10
  done
  say "Up after $((SECONDS - t0))s: $0 ssh"
}

cmd_ssh() { ssh_base; exec "${SSH[@]}" "$@"; }

cmd_copy_kit() {
  ssh_base
  local tmp; tmp=$(mktemp -d)
  # Same files as the release ZIP (scripts/make-dist.sh), without git history or caches.
  tar -C "$REPO" --exclude='__pycache__' -cf "$tmp/kit.tar" README.md LICENSE VERSION cli docs scripts system
  "${SSH[@]}" 'rm -rf ~/homecore-os && mkdir -p ~/homecore-os && tar -xmf - -C ~/homecore-os' <"$tmp/kit.tar"
  rm -rf "$tmp"
  say "Kit copied to ~/homecore-os on the Pi. Install with:"
  say "  $0 ssh   then:   cd ~/homecore-os && ./scripts/install-host.sh"
}

cmd_stop() {
  if ! running; then say "Not running."; return 0; fi
  ssh_base
  say "Shutting down cleanly (sudo will ask for the homecore password)…"
  "${SSH[@]}" -t 'sudo poweroff' 2>/dev/null || true
  local _
  for _ in $(seq 1 30); do running || break; sleep 2; done
  if running; then
    say "No clean shutdown — cutting power."
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    [[ -f "$QEMU_PIDFILE" ]] && kill "$(cat "$QEMU_PIDFILE")" 2>/dev/null || true
  fi
  rm -f "$PIDFILE" "$QEMU_PIDFILE"
  say "Stopped."
}

case "${1:-}" in
  setup) cmd_setup ;;
  start) cmd_start ;;
  console) cmd_console ;;
  wait) shift; cmd_wait "$@" ;;
  ssh) shift; cmd_ssh "$@" ;;
  copy-kit) cmd_copy_kit ;;
  _supervise) cmd_supervise ;;
  log) exec tail -n 50 -f "$WORK/console.log" ;;
  stop) cmd_stop ;;
  reset) cmd_stop; rm -f "$IMG"; cmd_setup ;;
  *) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
