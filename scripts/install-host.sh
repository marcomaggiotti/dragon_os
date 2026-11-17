#!/usr/bin/env bash
# HomeCore OS — host installer.
# Turns a fresh Raspberry Pi OS Lite 64-bit (or Debian 12/13 amd64/arm64, e.g. in
# VirtualBox) into a fast, headless, hardened home-network security appliance:
# device discovery, vulnerability scanning, Wi-Fi audit. Safe to re-run.
#
# Usage: ./scripts/install-host.sh [options]
#   --ssh-user USER     account allowed to SSH in (default: the user running sudo)
#   --hostname NAME     set the hostname (e.g. homecore → homecore.local)
#   --lan CIDR          LAN prefix allowed through the firewall (repeatable; default: auto-detect)
#   --with-tailscale    also install Tailscale (private remote access to HomeCore)
#   --keep-bluetooth    leave the on-board Bluetooth enabled (default: switched off)
#   --no-firewall       do not install the nftables firewall (not recommended)
#   --no-ssh-hardening  leave the SSH configuration untouched
#   --no-upgrade        skip the initial apt upgrade
#   -y, --yes           do not ask for confirmation
set -Eeuo pipefail
SRC=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
# shellcheck source=scripts/lib.sh
. "$SRC/scripts/lib.sh"
require_root "$@"

SSH_USER=${SUDO_USER:-}
NEW_HOSTNAME=""
LAN_LIST=()
WITH_BT=0 WITH_TS=0 WITH_FW=1 WITH_SSH=1 DO_UPGRADE=1 ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-user) SSH_USER=$2; shift ;;
    --hostname) NEW_HOSTNAME=$2; shift ;;
    --lan) LAN_LIST+=("$2"); shift ;;
    --with-tailscale) WITH_TS=1 ;;
    --keep-bluetooth) WITH_BT=1 ;;
    --no-firewall) WITH_FW=0 ;;
    --no-ssh-hardening) WITH_SSH=0 ;;
    --no-upgrade) DO_UPGRADE=0 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
  shift
done

export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
REBOOT_NEEDED=0

# ---------------------------------------------------------------- preflight
preflight() {
  [[ -r /etc/os-release ]] || die "Cannot identify the OS."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "$ID" == raspbian ]] && die "32-bit Raspberry Pi OS detected. Flash Raspberry Pi OS Lite **64-bit**."
  [[ "$ID" == debian || "$ID" == ubuntu || " ${ID_LIKE:-} " == *" debian "* ]] ||
    die "HomeCore needs a Debian-based OS (found: $PRETTY_NAME)."
  [[ -n "${VERSION_CODENAME:-}" ]] || die "Cannot determine the Debian codename."

  ARCH=$(dpkg --print-architecture)
  [[ "$ARCH" == arm64 || "$ARCH" == amd64 ]] || die "Unsupported architecture '$ARCH' (need arm64 or amd64)."

  local virt
  virt=$(systemd-detect-virt 2>/dev/null || true)
  if grep -qi 'raspberry pi' /proc/device-tree/model 2>/dev/null; then
    PLATFORM="pi"; PLATFORM_DESC=$(tr -d '\0' </proc/device-tree/model)
  elif [[ -n "$virt" && "$virt" != none ]]; then
    PLATFORM="vm"; PLATFORM_DESC="virtual machine ($virt)"
  else
    PLATFORM="metal"; PLATFORM_DESC="bare metal"
  fi

  MEM_MB=$(awk '/MemTotal/ { print int($2/1024) }' /proc/meminfo)
  DISK_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  (( DISK_GB >= 2 )) || die "Only ${DISK_GB} GB free on / — need at least 2 GB."

  if [[ -z "$SSH_USER" || "$SSH_USER" == root ]]; then
    id homecore >/dev/null 2>&1 || die "Run as a normal user with sudo, or pass --ssh-user <user>."
    SSH_USER=homecore
  fi
  id "$SSH_USER" >/dev/null 2>&1 || die "User '$SSH_USER' does not exist."

  log "HomeCore OS $(cat "$SRC/VERSION") installer — home network security appliance"
  log "Host: $PLATFORM_DESC · $PRETTY_NAME · $ARCH · ${MEM_MB} MB RAM · ${DISK_GB} GB free"
  log "SSH user: $SSH_USER · Tailscale: $WITH_TS · Bluetooth: $WITH_BT · Firewall: $WITH_FW"
  if (( ! ASSUME_YES )) && [[ -t 0 ]]; then
    read -r -p "Continue? [Y/n] " a
    [[ -z "$a" || "$a" =~ ^[Yy] ]] || exit 1
  fi
}

# ---------------------------------------------------------------- packages
install_packages() {
  log "Installing packages (no recommends, no docs, no GUI)…"
  install -m 0644 "$SRC/system/apt/99homecore-norecommends" /etc/apt/apt.conf.d/99homecore-norecommends
  install -d -m 0755 /etc/dpkg/dpkg.cfg.d
  install -m 0644 "$SRC/system/dpkg/01-homecore-nodoc" /etc/dpkg/dpkg.cfg.d/01-homecore-nodoc
  "${APT[@]}" update
  if (( DO_UPGRADE )); then "${APT[@]}" upgrade; fi
  local pkgs=(ca-certificates nftables python3 iproute2 openssh-server sudo
              avahi-daemon unattended-upgrades nmap iw)
  swapon --noheadings --show=NAME 2>/dev/null | grep -q zram || pkgs+=(zram-tools)
  "${APT[@]}" install --no-install-recommends "${pkgs[@]}"
  ok "Packages installed."
}

# ---------------------------------------------------------------- fast, headless, lean
unit_exists() { systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q .; }

make_lean() {
  log "Configuring a headless, fast-booting system…"
  systemctl set-default multi-user.target >/dev/null 2>&1
  local gui
  gui=$(dpkg-query -W -f='${Package} ${Status}\n' xserver-xorg-core gdm3 lightdm sddm \
        gnome-shell xfce4-session lxsession wayfire labwc 2>/dev/null | awk '/ installed$/ { print $1 }' | xargs || true)
  if [[ -n "$gui" ]]; then
    warn "Desktop packages present ($gui). They no longer start; remove them with: sudo apt purge $gui && sudo apt autoremove"
  fi

  # Services/timers that cost boot time, RAM or SD writes and are useless on a headless appliance.
  local u unneeded=(
    triggerhappy.service ModemManager.service cups.service cups-browsed.service
    rpi-connect.service rpi-connect-wayvnc.service rpi-eeprom-update.service
    NetworkManager-wait-online.service systemd-networkd-wait-online.service
    man-db.timer e2scrub_all.timer e2scrub_reap.service
  )
  if (( ! WITH_BT )); then unneeded+=(bluetooth.service hciuart.service); fi
  for u in "${unneeded[@]}"; do
    if unit_exists "$u" && systemctl is-enabled --quiet "$u" 2>/dev/null; then
      if systemctl disable --now "$u" >/dev/null 2>&1; then log "  disabled $u"; fi
    fi
  done
  if unit_exists ModemManager.service; then systemctl mask ModemManager.service >/dev/null 2>&1 || true; fi

  # Swap: zram (compressed RAM) instead of a swap file wearing out the SD card.
  if unit_exists dphys-swapfile.service; then
    dphys-swapfile swapoff >/dev/null 2>&1 || true
    systemctl disable --now dphys-swapfile >/dev/null 2>&1 || true
    log "  disabled dphys-swapfile (SD wear)"
  fi
  if [[ -f /etc/default/zramswap ]]; then
    write_managed_block /etc/default/zramswap $'ALGO=zstd\nPERCENT=50\nPRIORITY=100'
    systemctl enable zramswap >/dev/null 2>&1 || true
    systemctl restart zramswap >/dev/null 2>&1 || true
  fi

  if [[ -d /etc/NetworkManager/conf.d ]]; then
    install -m 0644 "$SRC/system/networkmanager/homecore-wifi.conf" /etc/NetworkManager/conf.d/homecore-wifi.conf
  fi

  # GRUB (VirtualBox/PC): no menu delay.
  if [[ -f /etc/default/grub ]] && command -v update-grub >/dev/null; then
    if ! grep -q '^GRUB_TIMEOUT=0' /etc/default/grub; then
      sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' /etc/default/grub
      update-grub >/dev/null 2>&1 || true
      REBOOT_NEEDED=1
    fi
  fi
  ok "Headless, zram swap, boot-time services trimmed."
}

tune_pi() {
  [[ "$PLATFORM" == pi ]] || return 0
  log "Applying Raspberry Pi 3B tuning…"
  local cfg=/boot/firmware/config.txt cmd=/boot/firmware/cmdline.txt block
  [[ -f $cfg ]] || cfg=/boot/config.txt
  [[ -f $cmd ]] || cmd=/boot/cmdline.txt
  if [[ -f $cfg ]]; then
    # Headless: the KMS graphics driver reserves a CMA memory pool and slows boot.
    # Without it the firmware framebuffer still gives you an HDMI console.
    if grep -qE '^\s*dtoverlay=vc4-(f)?kms-v3d' "$cfg"; then
      sed -i -E 's/^\s*(dtoverlay=vc4-(f)?kms-v3d.*)$/#\1  # disabled by homecore (headless)/' "$cfg"
    fi
    block=$'[all]\n# HomeCore: headless & fast boot\ngpu_mem=16\ndisable_splash=1\nboot_delay=0\ndtparam=audio=off\ncamera_auto_detect=0\ndisplay_auto_detect=0'
    if (( ! WITH_BT )); then
      block+=$'\n# On-board Bluetooth off: faster boot, UART freed, less 2.4 GHz noise for Wi-Fi\ndtoverlay=disable-bt'
    fi
    write_managed_block "$cfg" "$block"
    REBOOT_NEEDED=1
  fi
  if [[ -f $cmd ]]; then
    local line opt
    line=$(head -1 "$cmd")
    for opt in quiet loglevel=3 logo.nologo; do
      [[ " $line " == *" $opt "* ]] || line+=" $opt"
    done
    if [[ "$line" != "$(head -1 "$cmd")" ]]; then
      printf '%s\n' "$line" >"$cmd"
      REBOOT_NEEDED=1
    fi
  fi
  ok "Pi tuned (KMS off, gpu_mem=16, no splash/audio/camera probing, quiet boot$( (( WITH_BT )) || echo ", Bluetooth off"))."
}

set_hostname() {
  [[ -n "$NEW_HOSTNAME" ]] || return 0
  [[ "$NEW_HOSTNAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "Invalid hostname: $NEW_HOSTNAME"
  hostnamectl set-hostname "$NEW_HOSTNAME"
  if grep -q '^127\.0\.1\.1' /etc/hosts; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
  else
    printf '127.0.1.1\t%s\n' "$NEW_HOSTNAME" >>/etc/hosts
  fi
  ok "Hostname set to $NEW_HOSTNAME ($NEW_HOSTNAME.local)."
}

# ---------------------------------------------------------------- homecore files
deploy_files() {
  log "Deploying HomeCore to $HC_ROOT…"
  if [[ "$SRC" -ef "$HC_ROOT" ]]; then
    die "Run the installer from the extracted kit (e.g. ~/homecore-os), not from $HC_ROOT."
  fi
  install -d -m 0755 "$HC_ROOT" "$HC_ROOT/scripts" "$HC_ROOT/cli" "$HC_ROOT/system" "$HC_ROOT/docs" "$HC_ETC"
  install -d -m 0700 "$HC_ROOT/backups" /var/lib/homecore

  cp -f "$SRC/VERSION" "$SRC/README.md" "$HC_ROOT/"
  cp -f "$SRC"/scripts/*.sh "$HC_ROOT/scripts/"
  chmod 0755 "$HC_ROOT"/scripts/*.sh
  cp -f "$SRC"/cli/*.py "$HC_ROOT/cli/"
  cp -rf "$SRC/system/." "$HC_ROOT/system/"
  cp -f "$SRC"/docs/*.md "$HC_ROOT/docs/"
  # Pre-compile the CLI once, so every `homecore` call starts faster on the Pi.
  python3 -m compileall -q "$HC_ROOT/cli" >/dev/null 2>&1 || true

  if [[ ! -f "$HC_ENV" ]]; then
    local admins
    admins=$(ss -Htn state established '( sport = :22 )' 2>/dev/null |
             awk '{ print $4 }' | sed -E 's/:[0-9]+$//' | grep -E '^[0-9.]+$' | sort -u | xargs || true)
    cat >"$HC_ENV" <<EOF
# HomeCore OS host settings. After editing run: sudo homecore firewall apply
HC_ROOT=$HC_ROOT
SSH_USER=$SSH_USER
PLATFORM=$PLATFORM

# Firewall — networks allowed to reach HomeCore itself (space separated CIDRs).
# Empty LAN4/LAN6 = auto-detect from the network interfaces at apply time.
LAN4="${LAN_LIST[*]:-}"
LAN6=""
# Workstations that may always SSH in (the address you installed from is pre-filled).
ADMIN4="$admins"
ADMIN6=""
# Ports of HomeCore itself open to the LAN / Tailscale tailnet: 22 SSH, 5353 mDNS
LAN_TCP_PORTS="22"
LAN_UDP_PORTS="5353"
TS_TCP_PORTS="22"
TAILSCALE_UDP_PORT=41641
SSH_RATE="8/minute"

# Backups — point BACKUP_DIR at a USB disk or NAS mount, not the SD card.
BACKUP_DIR=$HC_ROOT/backups
BACKUP_KEEP=7
# File holding a passphrase to encrypt backups (AES-256, openssl). Empty = no encryption.
BACKUP_PASSFILE=
EOF
    chmod 0644 "$HC_ENV"
  fi

  cat >/usr/local/bin/homecore <<EOF
#!/bin/sh
exec /usr/bin/python3 -I $HC_ROOT/cli/homecore.py "\$@"
EOF
  chmod 0755 /usr/local/bin/homecore

  if [[ -d /etc/update-motd.d ]]; then
    install -m 0755 "$SRC/system/motd/20-homecore" /etc/update-motd.d/20-homecore
  fi
  install -m 0644 "$SRC/system/systemd/homecore-backup.service" /etc/systemd/system/
  install -m 0644 "$SRC/system/systemd/homecore-backup.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable homecore-backup.timer >/dev/null 2>&1
  ok "HomeCore files deployed; 'homecore' command installed."
}

# ---------------------------------------------------------------- scanner
setup_scanner() {
  log "Setting up network discovery and scanning…"
  local u
  for u in homecore-discover.service homecore-discover.timer homecore-scan.service homecore-scan.timer; do
    install -m 0644 "$SRC/system/systemd/$u" /etc/systemd/system/
  done
  systemctl daemon-reload
  systemctl enable --now homecore-discover.timer homecore-scan.timer >/dev/null 2>&1
  ok "Discovery every 30 min, standard vulnerability scan weekly ($(nmap --version | head -1 | awk '{ print $1, $2, $3 }'))."
}

install_tailscale() {
  (( WITH_TS )) || return 0
  "$SRC/scripts/install-tailscale.sh" --install-only
}

setup_firewall() {
  if (( ! WITH_FW )); then warn "Firewall skipped (--no-firewall)."; return 0; fi
  if systemctl is-enabled --quiet nftables.service 2>/dev/null; then
    warn "Debian's nftables.service is enabled; its 'flush ruleset' would wipe HomeCore rules. Disabling it."
    systemctl disable nftables.service >/dev/null 2>&1 || true
  fi
  "$HC_ROOT/scripts/firewall.sh" apply
  install -m 0644 "$SRC/system/systemd/homecore-firewall.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable homecore-firewall.service >/dev/null 2>&1
}

harden() {
  "$HC_ROOT/scripts/harden.sh" kernel
  "$HC_ROOT/scripts/harden.sh" journald
  "$HC_ROOT/scripts/harden.sh" updates
  if (( WITH_SSH )); then SSH_USER=$SSH_USER "$HC_ROOT/scripts/harden.sh" ssh; fi
}

summary() {
  echo
  ok "HomeCore OS $(cat "$SRC/VERSION") installed. RAM in use now: $(free -m | awk '/^Mem:/ { print $3 }') MB"
  echo
  echo "  Next steps"
  if (( REBOOT_NEEDED )); then
    echo "    • sudo reboot                  (boot settings changed)"
  fi
  echo "    • sudo homecore discover       (find every device on your LAN)"
  echo "    • sudo homecore scan           (vulnerability scan; 'quick' and 'deep' also available)"
  echo "    • sudo homecore wifi           (Wi-Fi security audit — Raspberry Pi, not VirtualBox)"
  echo "    • homecore                     (menu)  ·  sudo homecore security  (self-audit)"
  if (( WITH_TS )); then
    echo "    • sudo homecore tailscale      (connect to your tailnet)"
  fi
  echo
  echo "  Scan only networks you own or are authorised to test."
}

preflight
install_packages
deploy_files
make_lean
tune_pi
set_hostname
setup_scanner
install_tailscale
harden
setup_firewall
summary
