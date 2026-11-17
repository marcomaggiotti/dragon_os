#!/usr/bin/env bash
# HomeCore OS — host installer.
# Turns a fresh Raspberry Pi OS Lite 64-bit (or Debian 12/13 amd64/arm64, e.g. in
# VirtualBox) into a headless, hardened HomeCore server. Safe to re-run.
#
# Usage: ./scripts/install-host.sh [options]
#   --ssh-user USER     account allowed to SSH in (default: the user running sudo)
#   --hostname NAME     set the hostname (e.g. homecore → homecore.local)
#   --lan CIDR          LAN prefix allowed through the firewall (repeatable; default: auto-detect)
#   --no-bluetooth      do not install BlueZ, disable Bluetooth
#   --no-tailscale      do not install Tailscale
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
WITH_BT=1 WITH_TS=1 WITH_FW=1 WITH_SSH=1 DO_UPGRADE=1 ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-user) SSH_USER=$2; shift ;;
    --hostname) NEW_HOSTNAME=$2; shift ;;
    --lan) LAN_LIST+=("$2"); shift ;;
    --no-bluetooth) WITH_BT=0 ;;
    --no-tailscale) WITH_TS=0 ;;
    --no-firewall) WITH_FW=0 ;;
    --no-ssh-hardening) WITH_SSH=0 ;;
    --no-upgrade) DO_UPGRADE=0 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
  OS_ID=$ID
  OS_CODENAME=${VERSION_CODENAME:-}
  [[ "$ID" == debian || "$ID" == ubuntu || " ${ID_LIKE:-} " == *" debian "* ]] ||
    die "HomeCore needs a Debian-based OS (found: $PRETTY_NAME)."
  [[ "$ID" == raspbian ]] && die "32-bit Raspberry Pi OS detected. Flash Raspberry Pi OS Lite **64-bit**."
  [[ -n "$OS_CODENAME" ]] || die "Cannot determine the Debian codename."

  ARCH=$(dpkg --print-architecture)
  [[ "$ARCH" == arm64 || "$ARCH" == amd64 ]] || die "Unsupported architecture '$ARCH' (need arm64 or amd64)."

  if grep -qi 'raspberry pi' /proc/device-tree/model 2>/dev/null; then
    PLATFORM="pi"; PLATFORM_DESC=$(tr -d '\0' </proc/device-tree/model)
  elif [[ "$(systemd-detect-virt 2>/dev/null || true)" != none && -n "$(systemd-detect-virt 2>/dev/null || true)" ]]; then
    PLATFORM="vm"; PLATFORM_DESC="virtual machine ($(systemd-detect-virt))"
  else
    PLATFORM="metal"; PLATFORM_DESC="bare metal"
  fi

  MEM_MB=$(awk '/MemTotal/ { print int($2/1024) }' /proc/meminfo)
  DISK_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  (( MEM_MB >= 900 )) || warn "Only ${MEM_MB} MB RAM — Home Assistant needs ~1 GB. Expect slowness."
  (( DISK_GB >= 6 )) || die "Only ${DISK_GB} GB free on / — need at least 6 GB."

  [[ -n "$SSH_USER" && "$SSH_USER" != root ]] || {
    if id homecore >/dev/null 2>&1; then SSH_USER=homecore
    else die "Run as a normal user with sudo, or pass --ssh-user <user>."; fi
  }
  id "$SSH_USER" >/dev/null 2>&1 || die "User '$SSH_USER' does not exist."

  log "HomeCore OS $(cat "$SRC/VERSION") installer"
  log "Host: $PLATFORM_DESC · $PRETTY_NAME · $ARCH · ${MEM_MB} MB RAM · ${DISK_GB} GB free"
  log "SSH user: $SSH_USER · Bluetooth: $WITH_BT · Tailscale: $WITH_TS · Firewall: $WITH_FW"
  if (( ! ASSUME_YES )) && [[ -t 0 ]]; then
    read -r -p "Continue? [Y/n] " a
    [[ -z "$a" || "$a" =~ ^[Yy] ]] || exit 1
  fi
}

# ---------------------------------------------------------------- packages
install_packages() {
  log "Installing base packages (no recommends, no GUI)…"
  install -m 0644 "$SRC/system/apt/99homecore-norecommends" /etc/apt/apt.conf.d/99homecore-norecommends
  "${APT[@]}" update
  if (( DO_UPGRADE )); then "${APT[@]}" upgrade; fi
  local pkgs=(ca-certificates curl gnupg nftables python3 iproute2 openssh-server sudo
              avahi-daemon unattended-upgrades kmod)
  if (( WITH_BT )); then pkgs+=(bluez); fi
  swapon --noheadings --show=NAME 2>/dev/null | grep -q zram || pkgs+=(zram-tools)
  "${APT[@]}" install --no-install-recommends "${pkgs[@]}"
  ok "Base packages installed."
}

# ---------------------------------------------------------------- headless & lean
make_headless() {
  log "Configuring headless, lean system…"
  systemctl set-default multi-user.target >/dev/null
  local gui
  gui=$(dpkg-query -W -f='${Package} ${Status}\n' xserver-xorg-core gdm3 lightdm sddm \
        gnome-shell xfce4-session lxsession wayfire labwc 2>/dev/null | awk '/ installed$/ { print $1 }' | xargs || true)
  [[ -z "$gui" ]] || warn "Desktop packages present ($gui). They no longer start; remove them with: sudo apt purge $gui && sudo apt autoremove"

  local svc unneeded=(triggerhappy ModemManager cups cups-browsed rpi-connect rpi-connect-wayvnc)
  if (( ! WITH_BT )); then unneeded+=(bluetooth hciuart); fi
  for svc in "${unneeded[@]}"; do
    if systemctl list-unit-files "$svc.service" --no-legend 2>/dev/null | grep -q .; then
      if systemctl disable --now "$svc.service" >/dev/null 2>&1; then log "  disabled $svc"; fi
    fi
  done

  # Swap: zram (compressed RAM) instead of a swap file wearing out the SD card.
  if systemctl list-unit-files dphys-swapfile.service --no-legend 2>/dev/null | grep -q .; then
    dphys-swapfile swapoff >/dev/null 2>&1 || true
    systemctl disable --now dphys-swapfile >/dev/null 2>&1 || true
    log "  disabled dphys-swapfile (SD wear)"
  fi
  if [[ -f /etc/default/zramswap ]]; then
    write_managed_block /etc/default/zramswap $'ALGO=zstd\nPERCENT=50\nPRIORITY=100'
    systemctl enable zramswap >/dev/null 2>&1 && systemctl restart zramswap >/dev/null 2>&1 || true
  fi

  if [[ -d /etc/NetworkManager/conf.d ]]; then
    install -m 0644 "$SRC/system/networkmanager/homecore-wifi.conf" /etc/NetworkManager/conf.d/homecore-wifi.conf
  fi
  ok "Headless mode, zram swap and service trimming done."
}

tune_pi() {
  [[ "$PLATFORM" == pi ]] || return 0
  log "Applying Raspberry Pi tuning…"
  local cfg=/boot/firmware/config.txt cmd=/boot/firmware/cmdline.txt
  [[ -f $cfg ]] || cfg=/boot/config.txt
  [[ -f $cmd ]] || cmd=/boot/cmdline.txt
  if [[ -f $cfg ]]; then
    write_managed_block "$cfg" $'[all]\n# Headless: minimum GPU memory, no audio/camera/display probing\ngpu_mem=16\ndtparam=audio=off\ncamera_auto_detect=0\ndisplay_auto_detect=0'
    REBOOT_NEEDED=1
  fi
  # Docker memory limits need the memory cgroup controller.
  if [[ -f $cmd ]] && ! grep -q 'cgroup_enable=memory' "$cmd"; then
    sed -i '1 s/$/ cgroup_enable=memory cgroup_memory=1/' "$cmd"
    REBOOT_NEEDED=1
  fi
  ok "Pi tuned (gpu_mem=16, audio off, memory cgroup)."
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

# ---------------------------------------------------------------- docker
install_docker() {
  if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    log "Installing Docker Engine from the official Docker repository…"
    local distro=$OS_ID
    [[ "$distro" == ubuntu ]] || distro=debian
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$distro $OS_CODENAME stable" \
      >/etc/apt/sources.list.d/docker.list
    "${APT[@]}" update
    "${APT[@]}" install --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
  fi
  install -d -m 0755 /etc/docker
  if [[ -f /etc/docker/daemon.json ]] && ! cmp -s /etc/docker/daemon.json "$SRC/system/docker/daemon.json"; then
    cp -f /etc/docker/daemon.json /etc/docker/daemon.json.pre-homecore
  fi
  install -m 0644 "$SRC/system/docker/daemon.json" /etc/docker/daemon.json
  systemctl enable docker >/dev/null 2>&1
  systemctl restart docker
  ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) ready (no NAT, no iptables, host networking)."
}

install_tailscale() {
  (( WITH_TS )) || return 0
  "$SRC/scripts/install-tailscale.sh" --install-only
}

# ---------------------------------------------------------------- homecore files
deploy_files() {
  log "Deploying HomeCore to $HC_ROOT…"
  install -d -m 0755 "$HC_ROOT" "$HC_ROOT/scripts" "$HC_ROOT/cli" "$HC_ROOT/system" "$HC_ROOT/docs" "$HC_ROOT/config"
  install -d -m 0700 "$HC_SECRETS" "$HC_ROOT/backups"
  install -d -m 0755 "$HC_ETC"

  if [[ "$SRC" -ef "$HC_ROOT" ]]; then
    die "Run the installer from the extracted kit (e.g. ~/homecore-os), not from $HC_ROOT."
  fi
  cp -f "$SRC/VERSION" "$HC_ROOT/VERSION"
  cp -f "$SRC/stack/docker-compose.yml" "$HC_ROOT/docker-compose.yml"
  cp -f "$SRC"/scripts/*.sh "$HC_ROOT/scripts/"
  chmod 0755 "$HC_ROOT"/scripts/*.sh
  cp -f "$SRC"/cli/*.py "$HC_ROOT/cli/"
  cp -rf "$SRC/system/." "$HC_ROOT/system/"
  cp -f "$SRC"/docs/*.md "$HC_ROOT/docs/" 2>/dev/null || true
  cp -f "$SRC/README.md" "$HC_ROOT/README.md"

  # Configuration: never overwrite what the user already changed.
  local d
  for d in homeassistant mosquitto zigbee2mqtt; do
    install -d "$HC_ROOT/config/$d"
  done
  local f
  for f in "$SRC"/stack/config/homeassistant/*; do
    [[ -e "$HC_ROOT/config/homeassistant/${f##*/}" ]] || cp "$f" "$HC_ROOT/config/homeassistant/"
  done
  cp -f "$SRC/stack/config/mosquitto/mosquitto.conf" "$HC_ROOT/config/mosquitto/mosquitto.conf"
  install -d "$HC_ROOT/data/mosquitto" "$HC_ROOT/data/zigbee2mqtt"
  [[ -f "$HC_ROOT/data/zigbee2mqtt/configuration.yaml" ]] ||
    cp "$SRC/stack/config/zigbee2mqtt/configuration.yaml" "$HC_ROOT/data/zigbee2mqtt/configuration.yaml"
  if (( ! WITH_BT )); then sed -i '/# HOMECORE_BLUETOOTH/d' "$HC_ROOT/config/homeassistant/configuration.yaml"; fi

  # Ownership: broker runs as uid 1883, Zigbee2MQTT as the admin user.
  local uid gid dialout tz
  uid=$(id -u "$SSH_USER"); gid=$(id -g "$SSH_USER")
  dialout=$(getent group dialout | cut -d: -f3); dialout=${dialout:-20}
  chown -R "$MOSQ_UID:$MOSQ_UID" "$HC_ROOT/config/mosquitto" "$HC_ROOT/data/mosquitto"
  chmod 0750 "$HC_ROOT/config/mosquitto"
  chmod 0640 "$HC_ROOT/config/mosquitto/mosquitto.conf"
  chown -R "$uid:$gid" "$HC_ROOT/data/zigbee2mqtt"
  chmod 0700 "$HC_ROOT/data/zigbee2mqtt"

  # .env for docker compose
  [[ -f "$HC_ROOT/.env" ]] || cp "$SRC/stack/env.example" "$HC_ROOT/.env"
  chmod 0600 "$HC_ROOT/.env"
  tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)
  set_kv "$HC_ROOT/.env" TZ "${tz:-UTC}"
  set_kv "$HC_ROOT/.env" HC_UID "$uid"
  set_kv "$HC_ROOT/.env" HC_GID "$gid"
  set_kv "$HC_ROOT/.env" DIALOUT_GID "$dialout"
  if [[ "$PLATFORM" != pi ]] && (( MEM_MB >= 1800 )); then
    set_kv "$HC_ROOT/.env" HA_MEM_LIMIT 1024m
  fi

  # /etc/homecore/homecore.env — host settings used by the scripts and the CLI
  if [[ ! -f "$HC_ENV" ]]; then
    local admins
    admins=$(ss -Htn state established '( sport = :22 )' 2>/dev/null |
             awk '{ print $4 }' | sed -E 's/:[0-9]+$//; s/^\[|\]$//g' | grep -E '^[0-9.]+$' | sort -u | xargs || true)
    cat >"$HC_ENV" <<EOF
# HomeCore OS host settings. After editing run: sudo homecore firewall apply
HC_ROOT=$HC_ROOT
SSH_USER=$SSH_USER
PLATFORM=$PLATFORM

# Firewall — networks allowed to reach HomeCore services (space separated CIDRs).
# Empty LAN4/LAN6 = auto-detect from the network interfaces at apply time.
LAN4="${LAN_LIST[*]:-}"
LAN6=""
# Workstations that may always SSH in (the address you installed from is pre-filled).
ADMIN4="$admins"
ADMIN6=""
# Ports open to the LAN and to the Tailscale tailnet.
# 22 SSH · 8123 Home Assistant · 1883 MQTT · 8080 Zigbee2MQTT UI
LAN_TCP_PORTS="22 8123 1883 8080"
LAN_UDP_PORTS="5353"
TS_TCP_PORTS="22 8123 1883 8080"
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

  # CLI
  cat >/usr/local/bin/homecore <<EOF
#!/bin/sh
exec /usr/bin/python3 -I $HC_ROOT/cli/homecore.py "\$@"
EOF
  chmod 0755 /usr/local/bin/homecore

  # Login banner, systemd units
  if [[ -d /etc/update-motd.d ]]; then
    install -m 0755 "$SRC/system/motd/20-homecore" /etc/update-motd.d/20-homecore
  fi
  install -m 0644 "$SRC/system/systemd/homecore-backup.service" /etc/systemd/system/
  install -m 0644 "$SRC/system/systemd/homecore-backup.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable homecore-backup.timer >/dev/null 2>&1
  ok "HomeCore files deployed; 'homecore' command installed."
}

setup_firewall() {
  (( WITH_FW )) || { warn "Firewall skipped (--no-firewall)."; return 0; }
  if systemctl is-enabled nftables.service >/dev/null 2>&1; then
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
  # docker group membership == root. Keep the admin out of it; the CLI uses sudo.
  if id -nG "$SSH_USER" | grep -qw docker; then
    warn "$SSH_USER is in the 'docker' group (equivalent to root). Remove with: sudo gpasswd -d $SSH_USER docker"
  fi
}

summary() {
  local ip
  ip=$(hostname -I 2>/dev/null | awk '{ print $1 }')
  echo
  ok "HomeCore OS $(cat "$SRC/VERSION") installed."
  cat <<EOF

  Next steps
    1. sudo reboot$( (( REBOOT_NEEDED )) && echo "            (required: boot settings changed)")
    2. sudo homecore setup      (creates MQTT accounts, starts Home Assistant + Mosquitto)
    3. Open http://$(hostname).local:8123   or   http://${ip:-<ip>}:8123
$( (( WITH_TS )) && echo "    4. sudo homecore tailscale  (log in to your tailnet for remote access)" )

  Then:  homecore             (control menu)
         homecore security    (security audit)
         homecore zigbee detect   (after plugging in the Zigbee USB dongle)
EOF
}

preflight
install_packages
make_headless
tune_pi
set_hostname
install_docker
install_tailscale
deploy_files
harden
setup_firewall
summary
