#!/usr/bin/env bash
# HomeCore OS — Tailscale (WireGuard VPN) for remote access without opening router ports.
#
#   install-tailscale.sh                 install (if needed) and log in to your tailnet
#   install-tailscale.sh --install-only  install the package only
#
# Home Assistant is then reachable at http://homecore:8123 from your tailnet devices.
# Nothing is exposed to the public internet.
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"

install_pkg() {
  if command -v tailscale >/dev/null; then ok "Tailscale already installed."; return 0; fi
  # shellcheck disable=SC1091
  . /etc/os-release
  local distro=debian
  if [[ "$ID" == ubuntu ]]; then distro=ubuntu; fi
  log "Installing Tailscale from pkgs.tailscale.com (signed apt repository)…"
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL "https://pkgs.tailscale.com/stable/$distro/$VERSION_CODENAME.noarmor.gpg" \
    -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL "https://pkgs.tailscale.com/stable/$distro/$VERSION_CODENAME.tailscale-keyring.list" \
    -o /etc/apt/sources.list.d/tailscale.list
  apt-get -q update
  DEBIAN_FRONTEND=noninteractive apt-get -y -q install --no-install-recommends tailscale
  systemctl enable --now tailscaled >/dev/null
  ok "Tailscale installed."
}

login() {
  log "Connecting to your tailnet — open the URL printed below in a browser to authorise."
  # --ssh=false:          OpenSSH (keys + firewall) stays the only shell entry point.
  # --accept-dns=false:   keep the LAN's DNS (local names, .local) working.
  # --accept-routes=false and no exit node: HomeCore is a leaf, it does not route.
  tailscale up --hostname "$(hostname)" --ssh=false --accept-dns=false --accept-routes=false
  ok "Tailscale IP: $(tailscale ip -4 2>/dev/null | head -1)"
  cat <<'TIP'

  Recommended in the Tailscale admin console (login.tailscale.com):
    • Keep key expiry ON unless the device is physically secure.
    • Tag this machine (tag:homecore) and use ACLs so only your own devices
      can reach it, and only on ports 22 and 8123.
TIP
}

install_pkg
if [[ "${1:-}" != "--install-only" ]]; then login; fi
