#!/usr/bin/env bash
# HomeCore OS — first start (run after install-host.sh and a reboot). Safe to re-run.
# Creates the MQTT service accounts and starts the container stack.
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"
load_env

systemctl is-active --quiet docker || die "Docker is not running (did you reboot after the install?)."
cd "$HC_ROOT"

log "Pulling container images (first time on a Pi 3B: 5–15 minutes)…"
compose pull

log "Creating MQTT service accounts…"
"$HC_ROOT/scripts/mqtt-user.sh" bootstrap

log "Starting the stack…"
compose up -d
ok "Stack started."

ha_pass=$(cat "$HC_SECRETS/mqtt/homeassistant.pass")
ip=$(hostname -I | awk '{ print $1 }')
cat <<INFO

  Home Assistant:  http://$(hostname).local:8123   (or http://$ip:8123)
                   The first start takes a few minutes on a Raspberry Pi.

  Add MQTT in Home Assistant → Settings → Devices & services → Add → MQTT:
      Broker:   127.0.0.1      Port: 1883
      Username: homeassistant
      Password: $ha_pass
  (stored in $HC_SECRETS/mqtt/homeassistant.pass — readable by root only)

  Zigbee dongle plugged in?   sudo homecore zigbee enable
  Remote access:              sudo homecore tailscale
INFO
