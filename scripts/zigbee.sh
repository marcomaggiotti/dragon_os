#!/usr/bin/env bash
# HomeCore OS — Zigbee coordinator management.
#
#   zigbee.sh detect                          list USB serial devices and guess the adapter type
#   zigbee.sh enable [DEVICE] [zstack|ember]  configure and start Zigbee2MQTT
#   zigbee.sh disable                         stop Zigbee2MQTT (keeps its data)
#
# Sonoff ZBDongle-P (TI CC2652P)       → zstack
# Sonoff ZBDongle-E (SiLabs EFR32MG21) → ember
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"

guess_adapter() {
  local id=${1,,}
  case "$id" in
    *dongle_plus_v2*|*dongle-e*|*efr32*|*silicon_labs*|*skyconnect*|*zbt-1*) echo ember ;;
    *dongle_plus*|*dongle-p*|*cc2652*|*cc1352*|*texas_instruments*|*slae.sh*|*zzh*) echo zstack ;;
    *conbee*|*raspbee*|*dresden*) echo deconz ;;
    *) echo unknown ;;
  esac
}

detect() {
  local found=0 dev
  for dev in /dev/serial/by-id/*; do
    [[ -e "$dev" ]] || continue
    found=1
    printf '%s\n    -> %s   adapter guess: %s\n' "$dev" "$(readlink -f "$dev")" "$(guess_adapter "${dev##*/}")"
  done
  if (( ! found )); then
    echo "No USB serial devices found. Plug in the Zigbee dongle (VirtualBox: Devices → USB)."
    return 1
  fi
}

enable() {
  local dev=${1:-} adapter=${2:-}
  if [[ -z "$dev" ]]; then
    local c=() d
    for d in /dev/serial/by-id/*; do [[ -e "$d" ]] && c+=("$d"); done
    if (( ${#c[@]} != 1 )); then
      detect || true
      die "Found ${#c[@]} serial devices — pass the one to use: homecore zigbee enable /dev/serial/by-id/…"
    fi
    dev=${c[0]}
  fi
  [[ "$dev" =~ ^/dev/[A-Za-z0-9_./:+-]+$ ]] || die "Refusing unusual device path: $dev"
  [[ -e "$dev" ]] || die "No such device: $dev"
  [[ -n "$adapter" ]] || adapter=$(guess_adapter "${dev##*/}")
  case "$adapter" in
    zstack|ember|deconz|zigate|zboss) ;;
    *) die "Cannot guess the adapter type of $dev — pass it: homecore zigbee enable $dev zstack|ember" ;;
  esac

  set_kv "$HC_ROOT/.env" ZIGBEE_DEVICE "$dev"
  set_kv "$HC_ROOT/.env" ZIGBEE_ADAPTER "$adapter"
  set_kv "$HC_ROOT/.env" COMPOSE_PROFILES zigbee
  [[ -f "$HC_SECRETS/mqtt/zigbee2mqtt.pass" ]] || "$HC_ROOT/scripts/mqtt-user.sh" add zigbee2mqtt zigbee
  compose up -d zigbee2mqtt
  ok "Zigbee2MQTT started on $dev (adapter: $adapter)."
  local token
  token=$(get_kv "$HC_SECRETS/zigbee2mqtt.env" ZIGBEE2MQTT_CONFIG_FRONTEND_AUTH_TOKEN)
  echo "  Frontend: http://$(hostname).local:8080   token: $token"
  echo "  Pair devices: homecore zigbee pair   (opens joining for 120 s)"
}

disable() {
  compose stop zigbee2mqtt 2>/dev/null || true
  compose rm -f zigbee2mqtt 2>/dev/null || true
  set_kv "$HC_ROOT/.env" COMPOSE_PROFILES ""
  ok "Zigbee2MQTT disabled (configuration and paired devices are kept)."
}

case "${1:-}" in
  detect) detect ;;
  enable) require_root "$@"; shift; enable "$@" ;;
  disable) require_root "$@"; disable ;;
  *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
