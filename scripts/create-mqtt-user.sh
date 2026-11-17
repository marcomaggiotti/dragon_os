#!/usr/bin/env bash
# HomeCore OS — interactive helper around mqtt-user.sh (kept for the 1.0 install guide).
# Without arguments it creates the built-in service accounts (homeassistant, hc-cli).
#   create-mqtt-user.sh                  bootstrap service accounts
#   create-mqtt-user.sh <user> [role]    create one user (default role: device)
set -Eeuo pipefail
here=$(dirname "$(readlink -f "$0")")
if [[ $# -eq 0 ]]; then
  exec "$here/mqtt-user.sh" bootstrap
fi
exec "$here/mqtt-user.sh" add "$1" "${2:-device}"
