#!/usr/bin/env bash
# HomeCore OS — update the OS packages and the containers (backup first).
#   update.sh [--os-only | --containers-only] [--no-backup]
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"
load_env

DO_OS=1 DO_CT=1 DO_BACKUP=1
for a in "$@"; do
  case "$a" in
    --os-only) DO_CT=0 ;;
    --containers-only) DO_OS=0 ;;
    --no-backup) DO_BACKUP=0 ;;
    *) die "Unknown option: $a" ;;
  esac
done

if (( DO_BACKUP )); then "$HC_ROOT/scripts/backup.sh" --quiet; fi

if (( DO_OS )); then
  log "Updating OS packages…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get -q update
  apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
  apt-get -y -q autoremove --purge
  apt-get -q clean
fi

if (( DO_CT )); then
  log "Updating containers…"
  compose pull
  compose up -d --remove-orphans
  docker image prune -f >/dev/null
fi

[[ -f /run/reboot-required ]] && warn "A reboot is required to finish the update: sudo reboot"
ok "Update complete."
