#!/usr/bin/env bash
# HomeCore OS — update the system (backup first).
#   update.sh [--no-backup]
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"

DO_BACKUP=1
for a in "$@"; do
  case "$a" in
    --no-backup) DO_BACKUP=0 ;;
    *) die "Unknown option: $a" ;;
  esac
done

if (( DO_BACKUP )); then "$HC_ROOT/scripts/backup.sh" --quiet; fi

log "Updating packages…"
export DEBIAN_FRONTEND=noninteractive
apt-get -q update
apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
apt-get -y -q autoremove --purge
apt-get -q clean

if [[ -f /run/reboot-required ]]; then warn "A reboot is required to finish the update: sudo reboot"; fi
ok "Update complete."
