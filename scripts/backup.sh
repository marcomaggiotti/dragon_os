#!/usr/bin/env bash
# HomeCore OS — backup configuration, data and secrets.
#
#   backup.sh [--full] [--quiet] [--dest DIR]
#     --full   also include the Home Assistant history database (briefly stops HA)
#     --dest   override BACKUP_DIR from /etc/homecore/homecore.env
#
# Archives are root-only (they contain secrets). If BACKUP_PASSFILE is set they are
# encrypted with AES-256 (openssl, PBKDF2). Keep backups OFF the microSD card.
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"
load_env

FULL=0 QUIET=0 DEST=${BACKUP_DIR:-$HC_ROOT/backups}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full) FULL=1 ;;
    --quiet) QUIET=1 ;;
    --dest) DEST=$2; shift ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done
say() { if (( ! QUIET )); then log "$@"; fi; }

install -d -m 0700 "$DEST"
stamp=$(date +%Y%m%d-%H%M%S)
name="homecore-$(hostname)-$stamp.tar.gz"
out="$DEST/$name"
umask 077

excludes=(--exclude='data/mosquitto/*.db.new'
          --exclude='config/homeassistant/tts' --exclude='config/homeassistant/.cache')
restart_ha=0
if (( FULL )); then
  if container_running homecore-homeassistant; then
    say "Stopping Home Assistant for a consistent database copy…"
    compose stop homeassistant >/dev/null; restart_ha=1
  fi
else
  excludes+=(--exclude='config/homeassistant/home-assistant_v2.db*')
fi

say "Writing $out…"
tar -C "$HC_ROOT" "${excludes[@]}" -czf "$out" \
  .env config data secrets \
  -C / "${HC_ETC#/}" || tar_rc=$?
if (( restart_ha )); then compose start homeassistant >/dev/null; fi
if (( ${tar_rc:-0} > 1 )); then rm -f "$out"; die "tar failed (exit ${tar_rc})."; fi

if [[ -n "${BACKUP_PASSFILE:-}" ]]; then
  [[ -r "$BACKUP_PASSFILE" ]] || die "BACKUP_PASSFILE $BACKUP_PASSFILE is not readable."
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$BACKUP_PASSFILE" -in "$out" -out "$out.enc"
  rm -f "$out"; out="$out.enc"
fi
sha256sum "$out" >"$out.sha256"

# Rotation
keep=${BACKUP_KEEP:-7}
mapfile -t all < <(find "$DEST" -maxdepth 1 -type f \( -name 'homecore-*.tar.gz' -o -name 'homecore-*.tar.gz.enc' \) \
                     -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2-)
for f in "${all[@]:keep}"; do rm -f "$f" "$f.sha256"; done

case "$(df --output=source "$DEST" | tail -1)" in
  /dev/mmcblk0*) say "Note: $DEST is on the microSD card. Set BACKUP_DIR to a USB disk or NAS." ;;
esac
ok "Backup: $out ($(du -h "$out" | cut -f1))"
