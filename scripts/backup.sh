#!/usr/bin/env bash
# HomeCore OS — back up settings, device inventory, alerts and scan reports.
#
#   backup.sh [--quiet] [--dest DIR]
#     --dest   override BACKUP_DIR from /etc/homecore/homecore.env
#
# Archives are root-only (they describe your network's weak spots). If BACKUP_PASSFILE is set they are
# encrypted with AES-256 (openssl, PBKDF2). Keep backups OFF the microSD card.
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"
load_env

QUIET=0 DEST=${BACKUP_DIR:-$HC_ROOT/backups}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --dest) DEST=$2; shift ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done
say() { if (( ! QUIET )); then log "$@"; fi; }

install -d -m 0700 "$DEST"
out="$DEST/homecore-$(hostname)-$(date +%Y%m%d-%H%M%S).tar.gz"
umask 077

# Paths are stored relative to / so restore.sh can put them back in place.
items=()
for p in "${HC_ETC#/}" var/lib/homecore; do
  if [[ -e "/$p" ]]; then items+=("$p"); fi
done
say "Writing $out…"
tar -C / -czf "$out" "${items[@]}" || tar_rc=$?
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
