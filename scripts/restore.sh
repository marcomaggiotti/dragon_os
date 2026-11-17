#!/usr/bin/env bash
# HomeCore OS — restore a backup created by backup.sh.
#   restore.sh <archive.tar.gz | archive.tar.gz.enc>
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"
load_env

archive=${1:-}
[[ -f "$archive" ]] || die "Usage: restore.sh <backup archive>"
if [[ -f "$archive.sha256" ]]; then
  (cd "$(dirname "$archive")" && sha256sum -c --quiet "$(basename "$archive").sha256") ||
    die "Checksum mismatch — archive is corrupted or was modified."
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
src=$archive
if [[ "$archive" == *.enc ]]; then
  [[ -r "${BACKUP_PASSFILE:-}" ]] || die "Encrypted backup: set BACKUP_PASSFILE in $HC_ENV."
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$BACKUP_PASSFILE" -in "$archive" -out "$work/b.tgz"
  src="$work/b.tgz"
fi

# Refuse archives with absolute paths or '..' (path traversal).
if tar -tzf "$src" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
  die "Archive contains unsafe paths — refusing to restore."
fi

read -r -p "This replaces the current HomeCore configuration and data. Type 'restore' to continue: " a
[[ "$a" == restore ]] || exit 1

compose down 2>/dev/null || true
tar -xzf "$src" -C "$work"
for d in config data secrets; do
  [[ -d "$work/$d" ]] && { rm -rf "${HC_ROOT:?}/$d"; cp -a "$work/$d" "$HC_ROOT/$d"; }
done
[[ -f "$work/.env" ]] && cp -a "$work/.env" "$HC_ROOT/.env"
[[ -d "$work/${HC_ETC#/}" ]] && cp -a "$work/${HC_ETC#/}/." "$HC_ETC/"
compose up -d
ok "Restored from $archive. Re-apply the firewall if the network changed: sudo homecore firewall apply"
