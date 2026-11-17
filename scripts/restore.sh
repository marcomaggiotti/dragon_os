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

# Only accept the paths backup.sh writes; refuse absolute paths and '..' (path traversal).
allowed="^(${HC_ETC#/}|var/lib/homecore)(/|$)"
while IFS= read -r member; do
  [[ "$member" =~ (^/|(^|/)\.\.(/|$)) ]] && die "Archive contains unsafe path '$member' — refusing."
  [[ "$member" =~ $allowed ]] || die "Archive contains unexpected path '$member' — refusing."
done < <(tar -tzf "$src")

read -r -p "This replaces the current HomeCore configuration. Type 'restore' to continue: " a
[[ "$a" == restore ]] || exit 1

tar -xzf "$src" -C / --same-owner --same-permissions
ok "Restored from $archive. Re-apply the firewall if the network changed: sudo homecore firewall apply"
