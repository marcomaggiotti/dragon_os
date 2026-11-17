# shellcheck shell=bash
# HomeCore OS — shared helpers for the shell scripts. Source, don't execute.

HC_ROOT="${HC_ROOT:-/opt/homecore}"
HC_ETC="${HC_ETC:-/etc/homecore}"
HC_ENV="$HC_ETC/homecore.env"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  _c_info=$'\033[1;36m' _c_warn=$'\033[1;33m' _c_err=$'\033[1;31m' _c_ok=$'\033[1;32m' _c_off=$'\033[0m'
else
  _c_info='' _c_warn='' _c_err='' _c_ok='' _c_off=''
fi

log()  { printf '%s[homecore]%s %s\n' "$_c_info" "$_c_off" "$*"; }
ok()   { printf '%s[  ok  ]%s %s\n' "$_c_ok" "$_c_off" "$*"; }
warn() { printf '%s[ warn ]%s %s\n' "$_c_warn" "$_c_off" "$*" >&2; }
die()  { printf '%s[error ]%s %s\n' "$_c_err" "$_c_off" "$*" >&2; exit 1; }

# Re-run the calling script as root through sudo, keeping its arguments.
require_root() {
  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null || die "Run this as root (sudo is not installed)."
    exec sudo -- "$0" "$@"
  fi
}

load_env() {
  # shellcheck disable=SC1090
  if [[ -r "$HC_ENV" ]]; then . "$HC_ENV"; fi
}

# Set KEY=VALUE in a simple env file (creates the key if missing).
set_kv() {
  local file=$1 key=$2 value=$3 tmp
  [[ -f "$file" ]] || touch "$file"
  tmp=$(mktemp "${file}.XXXXXX")
  awk -v k="$key" -v v="$value" -F= '
    BEGIN { done = 0 }
    $1 == k { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }' "$file" >"$tmp"
  chmod --reference="$file" "$tmp" 2>/dev/null || true
  chown --reference="$file" "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$file"
}

get_kv() {
  local file=$1 key=$2
  [[ -r "$file" ]] || return 0
  awk -F= -v k="$key" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

# Random URL-safe secret (no external deps beyond coreutils).
gen_secret() {
  # Read a bounded amount of randomness (no SIGPIPE under `set -o pipefail`).
  local len=${1:-32}
  head -c 2048 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c "1-$len"
}

# Add or replace a block delimited by "# >>> homecore" / "# <<< homecore" in a file.
write_managed_block() {
  local file=$1 content=$2 tmp
  tmp=$(mktemp)
  if [[ -f "$file" ]]; then
    awk '/^# >>> homecore/{skip=1; next} /^# <<< homecore/{skip=0; next} !skip' "$file" >"$tmp"
  fi
  printf '# >>> homecore\n%s\n# <<< homecore\n' "$content" >>"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}
