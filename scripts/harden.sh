#!/usr/bin/env bash
# HomeCore OS — system hardening. Safe to re-run.
#
#   harden.sh all            everything below
#   harden.sh ssh            SSH: keys only (if a key is installed), no root, modern crypto
#   harden.sh kernel         sysctl network/kernel hardening
#   harden.sh journald       small persistent logs
#   harden.sh updates        automatic security updates
#
# Environment: SSH_USER (account allowed to log in; default from homecore.env or $SUDO_USER)
set -Eeuo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$(readlink -f "$0")")/lib.sh"
require_root "$@"
load_env

SRC=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
SYS="$SRC/system"

harden_ssh() {
  local user=${SSH_USER:-${SUDO_USER:-}} home keys pw_auth methods allow
  [[ -n "$user" && "$user" != root ]] || die "Set SSH_USER (the non-root account you log in with)."
  home=$(getent passwd "$user" | cut -d: -f6) || die "User '$user' does not exist."
  keys="$home/.ssh/authorized_keys"

  if [[ -s "$keys" ]] && grep -qE '^(ssh-|ecdsa-|sk-)' "$keys"; then
    pw_auth=no; methods=publickey
  else
    pw_auth=yes; methods=any
    warn "No SSH public key found in $keys — password login stays ENABLED."
    warn "From your computer run:  ssh-copy-id $user@<this-host>   then:  sudo homecore harden ssh"
  fi
  allow="AllowUsers $user"

  install -d -m 0755 /etc/ssh/sshd_config.d
  local target=/etc/ssh/sshd_config.d/10-homecore.conf backup=""
  [[ -f "$target" ]] && { backup=$(mktemp); cp -f "$target" "$backup"; }
  sed -e "s|@PASSWORD_AUTH@|$pw_auth|" -e "s|@AUTH_METHODS@|$methods|" -e "s|@ALLOW_USERS@|$allow|" \
    "$SYS/ssh/10-homecore.conf.in" >"$target"
  chmod 0644 "$target"

  # Debian's sshd_config must include the drop-in directory (it does by default).
  grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config ||
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

  if sshd -t 2>/tmp/homecore-sshd.err; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    ok "SSH hardened (password login: $pw_auth, allowed user: $user)."
  else
    cat /tmp/homecore-sshd.err >&2
    if [[ -n "$backup" ]]; then cp -f "$backup" "$target"; else rm -f "$target"; fi
    die "sshd rejected the new configuration — previous configuration restored."
  fi
  rm -f "$backup" /tmp/homecore-sshd.err
}

harden_kernel() {
  install -m 0644 "$SYS/sysctl/99-homecore.conf" /etc/sysctl.d/99-homecore.conf
  # Some keys do not exist on every kernel (e.g. Pi vs VM); apply what is supported.
  sysctl -q -e -p /etc/sysctl.d/99-homecore.conf >/dev/null 2>&1 || true
  ok "Kernel/network sysctl hardening applied."
}

harden_journald() {
  install -d -m 0755 /etc/systemd/journald.conf.d /var/log/journal
  install -m 0644 "$SYS/journald/homecore.conf" /etc/systemd/journald.conf.d/homecore.conf
  systemctl restart systemd-journald
  ok "Journald limited to 64 MB."
}

harden_updates() {
  install -m 0644 "$SYS/apt/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
  install -m 0644 "$SYS/apt/52homecore-unattended" /etc/apt/apt.conf.d/52homecore-unattended
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "Automatic security updates enabled."
}

case "${1:-all}" in
  ssh) harden_ssh ;;
  kernel) harden_kernel ;;
  journald) harden_journald ;;
  updates) harden_updates ;;
  all) harden_kernel; harden_journald; harden_updates; harden_ssh ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
