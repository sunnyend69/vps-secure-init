#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
require_root
: "${NEW_SSH_PORT:?}"
: "${FAIL2BAN_BANTIME:=1h}" "${FAIL2BAN_FINDTIME:=10m}" "${FAIL2BAN_MAXRETRY:=5}" "${FAIL2BAN_BACKEND:=auto}" "${FAIL2BAN_SSH_SERVICE:=ssh}"
[[ "$FAIL2BAN_BANTIME" =~ ^[1-9][0-9]*[smhdw]$ ]] || fail FAIL2BAN_POLICY_INVALID "bantime 无效"
[[ "$FAIL2BAN_FINDTIME" =~ ^[1-9][0-9]*[smhdw]$ ]] || fail FAIL2BAN_POLICY_INVALID "findtime 无效"
[[ "$FAIL2BAN_MAXRETRY" =~ ^[0-9]+$ ]] && (( FAIL2BAN_MAXRETRY >= 1 && FAIL2BAN_MAXRETRY <= 20 )) \
  || fail FAIL2BAN_POLICY_INVALID "maxretry 无效"
[[ "$FAIL2BAN_BACKEND" == auto || "$FAIL2BAN_BACKEND" == systemd || "$FAIL2BAN_BACKEND" == polling ]] \
  || fail FAIL2BAN_POLICY_INVALID "backend 无效"
effective_backend="$FAIL2BAN_BACKEND"
if [[ "$effective_backend" == auto ]]; then
  if command -v journalctl >/dev/null 2>&1; then
    effective_backend=systemd
  else
    effective_backend=polling
  fi
fi
if [[ "$effective_backend" == polling ]] && [[ ! -r /var/log/auth.log && ! -r /var/log/secure ]]; then
  fail FAIL2BAN_LOG_SOURCE_MISSING "polling backend 找不到 SSH 认证日志"
fi
if ! command -v fail2ban-client >/dev/null; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
fi
install -d -m 755 /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/99-vps-secure-init.local <<EOF
# VPS Secure Init: managed SSH brute-force protection.
[sshd]
enabled = true
port = ${NEW_SSH_PORT}
bantime = ${FAIL2BAN_BANTIME}
findtime = ${FAIL2BAN_FINDTIME}
maxretry = ${FAIL2BAN_MAXRETRY}
backend = ${effective_backend}
EOF
if [[ "$effective_backend" == systemd ]]; then
  printf 'journalmatch = _SYSTEMD_UNIT=%s.service\n' "$FAIL2BAN_SSH_SERVICE" >> /etc/fail2ban/jail.d/99-vps-secure-init.local
else
  printf 'logpath = /var/log/auth.log\n' >> /etc/fail2ban/jail.d/99-vps-secure-init.local
fi
if [[ -n "${FAIL2BAN_IGNOREIP:-}" ]]; then
  printf 'ignoreip = %s\n' "$FAIL2BAN_IGNOREIP" >> /etc/fail2ban/jail.d/99-vps-secure-init.local
fi
fail2ban-client -t >/dev/null || fail FAIL2BAN_CONFIG_INVALID "Fail2ban 配置检查失败"
systemctl enable --now fail2ban
systemctl restart fail2ban
sleep 1
fail2ban-client status sshd >/dev/null || fail FAIL2BAN_JAIL_MISSING "sshd jail 未正常启动"
emit fail2ban ok
