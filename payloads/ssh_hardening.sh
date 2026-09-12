#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
require_root
: "${MANAGED_USER:?}" "${NEW_SSH_PORT:?}"
: "${SSH_SOCKET_MODE:=no}"

[[ "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] || fail SSH_PORT_INVALID "SSH 端口不是数字"
(( NEW_SSH_PORT >= 1024 && NEW_SSH_PORT <= 65535 )) || fail SSH_PORT_INVALID "SSH 端口超出允许范围"
id "$MANAGED_USER" >/dev/null 2>&1 || fail MANAGED_USER_MISSING "受管用户不存在"

install -d -m 755 /etc/ssh/sshd_config.d
config=/etc/ssh/sshd_config.d/00-vps-secure-init.conf
backup="${config}.pre-transition"
socket_dropin=/etc/systemd/system/ssh.socket.d/00-vps-secure-init.conf
socket_backup="${socket_dropin}.pre-transition"
[[ -e "$config" ]] && cp -a "$config" "$backup" || rm -f "$backup"

# Transition mode deliberately preserves the provider's root:22 rescue path.
# Only add the managed port here. Root/password hardening happens in finalize,
# after the new user/key/port has been independently verified.
cat > "$config" <<EOF
# VPS Secure Init: temporary dual-port SSH policy; finalize replaces this file.
Port 22
Port ${NEW_SSH_PORT}
PubkeyAuthentication yes
PermitEmptyPasswords no
LoginGraceTime 20
MaxAuthTries 6
MaxSessions 4
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
if [[ "$SSH_SOCKET_MODE" == yes ]]; then
  install -d -m 755 /etc/systemd/system/ssh.socket.d
  [[ -e "$socket_dropin" ]] && cp -a "$socket_dropin" "$socket_backup" || rm -f "$socket_backup"
  cat > "$socket_dropin" <<EOF_SOCKET
# VPS Secure Init: transition listeners for rescue and managed SSH.
[Socket]
ListenStream=
ListenStream=0.0.0.0:22
ListenStream=[::]:22
ListenStream=0.0.0.0:${NEW_SSH_PORT}
ListenStream=[::]:${NEW_SSH_PORT}
FreeBind=true
EOF_SOCKET
fi

rollback() {
  if [[ -e "$backup" ]]; then cp -a "$backup" "$config"; else rm -f "$config"; fi
  if [[ "$SSH_SOCKET_MODE" == yes ]]; then
    if [[ -e "$socket_backup" ]]; then cp -a "$socket_backup" "$socket_dropin"; else rm -f "$socket_dropin"; fi
    systemctl daemon-reload || true
  fi
  /usr/sbin/sshd -t >/dev/null 2>&1 && (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true)
}
trap rollback ERR

reload_ssh() {
  if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    systemctl daemon-reload
    systemctl restart ssh.socket
    systemctl restart ssh
  else
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
  fi
}

/usr/sbin/sshd -t || fail SSH_CONFIG_INVALID "双端口 SSH 配置检查失败"
effective="$(/usr/sbin/sshd -T)"
grep -qx 'port 22' <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "sshd 有效配置缺少 22 端口"
grep -qx "port ${NEW_SSH_PORT}" <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "sshd 有效配置缺少新端口 ${NEW_SSH_PORT}"

reload_ssh
sleep 1
ss -lnt | awk '{print $4}' | grep -Eq '(^|:|\])22$' || fail SSH_LISTENER_MISSING "22 端口未监听，已触发回滚"
ss -lnt | awk '{print $4}' | grep -Eq "(^|:|\\])${NEW_SSH_PORT}$" || fail SSH_LISTENER_MISSING "新 SSH 端口 ${NEW_SSH_PORT} 未监听，已触发回滚"

trap - ERR
rm -f "$backup"
[[ "$SSH_SOCKET_MODE" == yes ]] && rm -f "$socket_backup"
emit ssh_hardening ok
