#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
require_root
: "${MANAGED_USER:?}" "${NEW_SSH_PORT:?}"
: "${ALLOW_TCP_FORWARDING:=no}" "${ALLOW_AGENT_FORWARDING:=no}" "${X11_FORWARDING:=no}"
: "${LOGIN_GRACE_TIME:=45}" "${MAX_AUTH_TRIES:=5}" "${MAX_SESSIONS:=5}"
: "${CLIENT_ALIVE_INTERVAL:=300}" "${CLIENT_ALIVE_COUNT_MAX:=3}" "${FIREWALL_SSH_RATE_LIMIT:=yes}"
: "${SUDO_FINAL_MODE:=nopasswd-all}"
: "${SSH_SOCKET_MODE:=no}"

for option in ALLOW_TCP_FORWARDING ALLOW_AGENT_FORWARDING X11_FORWARDING; do
  [[ "${!option}" == yes || "${!option}" == no ]] \
    || fail SSH_FORWARDING_POLICY_INVALID "${option} 必须为 yes 或 no"
done

[[ "$LOGIN_GRACE_TIME" =~ ^[0-9]+$ ]] && (( LOGIN_GRACE_TIME >= 30 && LOGIN_GRACE_TIME <= 300 )) \
  || fail SSH_POLICY_INVALID "LoginGraceTime 无效"
[[ "$MAX_AUTH_TRIES" =~ ^[0-9]+$ ]] && (( MAX_AUTH_TRIES >= 3 && MAX_AUTH_TRIES <= 10 )) \
  || fail SSH_POLICY_INVALID "MaxAuthTries 无效"
[[ "$MAX_SESSIONS" =~ ^[0-9]+$ ]] && (( MAX_SESSIONS >= 1 && MAX_SESSIONS <= 20 )) \
  || fail SSH_POLICY_INVALID "MaxSessions 无效"
[[ "$CLIENT_ALIVE_INTERVAL" =~ ^[0-9]+$ ]] && (( CLIENT_ALIVE_INTERVAL == 0 || (CLIENT_ALIVE_INTERVAL >= 60 && CLIENT_ALIVE_INTERVAL <= 3600) )) \
  || fail SSH_POLICY_INVALID "ClientAliveInterval 无效"
[[ "$CLIENT_ALIVE_COUNT_MAX" =~ ^[0-9]+$ ]] && (( CLIENT_ALIVE_COUNT_MAX >= 1 && CLIENT_ALIVE_COUNT_MAX <= 10 )) \
  || fail SSH_POLICY_INVALID "ClientAliveCountMax 无效"
[[ "$FIREWALL_SSH_RATE_LIMIT" == yes || "$FIREWALL_SSH_RATE_LIMIT" == no ]] \
  || fail FIREWALL_POLICY_INVALID "FIREWALL_SSH_RATE_LIMIT 必须为 yes 或 no"
[[ "$SUDO_FINAL_MODE" == nopasswd-all || "$SUDO_FINAL_MODE" == command-allowlist ]] \
  || fail SUDO_POLICY_INVALID "SUDO_FINAL_MODE 无效"

config=/etc/ssh/sshd_config.d/00-vps-secure-init.conf
backup="${config}.pre-finalize"
legacy_config=/etc/ssh/sshd_config.d/99-vps-secure-init.conf
legacy_backup="${legacy_config}.pre-finalize"
socket_dropin=/etc/systemd/system/ssh.socket.d/00-vps-secure-init.conf
socket_backup="${socket_dropin}.pre-finalize"
legacy_present=no
if [[ -e "$config" ]]; then
  cp -a "$config" "$backup"
elif [[ -e "$legacy_config" ]]; then
  # Migrate the project-owned drop-in left by older releases when resuming
  # after a failed finalize.  The early filename is required because sshd
  # uses the first value found for most directives.
  cp -a "$legacy_config" "$legacy_backup"
  cp -a "$legacy_config" "$backup"
  legacy_present=yes
else
  fail SSH_CONFIG_MISSING "缺少过渡期 SSH 配置"
fi
if [[ -e "$legacy_config" ]]; then
  [[ "$legacy_present" == yes ]] || { cp -a "$legacy_config" "$legacy_backup"; legacy_present=yes; }
  rm -f "$legacy_config"
fi

cat > "$config" <<EOF2
# VPS Secure Init: final SSH policy; managed by vps-secure-init.
Port ${NEW_SSH_PORT}
AllowUsers ${MANAGED_USER}
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
LoginGraceTime ${LOGIN_GRACE_TIME}
MaxAuthTries ${MAX_AUTH_TRIES}
MaxSessions ${MAX_SESSIONS}
ClientAliveInterval ${CLIENT_ALIVE_INTERVAL}
ClientAliveCountMax ${CLIENT_ALIVE_COUNT_MAX}
AllowTcpForwarding ${ALLOW_TCP_FORWARDING}
AllowAgentForwarding ${ALLOW_AGENT_FORWARDING}
X11Forwarding ${X11_FORWARDING}
EOF2
if [[ "$SSH_SOCKET_MODE" == yes ]]; then
  [[ -e "$socket_dropin" ]] && cp -a "$socket_dropin" "$socket_backup"
  install -d -m 755 /etc/systemd/system/ssh.socket.d
  cat > "$socket_dropin" <<EOF_SOCKET
# VPS Secure Init: final listener for managed SSH only.
[Socket]
ListenStream=
ListenStream=0.0.0.0:${NEW_SSH_PORT}
ListenStream=[::]:${NEW_SSH_PORT}
FreeBind=true
EOF_SOCKET
fi

restore_transition_firewall() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw delete limit "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow 22/tcp >/dev/null 2>&1 || true
}

rollback() {
  cp -a "$backup" "$config"
  if [[ "$legacy_present" == yes && -e "$legacy_backup" ]]; then cp -a "$legacy_backup" "$legacy_config"; fi
  if [[ "$SSH_SOCKET_MODE" == yes ]]; then
    if [[ -e "$socket_backup" ]]; then cp -a "$socket_backup" "$socket_dropin"; else rm -f "$socket_dropin"; fi
    systemctl daemon-reload || true
  fi
  /usr/sbin/sshd -t >/dev/null 2>&1 && (systemctl is-active --quiet ssh.socket 2>/dev/null && { systemctl restart ssh.socket; systemctl restart ssh; } || systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true)
  restore_transition_firewall
}
trap rollback ERR

/usr/sbin/sshd -t || fail SSH_CONFIG_INVALID "最终 SSH 配置检查失败"
effective="$(/usr/sbin/sshd -T -C user="$MANAGED_USER",host=localhost,addr=127.0.0.1)"
grep -qx "port ${NEW_SSH_PORT}" <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "最终有效配置缺少新 SSH 端口"
! grep -qx 'port 22' <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "最终有效配置仍包含 22 端口"
grep -qx 'permitrootlogin no' <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "最终配置未禁止 root SSH"
grep -qx 'passwordauthentication no' <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "最终配置未禁止密码 SSH"
grep -qx "logingracetime ${LOGIN_GRACE_TIME}" <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "LoginGraceTime 不匹配"
grep -qx "maxauthtries ${MAX_AUTH_TRIES}" <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "MaxAuthTries 不匹配"
grep -qx "maxsessions ${MAX_SESSIONS}" <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "MaxSessions 不匹配"
grep -qx "clientaliveinterval ${CLIENT_ALIVE_INTERVAL}" <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "ClientAliveInterval 不匹配"
grep -qx "clientalivecountmax ${CLIENT_ALIVE_COUNT_MAX}" <<<"$effective" || fail SSH_EFFECTIVE_CONFIG "ClientAliveCountMax 不匹配"
grep -qx "allowtcpforwarding ${ALLOW_TCP_FORWARDING}" <<<"$effective" \
  || fail SSH_EFFECTIVE_CONFIG "最终配置的 TCP 转发策略不匹配"
grep -qx "allowagentforwarding ${ALLOW_AGENT_FORWARDING}" <<<"$effective" \
  || fail SSH_EFFECTIVE_CONFIG "最终配置的 Agent 转发策略不匹配"
grep -qx "x11forwarding ${X11_FORWARDING}" <<<"$effective" \
  || fail SSH_EFFECTIVE_CONFIG "最终配置的 X11 转发策略不匹配"

if systemctl is-active --quiet ssh.socket 2>/dev/null; then
  systemctl daemon-reload
  systemctl restart ssh.socket
  systemctl restart ssh
else
  systemctl reload ssh 2>/dev/null || systemctl reload sshd
fi
sleep 1
ss -lnt | awk '{print $4}' | grep -Eq "(^|:|\\])${NEW_SSH_PORT}$" || fail SSH_LISTENER_MISSING "最终新 SSH 端口未监听，已触发回滚"
if ss -lnt | awk '{print $4}' | grep -Eq '(^|:|\])22$'; then
  fail SSH_OLD_LISTENER_PRESENT "22 端口仍在监听，已触发回滚"
fi

# Final firewall policy: fail2ban is already active at this point. Convert the
# managed SSH port from transition ALLOW to LIMIT, then remove the old rescue
# port. If anything fails, the ERR trap restores the transition rules and SSH
# configuration so the machine remains reachable.
ufw delete limit "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
ufw delete allow "${NEW_SSH_PORT}/tcp" >/dev/null 2>&1 || true
if [[ "$FIREWALL_SSH_RATE_LIMIT" == yes ]]; then
  ufw limit "${NEW_SSH_PORT}/tcp" comment 'VPS Secure Init: rate-limit managed SSH access'
  expected_action=LIMIT
else
  ufw allow "${NEW_SSH_PORT}/tcp" comment 'VPS Secure Init: managed SSH access'
  expected_action=ALLOW
fi

ufw delete limit 22/tcp >/dev/null 2>&1 || true
ufw delete allow 22/tcp >/dev/null 2>&1 || true

ufw status | awk -v p="${NEW_SSH_PORT}/tcp" -v action="$expected_action" '$1 == p && $2 == action {ok=1} END {exit ok ? 0 : 1}' \
  || fail UFW_FINAL_RULE_MISSING "UFW 最终 SSH 规则与计划不匹配"
if ufw status | awk '$1 == "22/tcp" {found=1} END {exit found ? 0 : 1}'; then
  fail UFW_OLD_RULE_PRESENT "UFW 最终规则仍包含 22/tcp"
fi

# The bootstrap sudoers entry is intentionally broad so recovery can remain
# non-interactive.  Once every privileged mutation and its verification have
# succeeded, command-allowlist mode replaces it with only the read-only tools
# used by the final audit.  This is applied last so a failed finalize retains
# the original recovery contract.
if [[ "$SUDO_FINAL_MODE" == command-allowlist ]]; then
  sudoers_tmp=/etc/sudoers.d/.90-vps-secure-init-managed.tmp
  cat > "$sudoers_tmp" <<'EOF_SUDO'
# VPS Secure Init: final read-only audit command allowlist.
Cmnd_Alias VPS_INIT_AUDIT = /usr/bin/true, /bin/true, /usr/sbin/sshd -t, /usr/sbin/sshd -T -C *, /usr/sbin/ufw status, /usr/sbin/ufw status *, /usr/bin/ufw status, /usr/bin/ufw status *, /usr/bin/systemctl is-active --quiet fail2ban, /usr/bin/systemctl is-enabled --quiet fail2ban, /usr/bin/fail2ban-client status sshd, /usr/sbin/fail2ban-client status sshd, /usr/bin/awk *, /usr/bin/stat *, /usr/bin/passwd -S *
__VPS_INIT_USER__ ALL=(ALL:ALL) NOPASSWD: VPS_INIT_AUDIT
EOF_SUDO
  sed -i "s/__VPS_INIT_USER__/${MANAGED_USER}/" "$sudoers_tmp"
  chmod 440 "$sudoers_tmp"
  visudo -cf "$sudoers_tmp" >/dev/null || fail SUDOERS_INVALID "命令白名单 sudoers 检查失败"
  install -m 440 "$sudoers_tmp" /etc/sudoers.d/90-vps-secure-init-managed
  rm -f "$sudoers_tmp"
fi

trap - ERR
rm -f "$backup"
rm -f "$legacy_backup"
rm -f "$socket_backup"
emit finalize ok
