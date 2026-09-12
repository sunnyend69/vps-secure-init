#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
require_root
[[ -r /etc/os-release ]] || fail OS_UNKNOWN "无法识别系统"
source /etc/os-release
case "${ID}:${VERSION_ID}" in ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;; *) fail UNSUPPORTED_OS "不支持 ${ID}:${VERSION_ID}" ;; esac
command -v systemctl >/dev/null || fail NO_SYSTEMD "需要 systemd"
sshd_bin="$(command -v sshd || true)"
[[ -n "$sshd_bin" ]] || fail NO_SSHD "未找到 sshd"

ssh_service=""
for candidate in ssh sshd; do
  if [[ "$(systemctl show -p LoadState --value "${candidate}.service" 2>/dev/null || true)" == loaded ]]; then
    ssh_service="$candidate"
    break
  fi
done
[[ -n "$ssh_service" ]] || fail NO_SSH_SERVICE "未识别 ssh 或 sshd systemd 服务"
ssh_socket_active=no; systemctl is-active --quiet ssh.socket 2>/dev/null && ssh_socket_active=yes
ssh_socket_enabled=no; systemctl is-enabled --quiet ssh.socket 2>/dev/null && ssh_socket_enabled=yes

sshd_config=/etc/ssh/sshd_config
[[ -r "$sshd_config" ]] || fail NO_SSHD_CONFIG "未找到 sshd_config"
if grep -Eq '^[[:space:]]*[Ii]nclude[[:space:]].*sshd_config\.d' "$sshd_config"; then
  ssh_dropin=yes
else
  ssh_dropin=no
fi

apt_get=no; command -v apt-get >/dev/null && apt_get=yes
sudo_present=no; command -v sudo >/dev/null && sudo_present=yes
ufw_present=no; command -v ufw >/dev/null && ufw_present=yes
fail2ban_present=no; command -v fail2ban-client >/dev/null && fail2ban_present=yes
journal_present=no; command -v journalctl >/dev/null && journal_present=yes
auth_log_present=no; [[ -r /var/log/auth.log || -r /var/log/secure ]] && auth_log_present=yes
ipv6_present=no; [[ -s /proc/net/if_inet6 ]] && ipv6_present=yes

printf 'VPS_INIT_OS=%s-%s\n' "$ID" "$VERSION_ID"
printf 'VPS_INIT_CAP_OS_ID=%s\n' "$ID"
printf 'VPS_INIT_CAP_OS_VERSION=%s\n' "$VERSION_ID"
printf 'VPS_INIT_CAP_PLATFORM=%s-%s\n' "$ID" "$VERSION_ID"
printf 'VPS_INIT_CAP_APT_GET=%s\n' "$apt_get"
printf 'VPS_INIT_CAP_SYSTEMD=yes\n'
printf 'VPS_INIT_CAP_SSHD_BIN=%s\n' "$sshd_bin"
printf 'VPS_INIT_CAP_SSH_SERVICE=%s\n' "$ssh_service"
printf 'VPS_INIT_CAP_SSH_SOCKET_ACTIVE=%s\n' "$ssh_socket_active"
printf 'VPS_INIT_CAP_SSH_SOCKET_ENABLED=%s\n' "$ssh_socket_enabled"
printf 'VPS_INIT_CAP_SSH_DROPIN=%s\n' "$ssh_dropin"
printf 'VPS_INIT_CAP_SUDO=%s\n' "$sudo_present"
printf 'VPS_INIT_CAP_UFW=%s\n' "$ufw_present"
printf 'VPS_INIT_CAP_IPV6=%s\n' "$ipv6_present"
printf 'VPS_INIT_CAP_FAIL2BAN=%s\n' "$fail2ban_present"
printf 'VPS_INIT_CAP_JOURNAL=%s\n' "$journal_present"
printf 'VPS_INIT_CAP_AUTH_LOG=%s\n' "$auth_log_present"
emit preflight ok
