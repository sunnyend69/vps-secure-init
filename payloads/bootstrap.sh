#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
require_root
: "${MANAGED_USER:?}" "${MANAGED_PASSWORD:?}" "${PUBLIC_KEY:?}"

# Minimal Debian installations may not ship sudo.  The initial connection is
# root, so install it before creating the managed account and sudoers entry.
if ! command -v sudo >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 || fail SUDO_MISSING "系统没有 sudo 且缺少 apt-get，无法建立恢复权限"
  apt-get update -qq || fail SUDO_INSTALL_FAILED "sudo 软件源更新失败"
  DEBIAN_FRONTEND=noninteractive apt-get install -y sudo || fail SUDO_INSTALL_FAILED "sudo 安装失败"
fi

# Keep the login name within the conservative shadow-utils limit used by
# Ubuntu 22.04 and reject characters outside this project's portable subset.
if (( ${#MANAGED_USER} > 32 )) || [[ ! "$MANAGED_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  fail MANAGED_USER_INVALID "受管用户名不符合 Linux useradd 规则（仅小写字母/数字/_/-，最长 32 字符）"
fi
if ! id "$MANAGED_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$MANAGED_USER"
fi
printf '%s:%s\n' "$MANAGED_USER" "$MANAGED_PASSWORD" | chpasswd
usermod -aG sudo "$MANAGED_USER" 2>/dev/null || usermod -aG wheel "$MANAGED_USER" 2>/dev/null || true
install -d -m 700 -o "$MANAGED_USER" -g "$MANAGED_USER" "/home/$MANAGED_USER/.ssh"
printf '%s\n' "$PUBLIC_KEY" > "/home/$MANAGED_USER/.ssh/authorized_keys"
chown "$MANAGED_USER:$MANAGED_USER" "/home/$MANAGED_USER/.ssh/authorized_keys"
chmod 600 "/home/$MANAGED_USER/.ssh/authorized_keys"

# Subsequent security steps run through the newly verified managed SSH account.
# Restrict this file to root and use sudo -n so automation can never hang on a
# remote password prompt. The account is switched to key-only SSH in finalize.
install -d -m 755 /etc/sudoers.d
printf '# VPS Secure Init: temporary recovery sudo policy; finalize narrows this allowlist.\n%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$MANAGED_USER" > /etc/sudoers.d/90-vps-secure-init-managed
chmod 440 /etc/sudoers.d/90-vps-secure-init-managed
if command -v visudo >/dev/null 2>&1; then
  visudo -cf /etc/sudoers.d/90-vps-secure-init-managed >/dev/null || fail SUDOERS_INVALID "受管用户 sudoers 配置检查失败"
fi

emit bootstrap ok
