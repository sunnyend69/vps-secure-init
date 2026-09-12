"""Ubuntu/Debian preflight capability parsing and policy matching."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping


class CapabilityError(RuntimeError):
    """The remote host cannot safely run the Linux payload contract."""


_REQUIRED_FIELDS = {
    "OS_ID",
    "OS_VERSION",
    "PLATFORM",
    "APT_GET",
    "SYSTEMD",
    "SSHD_BIN",
    "SSH_SERVICE",
    "SSH_DROPIN",
    "SUDO",
    "UFW",
    "IPV6",
    "FAIL2BAN",
    "JOURNAL",
    "AUTH_LOG",
}
_YES_NO_FIELDS = {"APT_GET", "SYSTEMD", "SSH_DROPIN", "SUDO", "UFW", "IPV6", "FAIL2BAN", "JOURNAL", "AUTH_LOG"}
_PLATFORM_RE = re.compile(r"^(ubuntu)-(22\.04|24\.04|26\.04)$|^(debian)-(12|13)$")


@dataclass(frozen=True)
class LinuxCapabilitySnapshot:
    os_id: str
    os_version: str
    platform: str
    apt_get: bool
    systemd: bool
    sshd_bin: str
    ssh_service: str
    ssh_dropin: bool
    sudo: bool
    ufw_installed: bool
    ipv6_available: bool
    fail2ban_installed: bool
    journal_available: bool
    auth_log_available: bool
    ssh_socket_active: bool = False
    ssh_socket_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fields_from_output(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip().rstrip("\r")
        if not line.startswith("VPS_INIT_CAP_") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        fields[name.removeprefix("VPS_INIT_CAP_")] = value.strip()
    return fields


def _yes_no(fields: Mapping[str, str], name: str) -> bool:
    value = fields[name]
    if value not in {"yes", "no"}:
        raise CapabilityError(f"预检能力字段 {name} 必须为 yes 或 no，实际为 {value!r}")
    return value == "yes"


def parse_linux_capabilities(output: str) -> LinuxCapabilitySnapshot:
    """Parse the versioned preflight protocol without trusting display text."""
    fields = _fields_from_output(output)
    missing = sorted(_REQUIRED_FIELDS - set(fields))
    if missing:
        raise CapabilityError(f"预检未返回必要能力字段: {', '.join(missing)}")
    for name in _YES_NO_FIELDS:
        _yes_no(fields, name)
    platform = fields["PLATFORM"]
    if not _PLATFORM_RE.fullmatch(platform):
        raise CapabilityError(f"不支持或格式错误的平台标识: {platform}")
    os_id, _, os_version = platform.partition("-")
    if fields["OS_ID"] != os_id or fields["OS_VERSION"] != os_version:
        raise CapabilityError("预检平台标识与 OS ID/VERSION_ID 不一致")
    if not fields["SSHD_BIN"].startswith("/"):
        raise CapabilityError("预检返回的 sshd 路径必须是绝对路径")
    if fields["SSH_SERVICE"] not in {"ssh", "sshd"}:
        raise CapabilityError("预检未识别可用的 ssh/sshd systemd 服务")
    return LinuxCapabilitySnapshot(
        os_id=os_id,
        os_version=os_version,
        platform=platform,
        apt_get=_yes_no(fields, "APT_GET"),
        systemd=_yes_no(fields, "SYSTEMD"),
        sshd_bin=fields["SSHD_BIN"],
        ssh_service=fields["SSH_SERVICE"],
        ssh_dropin=_yes_no(fields, "SSH_DROPIN"),
        sudo=_yes_no(fields, "SUDO"),
        ufw_installed=_yes_no(fields, "UFW"),
        ipv6_available=_yes_no(fields, "IPV6"),
        fail2ban_installed=_yes_no(fields, "FAIL2BAN"),
        journal_available=_yes_no(fields, "JOURNAL"),
        auth_log_available=_yes_no(fields, "AUTH_LOG"),
        ssh_socket_active=_yes_no(fields, "SSH_SOCKET_ACTIVE") if "SSH_SOCKET_ACTIVE" in fields else False,
        ssh_socket_enabled=_yes_no(fields, "SSH_SOCKET_ENABLED") if "SSH_SOCKET_ENABLED" in fields else False,
    )


def validate_linux_capabilities(
    snapshot: LinuxCapabilitySnapshot,
    policy: Mapping[str, Any],
    requested_platform: str = "auto",
    *,
    allow_bootstrap_sudo: bool = False,
) -> None:
    """Enforce the local contract before any state-changing payload runs."""
    supported = policy.get("platforms", {}).get("supported", [])
    if snapshot.platform not in supported:
        raise CapabilityError(f"策略未启用平台 {snapshot.platform}")
    if requested_platform not in {"auto", snapshot.os_id}:
        raise CapabilityError(f"主机要求的平台是 {requested_platform}，实际探测到 {snapshot.os_id}")
    missing: list[str] = []
    if not snapshot.apt_get:
        missing.append("apt-get")
    if not snapshot.systemd:
        missing.append("systemd")
    if not snapshot.ssh_dropin:
        missing.append("OpenSSH drop-in Include")
    if not snapshot.sudo and not (allow_bootstrap_sudo and snapshot.apt_get):
        missing.append("sudo")
    if not (snapshot.journal_available or snapshot.auth_log_available):
        missing.append("journalctl 或 SSH 认证日志")
    if missing:
        raise CapabilityError(f"平台缺少项目所需能力: {', '.join(missing)}")
