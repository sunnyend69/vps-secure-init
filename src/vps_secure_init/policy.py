"""Versioned Linux policy schema, parameter registry, and profile resolution.

This module intentionally performs no remote work.  It provides one local,
strict source of truth for values that later stages compile into a frozen plan.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import ipaddress
import re
from typing import Any, Mapping


POLICY_VERSION = 2
SUPPORTED_PLATFORMS = frozenset(
    {
        "ubuntu-22.04",
        "ubuntu-24.04",
        "ubuntu-26.04",
        "debian-12",
        "debian-13",
    }
)

_DURATION_RE = re.compile(r"^(?P<value>[1-9][0-9]*)(?P<unit>[smhdw])$")
_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
# Uppercase remains accepted for 0.1.x inventory compatibility; new interactive
# entries will recommend lowercase IDs for portable filenames and labels.
_HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$")
_LINUX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class PolicyError(ValueError):
    """Raised before any VPS connection when policy input is invalid."""


@dataclass(frozen=True)
class ParameterSpec:
    """Metadata used by future YAML, CLI, planning, and report layers."""

    id: str
    type: str
    domain: str
    default: Any
    recommended: Any
    ui: str
    customizable: bool = True
    risk: str = "low"
    applies_to: tuple[str, ...] = ("ubuntu", "debian")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _spec(
    parameter_id: str,
    value_type: str,
    domain: str,
    default: Any,
    recommended: Any,
    ui: str,
    *,
    customizable: bool = True,
    risk: str = "low",
) -> ParameterSpec:
    return ParameterSpec(
        parameter_id,
        value_type,
        domain,
        default,
        recommended,
        ui,
        customizable,
        risk,
    )


# Keep this registry deliberately data-only: later interactive and report
# modules must consume it instead of duplicating default values.
PARAMETER_REGISTRY: dict[str, ParameterSpec] = {
    "host.id": _spec("host.id", "string", "[A-Za-z0-9][A-Za-z0-9_-]{0,47}", None, None, "text", risk="medium"),
    "host.address": _spec("host.address", "host-or-ip", "valid IPv4, IPv6, or DNS name", None, None, "text", risk="high"),
    "host.platform": _spec("host.platform", "enum", "auto|ubuntu|debian", "auto", "auto", "single-select"),
    "host.initial_port": _spec("host.initial_port", "integer", "1..65535", 22, 22, "number", risk="high"),
    "host.initial_auth": _spec("host.initial_auth", "enum", "key|password", "key", "key", "single-select", risk="high"),
    "host.profile": _spec("host.profile", "enum", "defined profile name", "standard", "standard", "single-select"),
    "credentials.username_length": _spec("credentials.username_length", "integer", "3..32", 18, 18, "number"),
    "credentials.password_length": _spec("credentials.password_length", "integer", "32..256", 100, 100, "number"),
    "credentials.passphrase_length": _spec("credentials.passphrase_length", "integer", "32..256", 100, 100, "number"),
    "credentials.key_type": _spec("credentials.key_type", "enum", "ed25519", "ed25519", "ed25519", "read-only", customizable=False),
    "credentials.key_kdf_rounds": _spec("credentials.key_kdf_rounds", "integer", "16..1000", 100, 100, "number", risk="medium"),
    "credentials.ssh_port_mode": _spec("credentials.ssh_port_mode", "enum", "random|manual", "random", "random", "single-select", risk="medium"),
    "credentials.ssh_port_range": _spec("credentials.ssh_port_range", "integer-pair", "1024..65535, low < high", [20000, 60000], [20000, 60000], "range"),
    "credentials.ssh_port": _spec("credentials.ssh_port", "integer", "1024..65535", None, None, "number", risk="high"),
    "ssh.login_grace_time": _spec("ssh.login_grace_time", "integer", "30..300 seconds", 45, 45, "number"),
    "ssh.max_auth_tries": _spec("ssh.max_auth_tries", "integer", "3..10", 5, 5, "number"),
    "ssh.max_sessions": _spec("ssh.max_sessions", "integer", "1..20", 5, 5, "number"),
    "ssh.client_alive_interval": _spec("ssh.client_alive_interval", "integer", "0 or 60..3600 seconds", 300, 300, "number"),
    "ssh.client_alive_count_max": _spec("ssh.client_alive_count_max", "integer", "1..10", 3, 3, "number"),
    "ssh.allow_tcp_forwarding": _spec("ssh.allow_tcp_forwarding", "boolean", "true|false", False, False, "single-select", risk="medium"),
    "ssh.allow_agent_forwarding": _spec("ssh.allow_agent_forwarding", "boolean", "true|false", False, False, "single-select", risk="high"),
    "ssh.x11_forwarding": _spec("ssh.x11_forwarding", "boolean", "true|false", False, False, "single-select", risk="medium"),
    "ssh.permit_root_login": _spec("ssh.permit_root_login", "constant", "false", False, False, "read-only", customizable=False, risk="critical"),
    "ssh.password_authentication": _spec("ssh.password_authentication", "constant", "false", False, False, "read-only", customizable=False, risk="critical"),
    "firewall.enabled": _spec("firewall.enabled", "constant", "true", True, True, "read-only", customizable=False, risk="critical"),
    "firewall.ssh_rate_limit": _spec("firewall.ssh_rate_limit", "boolean", "true|false", True, True, "single-select", risk="medium"),
    "firewall.ipv6_mode": _spec("firewall.ipv6_mode", "enum", "auto|enabled|disabled", "auto", "auto", "single-select", risk="high"),
    "firewall.allowed_services": _spec("firewall.allowed_services", "set", "http|https", [], [], "multi-select", risk="medium"),
    "firewall.allowed_ports": _spec("firewall.allowed_ports", "rule-list", "port/protocol/source/comment objects", [], [], "repeated-form", risk="high"),
    "fail2ban.enabled": _spec("fail2ban.enabled", "constant", "true", True, True, "read-only", customizable=False, risk="medium"),
    "fail2ban.bantime": _spec("fail2ban.bantime", "duration", "1m..30d", "1h", "1h", "duration"),
    "fail2ban.findtime": _spec("fail2ban.findtime", "duration", "1m..24h", "10m", "10m", "duration"),
    "fail2ban.maxretry": _spec("fail2ban.maxretry", "integer", "1..20", 5, 5, "number"),
    "fail2ban.backend": _spec("fail2ban.backend", "enum", "auto|systemd|polling", "auto", "auto", "single-select"),
    "fail2ban.ignoreip": _spec("fail2ban.ignoreip", "cidr-list", "IPv4/IPv6/CIDR", [], [], "repeated-text", risk="high"),
    "sudo.bootstrap_mode": _spec("sudo.bootstrap_mode", "constant", "nopasswd-all", "nopasswd-all", "nopasswd-all", "read-only", customizable=False, risk="critical"),
    "sudo.final_mode": _spec("sudo.final_mode", "enum", "nopasswd-all|command-allowlist", "nopasswd-all", "nopasswd-all", "single-select", risk="high"),
    "controller.connect_timeout": _spec("controller.connect_timeout", "integer", "5..60 seconds", 30, 30, "number"),
    "controller.step_timeout": _spec("controller.step_timeout", "integer", "60..1800 seconds", 300, 300, "number"),
    "controller.transport_retries": _spec("controller.transport_retries", "integer", "0..3", 1, 1, "number"),
    "controller.host_key_policy": _spec("controller.host_key_policy", "enum", "accept-new-then-pin|pinned", "accept-new-then-pin", "accept-new-then-pin", "single-select", risk="high"),
    "report.formats": _spec("report.formats", "set", "json|markdown", ["json", "markdown"], ["json", "markdown"], "multi-select"),
    "report.address_display": _spec("report.address_display", "enum", "full|masked", "masked", "masked", "single-select"),
    "report.include_raw_evidence": _spec("report.include_raw_evidence", "boolean", "true|false", False, False, "single-select", risk="medium"),
}


DEFAULT_POLICY: dict[str, Any] = {
    "policy_version": POLICY_VERSION,
    "onepassword_vault": "VPS",
    "platforms": {"supported": sorted(SUPPORTED_PLATFORMS)},
    "credentials": {
        "username_length": 18,
        "password_length": 100,
        "passphrase_length": 100,
        "key_type": "ed25519",
        "key_kdf_rounds": 100,
        "ssh_port_mode": "random",
        "ssh_port_range": [20000, 60000],
        "ssh_port": None,
    },
    "defaults": {"profile": "standard"},
    "profiles": {
        "standard": {
            "ssh": {
                "login_grace_time": 45,
                "max_auth_tries": 5,
                "max_sessions": 5,
                "client_alive_interval": 300,
                "client_alive_count_max": 3,
                "allow_tcp_forwarding": False,
                "allow_agent_forwarding": False,
                "x11_forwarding": False,
            },
            "firewall": {
                "enabled": True,
                "default_incoming": "deny",
                "default_outgoing": "allow",
                "ssh_rate_limit": True,
                "ipv6_mode": "auto",
                "allowed_services": [],
                "allowed_ports": [],
            },
            "fail2ban": {
                "enabled": True,
                "bantime": "1h",
                "findtime": "10m",
                "maxretry": 5,
                "backend": "auto",
                "ignoreip": [],
            },
            "sudo": {"bootstrap_mode": "nopasswd-all", "final_mode": "nopasswd-all"},
        },
        "web": {"extends": "standard", "firewall": {"allowed_services": ["http", "https"]}},
    },
    "controller": {
        "connect_timeout": 30,
        "step_timeout": 300,
        "transport_retries": 1,
        "host_key_policy": "accept-new-then-pin",
    },
    "report": {"formats": ["json", "markdown"], "address_display": "masked", "include_raw_evidence": False},
}


def default_policy() -> dict[str, Any]:
    """Return an independent copy of the current schema defaults."""
    return deepcopy(DEFAULT_POLICY)


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{path} 必须是对象")
    return dict(value)


def _unknown(mapping: Mapping[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise PolicyError(f"{path} 包含未知字段: {', '.join(unknown)}")


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{path} 必须是 true 或 false")
    return value


def _int(value: Any, path: str, low: int, high: int, *, zero_allowed: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{path} 必须是整数")
    if zero_allowed and value == 0:
        return value
    if not low <= value <= high:
        raise PolicyError(f"{path} 必须在 {low} 到 {high} 之间")
    return value


def _enum(value: Any, path: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise PolicyError(f"{path} 必须是以下值之一: {', '.join(sorted(allowed))}")
    return value


def _duration_seconds(value: Any, path: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, str):
        raise PolicyError(f"{path} 必须是如 10m 或 1h 的时长")
    match = _DURATION_RE.fullmatch(value)
    if not match:
        raise PolicyError(f"{path} 必须是正整数加 s/m/h/d/w 单位")
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match["unit"]]
    seconds = int(match["value"]) * multiplier
    if not minimum <= seconds <= maximum:
        raise PolicyError(f"{path} 必须在 {minimum} 到 {maximum} 秒之间")
    return seconds


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def _validate_string(value: Any, path: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{path} 必须是非空字符串")
    if pattern and not pattern.fullmatch(value):
        raise PolicyError(f"{path} 格式无效")
    return value


def _validate_port(value: Any, path: str) -> int:
    return _int(value, path, 1024, 65535)


def _validate_string_set(value: Any, path: str, allowed: set[str], *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PolicyError(f"{path} 必须是字符串列表")
    if nonempty and not value:
        raise PolicyError(f"{path} 不能为空")
    if len(value) != len(set(value)):
        raise PolicyError(f"{path} 不能包含重复项")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PolicyError(f"{path} 包含不支持的值: {', '.join(unknown)}")
    return list(value)


def _validate_cidrs(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PolicyError(f"{path} 必须是 IP/CIDR 字符串列表")
    if len(value) != len(set(value)):
        raise PolicyError(f"{path} 不能包含重复项")
    for item in value:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise PolicyError(f"{path} 包含无效 IP/CIDR: {item}") from exc
    return list(value)


def _validate_allowed_ports(value: Any, path: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise PolicyError(f"{path} 必须是规则列表")
    result: list[dict[str, Any]] = []
    fingerprints: set[tuple[str, str, str]] = set()
    for index, raw_rule in enumerate(value):
        rule_path = f"{path}[{index}]"
        rule = _mapping(raw_rule, rule_path)
        _unknown(rule, {"port", "protocol", "source", "comment"}, rule_path)
        if "port" not in rule:
            raise PolicyError(f"{rule_path}.port 为必填项")
        port = rule["port"]
        if isinstance(port, int) and not isinstance(port, bool):
            normalized_port = str(_int(port, f"{rule_path}.port", 1, 65535))
        elif isinstance(port, str) and re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", port):
            start, end = (int(part) for part in port.split(":"))
            if not 1 <= start <= end <= 65535:
                raise PolicyError(f"{rule_path}.port 范围无效")
            normalized_port = port
        else:
            raise PolicyError(f"{rule_path}.port 必须是端口号或 start:end 范围")
        protocol = _enum(rule.get("protocol", "tcp"), f"{rule_path}.protocol", {"tcp", "udp"})
        source = rule.get("source", "any")
        if source != "any":
            if not isinstance(source, str):
                raise PolicyError(f"{rule_path}.source 必须是 any、IP 或 CIDR")
            try:
                ipaddress.ip_network(source, strict=False)
            except ValueError as exc:
                raise PolicyError(f"{rule_path}.source 无效") from exc
        comment = rule.get("comment", "")
        if not isinstance(comment, str) or len(comment) > 64 or any(ord(char) < 32 for char in comment):
            raise PolicyError(f"{rule_path}.comment 必须是最多 64 字符的可打印文本")
        fingerprint = (normalized_port, protocol, source)
        if fingerprint in fingerprints:
            raise PolicyError(f"{path} 包含重复规则: {normalized_port}/{protocol} from {source}")
        fingerprints.add(fingerprint)
        result.append({"port": normalized_port, "protocol": protocol, "source": source, "comment": comment})
    return result


_CREDENTIAL_FIELDS = {
    "username_length", "password_length", "passphrase_length", "key_type",
    "key_kdf_rounds", "ssh_port_mode", "ssh_port_range", "ssh_port",
}


def _validate_credentials_settings(value: Any, path: str) -> dict[str, Any]:
    credentials = _mapping(value, path)
    _unknown(credentials, _CREDENTIAL_FIELDS, path)
    _int(credentials["username_length"], f"{path}.username_length", 3, 32)
    _int(credentials["password_length"], f"{path}.password_length", 32, 256)
    _int(credentials["passphrase_length"], f"{path}.passphrase_length", 32, 256)
    _enum(credentials["key_type"], f"{path}.key_type", {"ed25519"})
    _int(credentials["key_kdf_rounds"], f"{path}.key_kdf_rounds", 16, 1000)
    port_mode = _enum(credentials["ssh_port_mode"], f"{path}.ssh_port_mode", {"random", "manual"})
    port_range = credentials["ssh_port_range"]
    if not isinstance(port_range, list) or len(port_range) != 2:
        raise PolicyError(f"{path}.ssh_port_range 必须是两个端口组成的列表")
    low = _validate_port(port_range[0], f"{path}.ssh_port_range[0]")
    high = _validate_port(port_range[1], f"{path}.ssh_port_range[1]")
    if low >= high:
        raise PolicyError(f"{path}.ssh_port_range 必须满足 low < high")
    manual_port = credentials["ssh_port"]
    if port_mode == "manual":
        _validate_port(manual_port, f"{path}.ssh_port")
    elif manual_port is not None:
        _validate_port(manual_port, f"{path}.ssh_port")
    canonical = deepcopy(credentials)
    canonical["ssh_port_range"] = [low, high]
    return canonical


def _validate_profile_fragment(fragment: Mapping[str, Any], path: str, *, allow_extends: bool) -> None:
    allowed_sections = {"ssh", "firewall", "fail2ban", "sudo"}
    if allow_extends:
        allowed_sections.add("extends")
    _unknown(fragment, allowed_sections, path)
    if "extends" in fragment:
        _validate_string(fragment["extends"], f"{path}.extends", pattern=_PROFILE_RE)

    sections: dict[str, set[str]] = {
        "ssh": {
            "login_grace_time", "max_auth_tries", "max_sessions", "client_alive_interval",
            "client_alive_count_max", "allow_tcp_forwarding", "allow_agent_forwarding", "x11_forwarding",
        },
        "firewall": {
            "enabled", "default_incoming", "default_outgoing", "ssh_rate_limit", "ipv6_mode",
            "allowed_services", "allowed_ports",
        },
        "fail2ban": {"enabled", "bantime", "findtime", "maxretry", "backend", "ignoreip"},
        "sudo": {"bootstrap_mode", "final_mode"},
    }
    for section, allowed in sections.items():
        if section in fragment:
            values = _mapping(fragment[section], f"{path}.{section}")
            _unknown(values, allowed, f"{path}.{section}")


def _validate_resolved_profile(profile: Mapping[str, Any], path: str) -> None:
    _validate_profile_fragment(profile, path, allow_extends=False)
    for section in ("ssh", "firewall", "fail2ban", "sudo"):
        if section not in profile:
            raise PolicyError(f"{path}.{section} 缺失")

    ssh = _mapping(profile["ssh"], f"{path}.ssh")
    _int(ssh["login_grace_time"], f"{path}.ssh.login_grace_time", 30, 300)
    _int(ssh["max_auth_tries"], f"{path}.ssh.max_auth_tries", 3, 10)
    _int(ssh["max_sessions"], f"{path}.ssh.max_sessions", 1, 20)
    _int(ssh["client_alive_interval"], f"{path}.ssh.client_alive_interval", 60, 3600, zero_allowed=True)
    _int(ssh["client_alive_count_max"], f"{path}.ssh.client_alive_count_max", 1, 10)
    for name in ("allow_tcp_forwarding", "allow_agent_forwarding", "x11_forwarding"):
        _bool(ssh[name], f"{path}.ssh.{name}")

    firewall = _mapping(profile["firewall"], f"{path}.firewall")
    if _bool(firewall["enabled"], f"{path}.firewall.enabled") is not True:
        raise PolicyError(f"{path}.firewall.enabled 在 0.2.0 中必须为 true")
    if _enum(firewall["default_incoming"], f"{path}.firewall.default_incoming", {"deny"}) != "deny":
        raise PolicyError(f"{path}.firewall.default_incoming 必须为 deny")
    if _enum(firewall["default_outgoing"], f"{path}.firewall.default_outgoing", {"allow"}) != "allow":
        raise PolicyError(f"{path}.firewall.default_outgoing 必须为 allow")
    _bool(firewall["ssh_rate_limit"], f"{path}.firewall.ssh_rate_limit")
    _enum(firewall["ipv6_mode"], f"{path}.firewall.ipv6_mode", {"auto", "enabled", "disabled"})
    services = _validate_string_set(firewall["allowed_services"], f"{path}.firewall.allowed_services", {"http", "https"})
    ports = _validate_allowed_ports(firewall["allowed_ports"], f"{path}.firewall.allowed_ports")
    # Profile resolution returns a canonical rule representation for stable
    # planning, comparisons, and duplicate detection in later stages.
    if isinstance(profile, dict) and isinstance(profile.get("firewall"), dict):
        profile["firewall"]["allowed_services"] = services
        profile["firewall"]["allowed_ports"] = ports

    fail2ban = _mapping(profile["fail2ban"], f"{path}.fail2ban")
    if _bool(fail2ban["enabled"], f"{path}.fail2ban.enabled") is not True:
        raise PolicyError(f"{path}.fail2ban.enabled 在 0.2.0 中必须为 true")
    _duration_seconds(fail2ban["bantime"], f"{path}.fail2ban.bantime", 60, 30 * 86400)
    _duration_seconds(fail2ban["findtime"], f"{path}.fail2ban.findtime", 60, 86400)
    _int(fail2ban["maxretry"], f"{path}.fail2ban.maxretry", 1, 20)
    _enum(fail2ban["backend"], f"{path}.fail2ban.backend", {"auto", "systemd", "polling"})
    ignoreip = _validate_cidrs(fail2ban["ignoreip"], f"{path}.fail2ban.ignoreip")
    if isinstance(profile, dict) and isinstance(profile.get("fail2ban"), dict):
        profile["fail2ban"]["ignoreip"] = ignoreip

    sudo = _mapping(profile["sudo"], f"{path}.sudo")
    if _enum(sudo["bootstrap_mode"], f"{path}.sudo.bootstrap_mode", {"nopasswd-all"}) != "nopasswd-all":
        raise PolicyError(f"{path}.sudo.bootstrap_mode 必须为 nopasswd-all")
    _enum(sudo["final_mode"], f"{path}.sudo.final_mode", {"nopasswd-all", "command-allowlist"})


def _resolve_profile(profiles: Mapping[str, Any], name: str, stack: tuple[str, ...] = ()) -> dict[str, Any]:
    if name not in profiles:
        raise PolicyError(f"profiles 中不存在 {name}")
    if name in stack:
        raise PolicyError(f"profiles 存在循环继承: {' -> '.join((*stack, name))}")
    raw = _mapping(profiles[name], f"profiles.{name}")
    _validate_profile_fragment(raw, f"profiles.{name}", allow_extends=True)
    parent_name = raw.get("extends")
    current = {key: value for key, value in raw.items() if key != "extends"}
    parent = _resolve_profile(profiles, parent_name, (*stack, name)) if parent_name else {}
    return _deep_merge(parent, current)


def resolve_profile(policy: Mapping[str, Any], name: str, overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Resolve a named profile and optional host overrides into an exact policy."""
    profiles = _mapping(policy.get("profiles"), "profiles")
    resolved = _resolve_profile(profiles, name)
    if overrides is not None:
        override_mapping = _mapping(overrides, "host.overrides")
        _validate_profile_fragment(override_mapping, "host.overrides", allow_extends=False)
        resolved = _deep_merge(resolved, override_mapping)
    _validate_resolved_profile(resolved, f"resolved_profile.{name}")
    return resolved


def resolve_host_policy(
    policy: Mapping[str, Any], name: str, overrides: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Resolve credentials plus profile settings for one host without secrets."""
    raw_overrides = _mapping(overrides or {}, "host.overrides")
    _unknown(raw_overrides, {"credentials", "ssh", "firewall", "fail2ban", "sudo"}, "host.overrides")
    credential_override = _mapping(raw_overrides.get("credentials", {}), "host.overrides.credentials")
    _unknown(credential_override, _CREDENTIAL_FIELDS, "host.overrides.credentials")
    profile_overrides = {key: value for key, value in raw_overrides.items() if key != "credentials"}
    credentials = _validate_credentials_settings(
        _deep_merge(_mapping(policy["credentials"], "credentials"), credential_override),
        "resolved_credentials",
    )
    resolved = resolve_profile(policy, name, profile_overrides)
    return {"credentials": credentials, **resolved}


def _migrate_v1(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map the 0.1.x flat policy into v2 without writing the source file."""
    allowed = {
        "policy_version", "onepassword_vault", "supported_os", "username_length", "password_length",
        "passphrase_length", "ssh_port_range", "keep_old_port_until_verified", "permit_root_ssh",
        "password_authentication", "allow_tcp_forwarding", "allow_agent_forwarding", "x11_forwarding",
        "install_fail2ban", "fail2ban_bantime", "fail2ban_findtime", "fail2ban_maxretry",
    }
    _unknown(raw, allowed, "policy v1")
    result = default_policy()
    if "onepassword_vault" in raw:
        result["onepassword_vault"] = raw["onepassword_vault"]
    credentials = result["credentials"]
    for old, new in (
        ("username_length", "username_length"),
        ("password_length", "password_length"),
        ("passphrase_length", "passphrase_length"),
        ("ssh_port_range", "ssh_port_range"),
    ):
        if old in raw:
            credentials[new] = raw[old]
    if "supported_os" in raw:
        result["platforms"]["supported"] = raw["supported_os"]
    standard = result["profiles"]["standard"]
    ssh = standard["ssh"]
    for old, new in (
        ("allow_tcp_forwarding", "allow_tcp_forwarding"),
        ("allow_agent_forwarding", "allow_agent_forwarding"),
        ("x11_forwarding", "x11_forwarding"),
    ):
        if old in raw:
            ssh[new] = raw[old]
    fail2ban = standard["fail2ban"]
    for old, new in (("fail2ban_bantime", "bantime"), ("fail2ban_findtime", "findtime"), ("fail2ban_maxretry", "maxretry")):
        if old in raw:
            fail2ban[new] = raw[old]

    for name in ("keep_old_port_until_verified", "permit_root_ssh", "password_authentication", "install_fail2ban"):
        if name in raw and raw[name] is not (True if name == "keep_old_port_until_verified" or name == "install_fail2ban" else False):
            raise PolicyError(f"policy v1.{name} 与 0.2.0 安全不变量冲突，无法自动迁移")
    return result


def normalize_policy(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate and normalize v1/v2 input to an independent canonical v2 dict."""
    source = _mapping(raw or {}, "policy")
    version = source.get("policy_version", 1)
    if version == 1:
        source = _migrate_v1(source)
    elif version != POLICY_VERSION:
        raise PolicyError(f"不支持的 policy_version: {version}")
    else:
        _unknown(
            source,
            {"policy_version", "onepassword_vault", "platforms", "credentials", "defaults", "profiles", "controller", "report"},
            "policy v2",
        )
        source = _deep_merge(default_policy(), source)

    result = _deep_merge(default_policy(), source)
    result["policy_version"] = POLICY_VERSION
    _validate_string(result["onepassword_vault"], "onepassword_vault")

    platforms = _mapping(result["platforms"], "platforms")
    _unknown(platforms, {"supported"}, "platforms")
    result["platforms"]["supported"] = _validate_string_set(
        platforms["supported"], "platforms.supported", set(SUPPORTED_PLATFORMS), nonempty=True
    )

    result["credentials"] = _validate_credentials_settings(result["credentials"], "credentials")

    defaults = _mapping(result["defaults"], "defaults")
    _unknown(defaults, {"profile"}, "defaults")
    default_profile = _validate_string(defaults["profile"], "defaults.profile", pattern=_PROFILE_RE)

    profiles = _mapping(result["profiles"], "profiles")
    if not profiles:
        raise PolicyError("profiles 至少需要一个 profile")
    for name in profiles:
        _validate_string(name, "profiles 名称", pattern=_PROFILE_RE)
    if default_profile not in profiles:
        raise PolicyError(f"defaults.profile 引用了不存在的 profile: {default_profile}")
    for name in profiles:
        _validate_resolved_profile(_resolve_profile(profiles, name), f"resolved_profile.{name}")

    controller = _mapping(result["controller"], "controller")
    _unknown(controller, {"connect_timeout", "step_timeout", "transport_retries", "host_key_policy"}, "controller")
    _int(controller["connect_timeout"], "controller.connect_timeout", 5, 60)
    _int(controller["step_timeout"], "controller.step_timeout", 60, 1800)
    _int(controller["transport_retries"], "controller.transport_retries", 0, 3)
    _enum(controller["host_key_policy"], "controller.host_key_policy", {"accept-new-then-pin", "pinned"})

    report = _mapping(result["report"], "report")
    _unknown(report, {"formats", "address_display", "include_raw_evidence"}, "report")
    result["report"]["formats"] = _validate_string_set(report["formats"], "report.formats", {"json", "markdown"}, nonempty=True)
    _enum(report["address_display"], "report.address_display", {"full", "masked"})
    _bool(report["include_raw_evidence"], "report.include_raw_evidence")
    return result


def validate_host_input(data: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    """Validate schema-v2 host fields without persisting or contacting a VPS."""
    host = _mapping(data, "host")
    _unknown(
        host,
        {"id", "address", "platform", "initial_port", "initial_user", "initial_auth", "initial_key", "profile", "overrides"},
        "host",
    )
    _validate_string(host.get("id"), "host.id", pattern=_HOST_ID_RE)
    _validate_string(host.get("address"), "host.address")
    platform = _enum(host.get("platform", "auto"), "host.platform", {"auto", "ubuntu", "debian"})
    _int(host.get("initial_port", 22), "host.initial_port", 1, 65535)
    _validate_string(host.get("initial_user", "root"), "host.initial_user", pattern=_LINUX_USER_RE)
    auth = _enum(host.get("initial_auth", "key"), "host.initial_auth", {"key", "password"})
    key = host.get("initial_key")
    if auth == "key" and (not isinstance(key, str) or not key):
        raise PolicyError("host.initial_key 在 key 登录模式下为必填项")
    profile = _validate_string(host.get("profile", policy["defaults"]["profile"]), "host.profile", pattern=_PROFILE_RE)
    overrides = _mapping(host.get("overrides", {}), "host.overrides")
    resolve_host_policy(policy, profile, overrides)
    result = deepcopy(host)
    result["platform"] = platform
    result["profile"] = profile
    return result
