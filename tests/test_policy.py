from copy import deepcopy

import pytest

from vps_secure_init.policy import (
    PARAMETER_REGISTRY,
    PolicyError,
    default_policy,
    normalize_policy,
    resolve_host_policy,
    resolve_profile,
    validate_host_input,
)


def test_v1_policy_migrates_in_memory_to_v2():
    migrated = normalize_policy(
        {
            "policy_version": 1,
            "onepassword_vault": "Private",
            "supported_os": ["ubuntu-22.04", "debian-12"],
            "username_length": 18,
            "password_length": 100,
            "passphrase_length": 100,
            "ssh_port_range": [21000, 22000],
            "keep_old_port_until_verified": True,
            "permit_root_ssh": False,
            "password_authentication": False,
            "allow_tcp_forwarding": True,
            "allow_agent_forwarding": False,
            "install_fail2ban": True,
            "fail2ban_bantime": "2h",
            "fail2ban_findtime": "15m",
            "fail2ban_maxretry": 4,
        }
    )

    assert migrated["policy_version"] == 2
    assert migrated["onepassword_vault"] == "Private"
    assert migrated["platforms"]["supported"] == ["ubuntu-22.04", "debian-12"]
    assert migrated["credentials"]["ssh_port_range"] == [21000, 22000]
    assert migrated["profiles"]["standard"]["ssh"]["allow_tcp_forwarding"] is True
    assert migrated["profiles"]["standard"]["fail2ban"]["bantime"] == "2h"


def test_v1_migration_rejects_weakened_safety_invariant():
    with pytest.raises(PolicyError, match="permit_root_ssh"):
        normalize_policy({"policy_version": 1, "permit_root_ssh": True})


def test_web_profile_inherits_standard_and_host_override_is_resolved():
    policy = normalize_policy({"policy_version": 2})
    resolved = resolve_profile(
        policy,
        "web",
        {"ssh": {"max_sessions": 8}, "firewall": {"allowed_ports": [{"port": 8443, "comment": "admin-ui"}]}},
    )

    assert resolved["firewall"]["allowed_services"] == ["http", "https"]
    assert resolved["ssh"]["max_sessions"] == 8
    assert resolved["ssh"]["max_auth_tries"] == 5
    assert resolved["firewall"]["allowed_ports"] == [
        {"port": "8443", "protocol": "tcp", "source": "any", "comment": "admin-ui"}
    ]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"profiles": {"standard": {"ssh": {"allow_tcp_forwarding": "false"}}}}, "allow_tcp_forwarding"),
        ({"profiles": {"standard": {"firewall": {"allowed_services": ["smtp"]}}}}, "allowed_services"),
        ({"credentials": {"ssh_port_mode": "manual", "ssh_port": None}}, "credentials.ssh_port"),
        ({"controller": {"connect_timeout": 61}}, "controller.connect_timeout"),
    ],
)
def test_policy_rejects_invalid_values(change, message):
    policy = default_policy()
    for key, value in change.items():
        if isinstance(value, dict):
            policy[key] = _merge(policy[key], value)
        else:
            policy[key] = value
    with pytest.raises(PolicyError, match=message):
        normalize_policy(policy)


def test_policy_rejects_unknown_field_and_inheritance_cycle():
    with pytest.raises(PolicyError, match="未知字段"):
        normalize_policy({"policy_version": 2, "not_a_setting": True})

    with pytest.raises(PolicyError, match="循环继承"):
        normalize_policy(
            {
                "policy_version": 2,
                "profiles": {
                    "one": {"extends": "two"},
                    "two": {"extends": "one"},
                },
                "defaults": {"profile": "one"},
            }
        )


def test_firewall_rejects_duplicate_semantic_rule():
    policy = default_policy()
    policy["profiles"]["standard"]["firewall"]["allowed_ports"] = [
        {"port": 443, "protocol": "tcp"},
        {"port": 443, "protocol": "tcp", "source": "any", "comment": "duplicate"},
    ]
    with pytest.raises(PolicyError, match="重复规则"):
        normalize_policy(policy)


def test_host_input_is_checked_against_the_resolved_policy():
    policy = normalize_policy({"policy_version": 2})
    host = validate_host_input(
        {
            "id": "hk-01",
            "address": "203.0.113.10",
            "initial_auth": "key",
            "initial_key": "~/.ssh/provider",
            "profile": "web",
            "overrides": {"ssh": {"max_auth_tries": 6}},
        },
        policy,
    )
    assert host["platform"] == "auto"
    assert host["profile"] == "web"

    with pytest.raises(PolicyError, match="initial_key"):
        validate_host_input({"id": "hk-01", "address": "203.0.113.10"}, policy)


def test_host_credential_override_supports_a_manual_port():
    policy = normalize_policy({"policy_version": 2})
    resolved = resolve_host_policy(
        policy,
        "standard",
        {"credentials": {"ssh_port_mode": "manual", "ssh_port": 40993}},
    )
    assert resolved["credentials"]["ssh_port_mode"] == "manual"
    assert resolved["credentials"]["ssh_port"] == 40993

    with pytest.raises(PolicyError, match="ssh_port"):
        resolve_host_policy(policy, "standard", {"credentials": {"ssh_port_mode": "manual"}})


def test_credential_generation_reads_host_level_policy_without_side_effects():
    from vps_secure_init.cli import _host_credentials_policy
    from vps_secure_init.models import Host

    policy = normalize_policy({"policy_version": 2})
    host = Host(
        "hk-01", "203.0.113.10", initial_key="~/.ssh/provider",
        overrides={"credentials": {"ssh_port_mode": "manual", "ssh_port": 40993}},
    )
    settings = _host_credentials_policy(host, policy)
    assert settings["ssh_port_mode"] == "manual"
    assert settings["ssh_port"] == 40993


def test_registry_exposes_unique_metadata_for_every_parameter():
    assert len(PARAMETER_REGISTRY) >= 40
    assert set(PARAMETER_REGISTRY) == {spec.id for spec in PARAMETER_REGISTRY.values()}
    assert all(spec.domain and spec.ui for spec in PARAMETER_REGISTRY.values())


def test_package_version_matches_the_current_baseline():
    from vps_secure_init import __version__

    assert __version__ == "0.1.4"


def test_save_policy_writes_a_valid_v2_yaml_file(tmp_path):
    from vps_secure_init.config import load_policy, save_policy

    path = tmp_path / "config" / "policy.yaml"
    save_policy(path, {"policy_version": 2, "defaults": {"profile": "web"}})
    loaded = load_policy(path)
    assert loaded["defaults"]["profile"] == "web"
    assert path.stat().st_mode & 0o777 == 0o600


def _merge(base, override):
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result
