import pytest

from vps_secure_init.platforms import CapabilityError, parse_linux_capabilities, validate_linux_capabilities
from vps_secure_init.policy import normalize_policy


def _preflight_output(**changes: str) -> str:
    fields = {
        "OS_ID": "ubuntu",
        "OS_VERSION": "22.04",
        "PLATFORM": "ubuntu-22.04",
        "APT_GET": "yes",
        "SYSTEMD": "yes",
        "SSHD_BIN": "/usr/sbin/sshd",
        "SSH_SERVICE": "ssh",
        "SSH_DROPIN": "yes",
        "SUDO": "yes",
        "UFW": "no",
        "IPV6": "yes",
        "FAIL2BAN": "no",
        "JOURNAL": "yes",
        "AUTH_LOG": "yes",
    }
    fields.update(changes)
    return "\n".join(f"VPS_INIT_CAP_{key}={value}" for key, value in fields.items()) + "\n"


def test_parse_and_validate_ubuntu_capability_snapshot():
    snapshot = parse_linux_capabilities(_preflight_output())
    policy = normalize_policy({"policy_version": 2})
    validate_linux_capabilities(snapshot, policy, "auto")
    assert snapshot.platform == "ubuntu-22.04"
    assert snapshot.ssh_service == "ssh"
    assert snapshot.ufw_installed is False


def test_capability_parser_rejects_missing_or_inconsistent_protocol_fields():
    with pytest.raises(CapabilityError, match="必要能力字段"):
        parse_linux_capabilities("VPS_INIT_CAP_OS_ID=ubuntu\n")

    with pytest.raises(CapabilityError, match="不一致"):
        parse_linux_capabilities(_preflight_output(OS_VERSION="24.04"))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"SUDO": "no"}, "sudo"),
        ({"SSH_DROPIN": "no"}, "drop-in"),
        ({"JOURNAL": "no", "AUTH_LOG": "no"}, "认证日志"),
        ({"PLATFORM": "debian-13", "OS_ID": "debian", "OS_VERSION": "13"}, "实际探测到 debian"),
    ],
)
def test_capability_validation_rejects_unsafe_or_mismatched_hosts(changes, message):
    snapshot = parse_linux_capabilities(_preflight_output(**changes))
    policy = normalize_policy({"policy_version": 2})
    requested = "ubuntu" if snapshot.platform == "debian-13" else "auto"
    with pytest.raises(CapabilityError, match=message):
        validate_linux_capabilities(snapshot, policy, requested)


def test_root_bootstrap_may_defer_missing_sudo_when_apt_is_available():
    snapshot = parse_linux_capabilities(_preflight_output(SUDO="no"))
    policy = normalize_policy({"policy_version": 2})
    validate_linux_capabilities(snapshot, policy, "auto", allow_bootstrap_sudo=True)


def test_policy_can_restrict_the_supported_platform_matrix():
    snapshot = parse_linux_capabilities(_preflight_output())
    policy = normalize_policy(
        {"policy_version": 2, "platforms": {"supported": ["debian-12"]}}
    )
    with pytest.raises(CapabilityError, match="策略未启用"):
        validate_linux_capabilities(snapshot, policy)
