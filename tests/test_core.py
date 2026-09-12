import json
from pathlib import Path
import pytest
from vps_secure_init.config import save_hosts
from vps_secure_init.models import Host, State
from vps_secure_init.state import StateStore
from vps_secure_init.credentials import (
    MANAGED_PASSWORD_LENGTH, MANAGED_USERNAME_LENGTH, PASSWORD_ALPHABET,
    USERNAME_ALPHABET, is_valid_linux_username, random_port, random_username, random_value,
)


def test_random_values():
    username = random_username()
    assert MANAGED_USERNAME_LENGTH == 18
    assert len(username) == 18
    assert username.startswith("u_")
    assert set(username[2:]) <= set(USERNAME_ALPHABET)
    assert is_valid_linux_username(username)

    password = random_value()
    assert MANAGED_PASSWORD_LENGTH == 100
    assert len(password) == 100
    assert set(password) <= set(PASSWORD_ALPHABET)
    assert set(PASSWORD_ALPHABET) == set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

    # Legacy explicit values remain bounded by Linux's hard username limit.
    assert len(random_username(64)) == 32
    assert not is_valid_linux_username("u_" + "a" * 63)
    assert not is_valid_linux_username("BadUser")
    assert 20000 <= random_port() <= 60000


def test_state_round_trip(tmp_path: Path):
    store = StateStore(tmp_path / "state" / "hosts.json")
    hosts = [Host("a", "192.0.2.1", state=State.PREFLIGHT_OK.value)]
    store.save(hosts)
    loaded = store.load()
    assert loaded[0].id == "a"
    assert loaded[0].state == State.PREFLIGHT_OK.value


def test_hosts_save_is_json_compatible(tmp_path: Path):
    path = tmp_path / "hosts.yaml"
    save_hosts(path, [Host("a", "192.0.2.1", platform="debian", overrides={"ssh": {"max_sessions": 6}})])
    saved = json.loads(path.read_text())["hosts"][0]
    assert saved["id"] == "a"
    assert saved["platform"] == "debian"
    assert saved["overrides"]["ssh"]["max_sessions"] == 6


def test_legacy_default_host_profile_is_migrated_in_memory():
    host = Host.from_dict({"id": "a", "address": "192.0.2.1", "profile": "default"})
    assert host.profile == "standard"


def test_setup_retains_capabilities_only_for_the_same_initial_endpoint(tmp_path: Path):
    from vps_secure_init.cli import setup

    config = tmp_path / "config"
    config.mkdir()
    (config / "hosts.yaml").write_text(
        json.dumps({"hosts": [{"id": "a", "address": "192.0.2.1", "initial_key": "/tmp/key"}]}),
        encoding="utf-8",
    )
    (config / "policy.yaml").write_text(json.dumps({"policy_version": 2}), encoding="utf-8")
    old = Host(
        "a", "192.0.2.1", initial_key="/tmp/key", state=State.PREFLIGHT_OK.value,
        detected_platform="ubuntu-22.04", capabilities={"ssh_service": "ssh"},
    )
    StateStore(tmp_path / "state" / "hosts.json").save([old])

    hosts, _, _ = setup(tmp_path)
    assert hosts[0].detected_platform == "ubuntu-22.04"
    assert hosts[0].capabilities["ssh_service"] == "ssh"

    (config / "hosts.yaml").write_text(
        json.dumps({"hosts": [{"id": "a", "address": "192.0.2.99", "initial_key": "/tmp/key"}]}),
        encoding="utf-8",
    )
    hosts, _, _ = setup(tmp_path)
    assert hosts[0].state == State.NEW.value
    assert hosts[0].detected_platform is None
    assert hosts[0].capabilities == {}


def test_payload_protocol_validation():
    from vps_secure_init.payload_manager import PayloadManager, PayloadError

    PayloadManager._validate_protocol(
        "preflight",
        "noise\r\nVPS_INIT_PROTOCOL=1\r\nVPS_INIT_STEP=preflight\r\nVPS_INIT_RESULT=ok\r\n",
    )
    try:
        PayloadManager._validate_protocol("preflight", "VPS_INIT_RESULT=ok\n")
    except PayloadError:
        pass
    else:
        raise AssertionError("invalid payload protocol must fail")


def test_failed_preverify_state_restarts_safely():
    from vps_secure_init.orchestrator import Orchestrator

    host = Host("a", "192.0.2.1", state=State.FAILED.value, resume_state=State.FIREWALL_VERIFIED.value)
    assert Orchestrator._resume_step(host) == "firewall"

    host.resume_state = State.DUAL_SSH_READY.value
    assert Orchestrator._resume_step(host) == "preflight"

    host.resume_state = State.NEW_LOGIN_VERIFIED.value
    assert Orchestrator._resume_step(host) == "firewall"

    # A failed 0.1.2 run may have left UFW LIMIT rules active after firewall.
    # Re-running firewall first repairs them to transition ALLOW rules before
    # fail2ban starts opening multiple SCP/SSH sessions.
    host.resume_state = State.FIREWALL_VERIFIED.value
    assert Orchestrator._resume_step(host) == "firewall"


def test_legacy_username_is_repaired_before_remote_use(tmp_path, monkeypatch):
    from vps_secure_init.orchestrator import Orchestrator

    repaired = {}

    class FakeOP:
        def __init__(self, vault):
            self.vault = vault

        def update_server_username(self, item_id, username):
            repaired["item_id"] = item_id
            repaired["username"] = username

    monkeypatch.setattr("vps_secure_init.orchestrator.OnePasswordStore", FakeOP)

    host = Host("legacy", "192.0.2.10")
    creds = {
        "legacy": {
            "managed_user": "u_" + "a" * 62,
            "managed_password": "pw",
            "private_key_passphrase": "pp",
            "onepassword_item_id": "item123",
        }
    }
    orch = Orchestrator(tmp_path, [host], {"username_length": 18, "onepassword_vault": "Private"}, None, creds)
    result = orch._creds(host)
    assert len(result["managed_user"]) == 18
    assert repaired["item_id"] == "item123"
    assert repaired["username"] == result["managed_user"]


def test_ssh_forwarding_policy_is_conservative_and_typed(tmp_path):
    from vps_secure_init.orchestrator import Orchestrator

    orch = Orchestrator(tmp_path, [], {}, None, {})
    variables = orch._security_variables("u_test", 40993)
    assert variables["ALLOW_TCP_FORWARDING"] == "no"
    assert variables["ALLOW_AGENT_FORWARDING"] == "no"
    assert variables["X11_FORWARDING"] == "no"

    orch.policy = {
        "allow_tcp_forwarding": True,
        "allow_agent_forwarding": False,
        "x11_forwarding": True,
    }
    variables = orch._security_variables("u_test", 40993)
    assert variables["ALLOW_TCP_FORWARDING"] == "yes"
    assert variables["ALLOW_AGENT_FORWARDING"] == "no"
    assert variables["X11_FORWARDING"] == "yes"

    orch.policy["x11_forwarding"] = "false"
    try:
        orch._security_variables("u_test", 40993)
    except RuntimeError as exc:
        assert "x11_forwarding" in str(exc)
    else:
        raise AssertionError("string policy boolean must be rejected")


def test_execution_variables_are_compiled_from_resolved_policy(tmp_path):
    from vps_secure_init.orchestrator import Orchestrator
    from vps_secure_init.policy import normalize_policy, resolve_host_policy

    policy = normalize_policy({
        "policy_version": 2,
        "profiles": {"standard": {"ssh": {"max_sessions": 8}, "fail2ban": {"bantime": "2h"}}},
    })
    effective = resolve_host_policy(
        policy, "standard", {"firewall": {"allowed_services": ["http"]}, "ssh": {"login_grace_time": 60}}
    )
    variables = Orchestrator(tmp_path, [], policy, None, {})._security_variables("u_test", 40993, effective)

    assert variables["LOGIN_GRACE_TIME"] == "60"
    assert variables["MAX_SESSIONS"] == "8"
    assert variables["FAIL2BAN_BANTIME"] == "2h"
    assert variables["FIREWALL_ALLOWED_SERVICES"] == "http"
    assert variables["FIREWALL_SSH_RATE_LIMIT"] == "yes"


def test_run_requires_a_frozen_plan_before_loading_credentials_or_connecting(tmp_path):
    from vps_secure_init.orchestrator import Orchestrator

    host = Host("hk-01", "203.0.113.10", initial_key="~/.ssh/provider")
    with pytest.raises(RuntimeError, match="尚未冻结执行计划"):
        Orchestrator(tmp_path, [host], {}, None, {}).run(host)


def test_completed_plan_is_reaudited_without_replaying_retired_rescue_connection(tmp_path, monkeypatch):
    from vps_secure_init.orchestrator import Orchestrator

    host = Host("hk-01", "203.0.113.10", state=State.COMPLETED.value)
    orch = Orchestrator(tmp_path, [host], {}, None, {})
    monkeypatch.setattr(orch, "_execution_contract", lambda _host: ({"report_settings": {}}, {}))
    monkeypatch.setattr(orch, "_creds", lambda _host: {"ssh_port": 40993})
    calls = []
    monkeypatch.setattr(orch, "_write_final_acceptance_report", lambda *args: calls.append(args) or {"overall_status": "PASS"})

    orch.run(host)

    assert len(calls) == 1


def test_validator_parses_structured_read_only_evidence(monkeypatch):
    from types import SimpleNamespace
    from vps_secure_init.validator import validate_host

    output = """VPS_AUDIT_UID=1001
VPS_AUDIT_USER_EXISTS=yes
VPS_AUDIT_SSHD_SYNTAX=pass
VPS_AUDIT_SSHD_PORT=40993
VPS_AUDIT_MANAGED_LISTENER=yes
VPS_AUDIT_OLD_LISTENER=no
VPS_AUDIT_UFW_ACTIVE=yes
VPS_AUDIT_UFW_MANAGED=yes
VPS_AUDIT_UFW_OLD=no
VPS_AUDIT_FAIL2BAN_ACTIVE=yes
VPS_AUDIT_FAIL2BAN_ENABLED=yes
VPS_AUDIT_FAIL2BAN_JAIL=yes
"""
    monkeypatch.setattr("vps_secure_init.validator.run_ssh", lambda *args, **kwargs: SimpleNamespace(stdout=output))
    result = validate_host(Host("hk-01", "203.0.113.10", initial_port=22), {
        "managed_user": "u_example123456789", "ssh_port": 40993, "private_key": "/tmp/key",
    })
    assert result["non_root"] is True
    assert result["ssh_port_listening"] is True
    assert result["fields"]["FAIL2BAN_JAIL"] == "yes"
