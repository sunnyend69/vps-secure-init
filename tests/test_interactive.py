from pathlib import Path

from vps_secure_init.cli import build_host_plan, freeze_host_plan
from vps_secure_init.interactive import _EDITABLE_PARAMETER_IDS, edit_global_policy, edit_host_configuration, format_effective_policy
from vps_secure_init.models import Host
from vps_secure_init.plan import load_plan
from vps_secure_init.policy import normalize_policy, resolve_host_policy


def _answers(values):
    iterator = iter(values)
    return lambda _prompt: next(iterator)


def _payload_root(tmp_path: Path) -> Path:
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    (payloads / "preflight.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    return tmp_path


def test_interactive_edit_changes_only_desired_host_fields():
    policy = normalize_policy({"policy_version": 2})
    host = Host("hk-01", "203.0.113.10", initial_key="~/.ssh/provider")
    max_sessions_index = _EDITABLE_PARAMETER_IDS.index("ssh.max_sessions") + 1
    output = []

    edited = edit_host_configuration(
        host,
        policy,
        input_fn=_answers(["1", "web", "2", str(max_sessions_index), "8", "4"]),
        output_fn=output.append,
    )

    assert edited is not None
    assert edited.profile == "web"
    assert edited.overrides == {"ssh": {"max_sessions": 8}}
    assert host.profile == "standard"
    assert resolve_host_policy(policy, edited.profile, edited.overrides)["ssh"]["max_sessions"] == 8


def test_interactive_invalid_value_does_not_erase_an_existing_override():
    policy = normalize_policy({"policy_version": 2})
    host = Host(
        "hk-01", "203.0.113.10", initial_key="~/.ssh/provider", overrides={"ssh": {"max_sessions": 8}}
    )
    max_sessions_index = _EDITABLE_PARAMETER_IDS.index("ssh.max_sessions") + 1

    edited = edit_host_configuration(
        host,
        policy,
        input_fn=_answers(["2", str(max_sessions_index), "21", "4"]),
        output_fn=lambda _value: None,
    )

    assert edited is not None
    assert edited.overrides == {"ssh": {"max_sessions": 8}}


def test_plan_preview_and_freeze_keep_secrets_out_of_plan(tmp_path: Path):
    root = _payload_root(tmp_path)
    policy = normalize_policy({"policy_version": 2})
    host = Host("hk-01", "203.0.113.10", initial_key="~/.ssh/provider")
    session = {
        "hk-01": {
            "managed_user": "u_example123456789",
            "managed_password": "secret",
            "private_key": "~/.ssh/vps_hk_01_ed25519",
            "private_key_passphrase": "secret-passphrase",
            "ssh_port": 40993,
        }
    }

    preview = build_host_plan(root, host, policy, session)
    path = freeze_host_plan(root, host, policy, session, preview=preview)

    saved = load_plan(path)
    assert saved["plan_id"] == preview["plan_id"]
    assert host.plan_id == preview["plan_id"]
    assert host.plan_sha256 == preview["plan_sha256"]
    assert "managed_password" not in path.read_text(encoding="utf-8")
    assert "secret-passphrase" not in path.read_text(encoding="utf-8")


def test_global_interactive_editor_updates_controller_settings_only():
    policy = normalize_policy({"policy_version": 2})
    updated = edit_global_policy(
        policy,
        input_fn=_answers(["1", "1", "45", "3"]),
        output_fn=lambda _value: None,
    )
    assert updated is not None
    assert updated["controller"]["connect_timeout"] == 45
    assert updated["report"] == policy["report"]


def test_effective_policy_is_rendered_as_grouped_lists():
    rendered = format_effective_policy({"ssh": {"max_sessions": 8}, "firewall": {"allowed_services": [], "allowed_ports": [{"port": "51820", "protocol": "udp"}]}})
    assert "[ssh]" in rendered
    assert "- max_sessions: 8" in rendered
    assert "- allowed_services: （空）" in rendered
    assert "  - rule:" in rendered
    assert "    - port: 51820" in rendered
