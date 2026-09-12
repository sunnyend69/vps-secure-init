from copy import deepcopy
from pathlib import Path

import pytest

from vps_secure_init.models import Host
from vps_secure_init.plan import (
    PlanError, build_plan, calculate_plan_sha256, load_execution_plan, load_plan, verify_plan, write_plan,
)
from vps_secure_init.policy import normalize_policy


def _payload_root(tmp_path: Path) -> Path:
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    (payloads / "common.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (payloads / "preflight.sh").write_text("#!/usr/bin/env bash\necho preflight\n", encoding="utf-8")
    return tmp_path


def _host() -> Host:
    return Host(
        "hk-01",
        "203.0.113.10",
        initial_key="~/.ssh/provider_hk_01",
        profile="web",
        overrides={"credentials": {"ssh_port_mode": "manual", "ssh_port": 40993}},
    )


def _refs() -> dict:
    return {
        "onepassword_item_id": "item-123",
        "private_key_path": "~/.ssh/vps_hk_01_ed25519",
        "managed_user": "u_example123456789",
        "ssh_port": 40993,
    }


def test_plan_is_deterministic_when_identity_and_time_are_supplied(tmp_path: Path):
    root = _payload_root(tmp_path)
    policy = normalize_policy({"policy_version": 2})
    first = build_plan(root, _host(), policy, credential_refs=_refs(), plan_id="plan-a", created_at="2026-09-12T00:00:00+00:00")
    second = build_plan(root, _host(), policy, credential_refs=_refs(), plan_id="plan-a", created_at="2026-09-12T00:00:00+00:00")

    assert first == second
    assert first["resolved_policy"]["firewall"]["allowed_services"] == ["http", "https"]
    assert first["payload_sha256"].keys() == {"common.sh", "preflight.sh"}
    assert "managed_password" not in str(first)
    assert verify_plan(first)["plan_sha256"] == first["plan_sha256"]


def test_plan_is_atomically_written_once_and_verified_on_read(tmp_path: Path):
    root = _payload_root(tmp_path)
    plan = build_plan(root, _host(), normalize_policy({"policy_version": 2}), credential_refs=_refs(), plan_id="plan-b")
    path = write_plan(root, plan)

    assert path.exists()
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_plan(path)["plan_sha256"] == plan["plan_sha256"]
    with pytest.raises(PlanError, match="拒绝覆盖"):
        write_plan(root, plan)


def test_plan_rejects_tampering_and_secret_fields(tmp_path: Path):
    root = _payload_root(tmp_path)
    plan = build_plan(root, _host(), normalize_policy({"policy_version": 2}), credential_refs=_refs(), plan_id="plan-c")

    altered = deepcopy(plan)
    altered["host"]["address"] = "203.0.113.99"
    with pytest.raises(PlanError, match="SHA-256 不匹配"):
        verify_plan(altered)

    secret_bearing = deepcopy(plan)
    secret_bearing["resolved_policy"]["managed_password"] = "must-not-persist"
    secret_bearing["plan_sha256"] = calculate_plan_sha256(secret_bearing)
    with pytest.raises(PlanError, match="秘密字段"):
        verify_plan(secret_bearing)


def test_plan_rejects_credential_port_conflict(tmp_path: Path):
    root = _payload_root(tmp_path)
    refs = _refs()
    refs["ssh_port"] = 2222
    with pytest.raises(PlanError, match="SSH 端口"):
        build_plan(root, _host(), normalize_policy({"policy_version": 2}), credential_refs=refs)


def test_execution_plan_rejects_payload_drift_and_host_mismatch(tmp_path: Path):
    root = _payload_root(tmp_path)
    host = _host()
    plan = build_plan(root, host, normalize_policy({"policy_version": 2}), credential_refs=_refs())
    write_plan(root, plan)
    host.plan_id, host.plan_sha256 = plan["plan_id"], plan["plan_sha256"]

    assert load_execution_plan(root, host)["plan_id"] == plan["plan_id"]
    (root / "payloads" / "preflight.sh").write_text("changed\n", encoding="utf-8")
    with pytest.raises(PlanError, match="payload 已变化"):
        load_execution_plan(root, host)


def test_command_allowlist_is_frozen_for_finalize_application(tmp_path: Path):
    root = _payload_root(tmp_path)
    policy = normalize_policy({
        "policy_version": 2,
        "profiles": {"standard": {"sudo": {"final_mode": "command-allowlist"}}},
    })
    plan = build_plan(root, Host("hk-01", "203.0.113.10", initial_key="~/.ssh/provider"), policy)
    assert plan["resolved_policy"]["sudo"]["final_mode"] == "command-allowlist"
