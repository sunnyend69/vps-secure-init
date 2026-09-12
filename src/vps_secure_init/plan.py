"""Immutable, non-secret execution plans for a single VPS initialization."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping
from uuid import uuid4

from . import __version__
from .models import Host
from .policy import PolicyError, resolve_host_policy, validate_host_input


# v2 binds the platform matrix in addition to the host, resolved policy and
# payloads.  Older plan files must be deliberately regenerated, not guessed.
PLAN_SCHEMA_VERSION = 4
_PLAN_FILE_TOKEN = re.compile(r"[^a-zA-Z0-9_.-]+")
_CREDENTIAL_REF_FIELDS = {"onepassword_item_id", "private_key_path", "managed_user", "ssh_port"}
_FORBIDDEN_SECRET_TOKENS = {"managed_password", "passphrase", "private_key", "public_key", "initial_password"}


class PlanError(ValueError):
    """A plan cannot be safely built, read, or persisted."""


def canonical_json(value: Mapping[str, Any]) -> str:
    """Canonical JSON used for stable plan digests and test fixtures."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def calculate_plan_sha256(plan: Mapping[str, Any]) -> str:
    unsigned = deepcopy(dict(plan))
    unsigned.pop("plan_sha256", None)
    return hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()


def payload_digests(root: Path) -> dict[str, str]:
    payload_dir = root / "payloads"
    if not payload_dir.is_dir():
        raise PlanError(f"payload 目录不存在: {payload_dir}")
    payloads = sorted(payload_dir.rglob("*.sh"))
    if not payloads:
        raise PlanError("未找到任何 payload")
    return {
        str(path.relative_to(payload_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in payloads
    }


def _safe_credential_refs(value: Mapping[str, Any] | None) -> dict[str, Any]:
    refs = dict(value or {})
    unknown = sorted(set(refs) - _CREDENTIAL_REF_FIELDS)
    if unknown:
        raise PlanError(f"credential_refs 包含不允许字段: {', '.join(unknown)}")
    forbidden = sorted(key for key in refs if key in _FORBIDDEN_SECRET_TOKENS)
    if forbidden:
        raise PlanError(f"执行计划不能包含秘密字段: {', '.join(forbidden)}")
    if "onepassword_item_id" in refs and not isinstance(refs["onepassword_item_id"], str):
        raise PlanError("onepassword_item_id 必须是字符串")
    if "private_key_path" in refs and not isinstance(refs["private_key_path"], str):
        raise PlanError("private_key_path 必须是字符串")
    if "managed_user" in refs and not isinstance(refs["managed_user"], str):
        raise PlanError("managed_user 必须是字符串")
    if "ssh_port" in refs and (isinstance(refs["ssh_port"], bool) or not isinstance(refs["ssh_port"], int)):
        raise PlanError("ssh_port 必须是整数")
    return refs


def _assert_no_secrets(value: Any, path: str = "plan") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key in _FORBIDDEN_SECRET_TOKENS:
                raise PlanError(f"执行计划不能包含秘密字段: {path}.{key}")
            _assert_no_secrets(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_secrets(nested, f"{path}[{index}]")


def _host_input(host: Host) -> dict[str, Any]:
    return {
        "id": host.id,
        "address": host.address,
        "platform": host.platform,
        "initial_port": host.initial_port,
        "initial_user": host.initial_user,
        "initial_auth": host.initial_auth,
        "initial_key": host.initial_key,
        "profile": host.profile,
        "overrides": host.overrides,
    }


def build_plan(
    root: Path,
    host: Host,
    policy: Mapping[str, Any],
    *,
    credential_refs: Mapping[str, Any] | None = None,
    plan_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build but do not persist a fully resolved, non-secret plan preview."""
    try:
        normalized_host = validate_host_input(_host_input(host), policy)
        resolved_policy = resolve_host_policy(policy, normalized_host["profile"], normalized_host["overrides"])
    except PolicyError as exc:
        raise PlanError(str(exc)) from exc
    refs = _safe_credential_refs(credential_refs)
    if "ssh_port" in refs:
        configured_port = resolved_policy["credentials"].get("ssh_port")
        if configured_port is not None and configured_port != refs["ssh_port"]:
            raise PlanError("凭据 SSH 端口与有效计划的手工端口不一致")
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_id": plan_id or str(uuid4()),
        "app_version": __version__,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "host": {
            "id": normalized_host["id"],
            "address": normalized_host["address"],
            "platform": normalized_host["platform"],
            "initial_port": normalized_host["initial_port"],
            "initial_user": normalized_host["initial_user"],
            "initial_auth": normalized_host["initial_auth"],
            "profile": normalized_host["profile"],
        },
        "credential_refs": refs,
        "report_settings": deepcopy(policy["report"]),
        "controller_settings": deepcopy(policy["controller"]),
        "resolved_policy": resolved_policy,
        "supported_platforms": list(policy["platforms"]["supported"]),
        "payload_sha256": payload_digests(root),
    }
    plan["plan_sha256"] = calculate_plan_sha256(plan)
    return plan


def verify_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Reject malformed, altered, or secret-bearing plans before execution."""
    required = {
        "schema_version", "plan_id", "app_version", "created_at", "host", "credential_refs", "report_settings", "controller_settings", "supported_platforms",
        "resolved_policy", "payload_sha256", "plan_sha256",
    }
    missing = sorted(required - set(plan))
    if missing:
        raise PlanError(f"执行计划缺少字段: {', '.join(missing)}")
    unknown = sorted(set(plan) - required)
    if unknown:
        raise PlanError(f"执行计划包含未知字段: {', '.join(unknown)}")
    if plan["schema_version"] != PLAN_SCHEMA_VERSION:
        raise PlanError(f"不支持的计划 schema_version: {plan['schema_version']}")
    if not isinstance(plan["plan_id"], str) or not plan["plan_id"]:
        raise PlanError("执行计划 plan_id 无效")
    if not isinstance(plan["payload_sha256"], Mapping) or not plan["payload_sha256"]:
        raise PlanError("执行计划缺少 payload SHA-256")
    for name, digest in plan["payload_sha256"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise PlanError("执行计划包含无效 payload SHA-256")
    if not isinstance(plan["supported_platforms"], list) or not all(isinstance(item, str) for item in plan["supported_platforms"]):
        raise PlanError("执行计划缺少有效的平台支持列表")
    if not isinstance(plan["report_settings"], Mapping):
        raise PlanError("执行计划缺少报告设置")
    if not isinstance(plan["controller_settings"], Mapping):
        raise PlanError("执行计划缺少控制器设置")
    _safe_credential_refs(plan["credential_refs"])
    _assert_no_secrets(plan)
    expected = calculate_plan_sha256(plan)
    if plan["plan_sha256"] != expected:
        raise PlanError("执行计划 SHA-256 不匹配，文件可能已被修改")
    return deepcopy(dict(plan))


def _plan_path(root: Path, plan: Mapping[str, Any]) -> Path:
    host_id = _PLAN_FILE_TOKEN.sub("_", str(plan["host"]["id"])).strip("._") or "host"
    plan_id = _PLAN_FILE_TOKEN.sub("_", str(plan["plan_id"])).strip("._")
    if not plan_id:
        raise PlanError("执行计划 plan_id 无法生成安全文件名")
    return root / "state" / "plans" / f"{host_id}-{plan_id}.json"


def write_plan(root: Path, plan: Mapping[str, Any]) -> Path:
    """Atomically persist a verified plan once; never overwrite an existing plan."""
    verified = verify_plan(plan)
    path = _plan_path(root, verified)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise PlanError(f"执行计划已存在，拒绝覆盖: {path}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(verified, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def load_plan(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PlanError(f"无法读取执行计划: {path}") from exc
    if not isinstance(parsed, Mapping):
        raise PlanError("执行计划根节点必须是对象")
    return verify_plan(parsed)


def load_execution_plan(root: Path, host: Host) -> dict[str, Any]:
    """Load the exact plan attached to a host and reject policy/payload drift.

    A state record only stores an ID and digest, so this function re-establishes
    the binding to the inventory host before the controller opens SSH.
    """
    if not host.plan_id or not host.plan_sha256:
        raise PlanError(f"主机 {host.id} 尚未冻结执行计划")
    path = _plan_path(root, {"host": {"id": host.id}, "plan_id": host.plan_id})
    plan = load_plan(path)
    if plan["plan_sha256"] != host.plan_sha256:
        raise PlanError("主机状态中的执行计划摘要与计划文件不一致")
    if plan["host"]["id"] != host.id or plan["host"]["address"] != host.address:
        raise PlanError("执行计划与当前主机清单不一致；请重新冻结计划")
    if plan["payload_sha256"] != payload_digests(root):
        raise PlanError("payload 已变化；请重新预览并冻结新的执行计划")
    return plan
