"""Small, testable terminal editors for a single host's desired configuration.

The editor deliberately works on a copy.  Callers decide whether a completed
edit is saved, so cancelling or failing validation never partially changes the
inventory file.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any, Callable, Mapping

from .models import Host
from .policy import PARAMETER_REGISTRY, PolicyError, normalize_policy, resolve_host_policy, validate_host_input


Input = Callable[[str], str]
Output = Callable[[str], None]

_EDITABLE_PARAMETER_IDS = tuple(
    parameter_id
    for parameter_id, spec in PARAMETER_REGISTRY.items()
    if spec.customizable and parameter_id.split(".", 1)[0] in {"credentials", "ssh", "firewall", "fail2ban", "sudo"}
)


def _get_path(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _set_path(value: dict[str, Any], path: str, new_value: Any) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        existing = current.get(part)
        if not isinstance(existing, dict):
            existing = {}
            current[part] = existing
        current = existing
    current[parts[-1]] = new_value


def _delete_path(value: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    current: dict[str, Any] | None = value
    ancestors: list[tuple[dict[str, Any], str]] = []
    for part in parts[:-1]:
        if not isinstance(current, dict) or not isinstance(current.get(part), dict):
            return
        ancestors.append((current, part))
        current = current[part]
    if current is not None:
        current.pop(parts[-1], None)
    for parent, key in reversed(ancestors):
        if not parent[key]:
            parent.pop(key)


def _read_value(parameter_id: str, raw: str, input_fn: Input, output_fn: Output) -> Any:
    """Convert a terminal response to the registry type; policy validates range."""
    spec = PARAMETER_REGISTRY[parameter_id]
    value_type = spec.type
    if value_type == "integer":
        return int(raw)
    if value_type == "boolean":
        lowered = raw.lower()
        if lowered in {"y", "yes", "true", "1"}:
            return True
        if lowered in {"n", "no", "false", "0"}:
            return False
        raise ValueError("请输入 yes/no 或 true/false")
    if value_type == "enum":
        return raw
    if value_type == "duration":
        return raw
    if value_type == "integer-pair":
        values = [int(token.strip()) for token in raw.split(",")]
        if len(values) != 2:
            raise ValueError("请输入两个以逗号分隔的整数")
        return values
    if value_type == "set":
        allowed = ["http", "https"] if parameter_id == "firewall.allowed_services" else ["json", "markdown"]
        output_fn("可选值: " + ", ".join(allowed) + "；留空表示无选项")
        values = [token.strip() for token in raw.split(",") if token.strip()]
        return values
    if value_type == "cidr-list":
        return [token.strip() for token in raw.split(",") if token.strip()]
    if value_type == "rule-list":
        output_fn("每条规则格式：端口[,tcp|udp][,来源 IP/CIDR 或 any][,备注]；多条用 ; 分隔；留空清空。")
        result: list[dict[str, Any]] = []
        for item in (part.strip() for part in raw.split(";") if part.strip()):
            fields = [field.strip() for field in item.split(",")]
            rule: dict[str, Any] = {"port": int(fields[0]) if fields[0].isdigit() else fields[0]}
            if len(fields) > 1 and fields[1]:
                rule["protocol"] = fields[1]
            if len(fields) > 2 and fields[2]:
                rule["source"] = fields[2]
            if len(fields) > 3 and fields[3]:
                rule["comment"] = fields[3]
            if len(fields) > 4:
                raise ValueError("每条规则最多四个字段")
            result.append(rule)
        return result
    raise ValueError(f"暂不支持编辑 {parameter_id}")


def _host_data(host: Host) -> dict[str, Any]:
    return {
        "id": host.id,
        "address": host.address,
        "platform": host.platform,
        "initial_port": host.initial_port,
        "initial_user": host.initial_user,
        "initial_auth": host.initial_auth,
        "initial_key": host.initial_key,
        "profile": host.profile,
        "overrides": deepcopy(host.overrides),
    }


def _apply_host_data(host: Host, data: Mapping[str, Any]) -> Host:
    """Copy desired fields only; runtime state stays exclusively in state/hosts.json."""
    return replace(
        host,
        platform=data["platform"],
        profile=data["profile"],
        overrides=deepcopy(data["overrides"]),
    )


def format_effective_policy(policy: Mapping[str, Any]) -> str:
    """Render resolved policy as readable grouped lists for the interactive UI."""
    lines = ["有效配置："]
    for section, values in policy.items():
        lines.append(f"\n[{section}]")
        if not isinstance(values, Mapping):
            lines.append(f"- {values}")
            continue
        for name, value in values.items():
            if isinstance(value, list):
                if not value:
                    lines.append(f"- {name}: （空）")
                elif all(isinstance(item, Mapping) for item in value):
                    lines.append(f"- {name}:")
                    for item in value:
                        lines.append("  - rule:")
                        for item_name, item_value in item.items():
                            lines.append(f"    - {item_name}: {item_value}")
                else:
                    lines.append(f"- {name}: {', '.join(str(item) for item in value)}")
            else:
                lines.append(f"- {name}: {value}")
    return "\n".join(lines)


def edit_host_configuration(host: Host, policy: Mapping[str, Any], *, input_fn: Input = input, output_fn: Output = print) -> Host | None:
    """Interactively edit profile and host-level overrides; return ``None`` on cancel.

    It intentionally does not ask for initial passwords or private-key
    passphrases.  Those are transient runtime inputs, never configuration.
    """
    candidate = _host_data(host)
    profile_names = sorted(policy["profiles"])
    output_fn(f"正在编辑 {host.id}；输入 q 可取消，Enter 保留当前值。")
    while True:
        output_fn("\n配置菜单：1 选择 profile  2 编辑参数覆盖  3 查看有效配置  4 确认  q 取消")
        choice = input_fn("选择: ").strip().lower()
        if choice == "q":
            return None
        if choice == "1":
            output_fn("可选 profile: " + ", ".join(profile_names))
            selected = input_fn(f"profile [{candidate['profile']}]: ").strip()
            if selected:
                if selected not in profile_names:
                    output_fn("未知 profile。")
                else:
                    candidate["profile"] = selected
        elif choice == "2":
            resolved = resolve_host_policy(policy, candidate["profile"], candidate["overrides"])
            for index, parameter_id in enumerate(_EDITABLE_PARAMETER_IDS, 1):
                spec = PARAMETER_REGISTRY[parameter_id]
                overridden = _get_path(candidate["overrides"], parameter_id)
                marker = "覆盖" if overridden is not None else "继承"
                output_fn(f"{index:2}. {parameter_id} = {_get_path(resolved, parameter_id)!r} [{marker}; {spec.domain}]")
            selected = input_fn("参数编号（q 返回）: ").strip().lower()
            if selected == "q" or not selected:
                continue
            try:
                parameter_id = _EDITABLE_PARAMETER_IDS[int(selected) - 1]
            except (ValueError, IndexError):
                output_fn("无效编号。")
                continue
            current = _get_path(resolved, parameter_id)
            raw = input_fn(f"{parameter_id} [{current!r}]（r=恢复继承）: ").strip()
            if not raw:
                continue
            if raw.lower() == "r":
                _delete_path(candidate["overrides"], parameter_id)
                continue
            try:
                previous_overrides = deepcopy(candidate["overrides"])
                _set_path(candidate["overrides"], parameter_id, _read_value(parameter_id, raw, input_fn, output_fn))
                # Validate immediately, but preserve the candidate for further edits
                # if the user supplied an invalid value.
                resolve_host_policy(policy, candidate["profile"], candidate["overrides"])
            except (PolicyError, ValueError) as exc:
                candidate["overrides"] = previous_overrides
                output_fn(f"未应用：{exc}")
        elif choice == "3":
            try:
                output_fn(format_effective_policy(resolve_host_policy(policy, candidate["profile"], candidate["overrides"])))
            except PolicyError as exc:
                output_fn(f"配置无效：{exc}")
        elif choice == "4":
            try:
                normalized = validate_host_input(candidate, policy)
                return _apply_host_data(host, normalized)
            except PolicyError as exc:
                output_fn(f"无法保存：{exc}")
        else:
            output_fn("无效选择。")


def edit_global_policy(policy: Mapping[str, Any], *, input_fn: Input = input, output_fn: Output = print) -> dict[str, Any] | None:
    """Edit controller/report settings in a policy copy and validate each change."""
    candidate = deepcopy(dict(policy))
    parameter_ids = tuple(
        parameter_id for parameter_id, spec in PARAMETER_REGISTRY.items()
        if spec.customizable and parameter_id.split(".", 1)[0] in {"controller", "report"}
    )
    while True:
        output_fn("\n全局参数：1 编辑参数  2 查看当前值  3 确认  q 取消")
        choice = input_fn("选择: ").strip().lower()
        if choice == "q":
            return None
        if choice == "2":
            output_fn(str({parameter_id: _get_path(candidate, parameter_id) for parameter_id in parameter_ids}))
            continue
        if choice == "3":
            return normalize_policy(candidate)
        if choice != "1":
            output_fn("无效选择。")
            continue
        for index, parameter_id in enumerate(parameter_ids, 1):
            output_fn(f"{index:2}. {parameter_id} = {_get_path(candidate, parameter_id)!r} ({PARAMETER_REGISTRY[parameter_id].domain})")
        selected = input_fn("参数编号（q 返回）: ").strip().lower()
        if selected == "q" or not selected:
            continue
        try:
            parameter_id = parameter_ids[int(selected) - 1]
        except (ValueError, IndexError):
            output_fn("无效编号。")
            continue
        raw = input_fn(f"{parameter_id} [{_get_path(candidate, parameter_id)!r}]: ").strip()
        if not raw:
            continue
        previous = deepcopy(candidate)
        try:
            _set_path(candidate, parameter_id, _read_value(parameter_id, raw, input_fn, output_fn))
            normalize_policy(candidate)
        except (PolicyError, ValueError) as exc:
            candidate = previous
            output_fn(f"未应用：{exc}")
