"""Write concise, non-secret JSON and Markdown final acceptance reports."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


_SECRET_KEYS = {
    "password", "managed_password", "passphrase", "private_key_passphrase", "private_key", "public_key",
    "initial_password", "raw",
}
_STATUSES = {"PASS", "FAIL", "WARN", "NOT_APPLICABLE", "NOT_CHECKED"}

def _description(name: str) -> str:
    known = {
        "ssh.managed_port": "受管 SSH 对外监听端口。",
        "ssh.root_login": "是否禁止 root 直接 SSH 登录。",
        "ssh.password_authentication": "是否允许 SSH 密码认证。",
        "files.ssh_config": "项目管理的 SSH 配置文件权限。",
        "user.home": "受管用户的 home 目录路径。",
        "user.ssh_dir": "受管用户 .ssh 目录的所有权和权限。",
        "user.authorized_keys": "受管用户授权公钥文件的所有权和权限。",
        "fail2ban.bantime": "单次封禁 IP 的持续时间。",
        "fail2ban.findtime": "统计失败登录次数的时间窗口。",
        "fail2ban.maxretry": "窗口内允许的最大失败次数。",
    }
    return known.get(name, "该检查项用于验证计划声明的安全配置是否已在 VPS 上生效。")


def _safe_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "host"


def _masked_address(address: str) -> str:
    if ":" in address:
        return "[IPv6 masked]"
    parts = address.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return f"{parts[0]}.{parts[1]}.***.***"
    return "***" if len(address) <= 4 else f"{address[:2]}***{address[-2:]}"


def _assert_no_secrets(value: Any, path: str = "report") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key.lower() in _SECRET_KEYS:
                raise ValueError(f"报告不能包含敏感字段: {path}.{key}")
            _assert_no_secrets(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_secrets(nested, f"{path}[{index}]")


def acceptance_check(check_id: str, severity: str, expected: Any, actual: Any, passed: bool, evidence: str) -> dict[str, Any]:
    if severity not in {"critical", "high", "medium", "low"}:
        raise ValueError("验收严重级别无效")
    return {"id": check_id, "severity": severity, "expected": expected, "actual": actual,
            "status": "PASS" if passed else "FAIL", "evidence": evidence[:500], "description": _description(check_id)}


def build_acceptance_report(host_id: str, address: str, checks: list[Mapping[str, Any]], *, plan: Mapping[str, Any] | None = None,
                            address_display: str = "masked") -> dict[str, Any]:
    """Create a validated report document without writing it to disk."""
    if address_display not in {"full", "masked"}:
        raise ValueError("address_display 必须为 full 或 masked")
    normalized = [dict(item) for item in checks]
    for item in normalized:
        item.setdefault("description", _description(str(item.get("id", ""))))
    _assert_no_secrets(normalized)
    required = {"id", "severity", "expected", "actual", "status", "evidence", "description"}
    if any(set(item) != required or item["status"] not in _STATUSES for item in normalized):
        raise ValueError("验收检查字段或状态无效")
    failures = [item for item in normalized if item["status"] == "FAIL"]
    warnings = [item for item in normalized if item["status"] in {"WARN", "NOT_CHECKED"}]
    report: dict[str, Any] = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": {"id": host_id, "address": address if address_display == "full" else _masked_address(address)},
        "overall_status": "PASS" if not failures else "FAIL",
        "summary": {"checks": len(normalized), "failed": len(failures), "warnings": len(warnings)}, "checks": normalized,
    }
    if plan:
        report["plan"] = {"plan_id": plan.get("plan_id"), "plan_sha256": plan.get("plan_sha256"),
                          "payload_sha256": plan.get("payload_sha256")}
        report["report_settings"] = {
            "formats": list(plan.get("report_settings", {}).get("formats", ["json", "markdown"])),
            "address_display": plan.get("report_settings", {}).get("address_display", address_display),
        }
    _assert_no_secrets(report)
    return report


def _markdown(report: Mapping[str, Any]) -> str:
    lines = ["# VPS 最终验收报告", "", f"- 生成时间：{report['generated_at']}",
             f"- 主机：{report['host']['id']} ({report['host']['address']})", f"- 总体结果：**{report['overall_status']}**",
             f"- 检查：{report['summary']['checks']}；失败：{report['summary']['failed']}；警告/未检查：{report['summary']['warnings']}", "",
             "| 检查项 | 级别 | 预期 | 实际 | 状态 | 证据 | 参数说明 |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for check in report["checks"]:
        escape = lambda value: str(value).replace("|", "\\|").replace("\n", " ")
        lines.append("| " + " | ".join(escape(check[key]) for key in ("id", "severity", "expected", "actual", "status", "evidence", "description")) + " |")
    if report.get("plan"):
        lines.extend(["", "## 执行计划", "", f"- ID：{report['plan']['plan_id']}", f"- 摘要：`{report['plan']['plan_sha256']}`"])
    return "\n".join(lines) + "\n"


def write_acceptance_reports(root: Path, report: Mapping[str, Any]) -> dict[str, Path]:
    """Atomically write one JSON and one Markdown report with 0600 permissions."""
    _assert_no_secrets(report)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    plan_id = str(report.get("plan", {}).get("plan_id") or "no-plan")
    prefix = f"audit-{_safe_token(str(report['host']['id']))}-{_safe_token(plan_id)}-{stamp}"
    directory = root / "logs"
    directory.mkdir(parents=True, exist_ok=True)
    formats = set(report.get("report_settings", {}).get("formats", ["json", "markdown"]))
    if not formats.issubset({"json", "markdown"}) or not formats:
        raise ValueError("报告格式必须是非空的 json/markdown 集合")
    paths = {kind: directory / f"{prefix}.{kind if kind == 'json' else 'md'}" for kind in formats}
    content = {"json": json.dumps(report, ensure_ascii=False, indent=2) + "\n", "markdown": _markdown(report)}
    for kind, path in paths.items():
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(content[kind], encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
    return paths


def write_change_archive(root: Path, host_id: str, address: str, plan: Mapping[str, Any],
                         policy: Mapping[str, Any], *, managed_user: str, ssh_port: int,
                         private_key_path: str) -> dict[str, Path]:
    """Archive categorized file/parameter changes without secrets.

    The current executor does not collect every remote pre-change value, so
    those fields are explicitly marked ``NOT_COLLECTED`` rather than guessed.
    """
    resolved_ssh = dict(policy.get("ssh", {}))
    resolved_ssh.update({"managed_port": ssh_port, "managed_user": managed_user})
    categories = {
        "credentials": {"files": ["本机凭据元数据（不含秘密）", private_key_path], "parameters": {k: v for k, v in policy.get("credentials", {}).items() if k not in {"password", "passphrase"}}},
        "ssh": {"files": ["/etc/ssh/sshd_config.d/00-vps-secure-init.conf", "/etc/systemd/system/ssh.socket.d/00-vps-secure-init.conf"], "parameters": resolved_ssh},
        "firewall": {"files": ["/etc/default/ufw", "UFW ruleset"], "parameters": policy.get("firewall", {})},
        "fail2ban": {"files": ["/etc/fail2ban/jail.d/99-vps-secure-init.local"], "parameters": policy.get("fail2ban", {})},
        "sudo": {"files": ["/etc/sudoers.d/90-vps-secure-init-managed"], "parameters": policy.get("sudo", {})},
        "user": {"files": [f"/home/{managed_user}/.ssh/authorized_keys"], "parameters": {"managed_user": managed_user}},
        "local_client": {"files": ["~/.ssh/config"], "parameters": {"host_alias": host_id, "address": address, "port": ssh_port, "user": managed_user, "identity_file": private_key_path}},
    }
    for name, item in categories.items():
        item["changes"] = [{"parameter": key, "description": _description(f"{name}.{key}"), "before": None, "before_status": "NOT_COLLECTED", "after": value}
                            for key, value in item["parameters"].items()]
        item.pop("parameters")
    archive = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
               "host": {"id": host_id, "address": address},
               "plan": {"plan_id": plan.get("plan_id"), "plan_sha256": plan.get("plan_sha256")},
               "categories": categories}
    _assert_no_secrets(archive)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    directory = root / "logs" / "changes"; directory.mkdir(parents=True, exist_ok=True)
    prefix = f"changes-{_safe_token(host_id)}-{_safe_token(str(plan.get('plan_id') or 'no-plan'))}-{stamp}"
    paths = {"json": directory / f"{prefix}.json", "markdown": directory / f"{prefix}.md"}
    lines = ["# VPS 配置变更档案", "", f"- 主机：{host_id} ({address})", f"- 生成时间：{archive['generated_at']}", "", "> before=NOT_COLLECTED 表示当前版本未采集远端修改前快照。", ""]
    for name, item in categories.items():
        lines += [f"## {name}", "", f"- 文件：{', '.join(item['files'])}", "", "| 参数 | 修改前 | 修改后 | 参数说明 |", "| --- | --- | --- | --- |"]
        lines += [f"| {c['parameter']} | NOT_COLLECTED | {str(c['after']).replace('|', '\\|')} | {c['description']} |" for c in item["changes"]]
        lines.append("")
    contents = {"json": json.dumps(archive, ensure_ascii=False, indent=2) + "\n", "markdown": "\n".join(lines)}
    for kind, path in paths.items():
        tmp = path.with_suffix(path.suffix + ".tmp"); tmp.write_text(contents[kind], encoding="utf-8"); tmp.chmod(0o600); tmp.replace(path)
    return paths


def write_report(root: Path, results: list[dict]) -> Path:
    """Compatibility wrapper for the legacy menu's multi-host audit output."""
    out = root / "logs" / f"audit-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    sanitized = [{key: value for key, value in result.items() if key != "raw"} for result in results]
    _assert_no_secrets(sanitized)
    out.write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), "results": sanitized}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out.chmod(0o600)
    return out
