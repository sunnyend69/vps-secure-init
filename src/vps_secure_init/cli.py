import argparse
import json
import logging
from pathlib import Path
from .config import load_hosts, load_policy, save_hosts, save_policy
from .credentials import (
    MANAGED_PASSWORD_LENGTH, MANAGED_USERNAME_LENGTH, generate_key, random_value,
    random_port, random_username,
)
from .models import Host, State
from .state import StateStore
from .orchestrator import Orchestrator
from .report import write_report
from .onepassword import OnePasswordStore, OnePasswordError
from .policy import resolve_host_policy
from .interactive import edit_global_policy, edit_host_configuration
from .plan import PlanError, build_plan, write_plan


def _paths(root: Path):
    return root / "config/hosts.yaml", root / "config/policy.yaml", root / "state/hosts.json", root / "logs/vpsctl.log"


def setup(root: Path):
    hosts_path, policy_path, state_path, log_path = _paths(root)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=log_path, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # hosts.yaml is authoritative for inventory. Persisted state is merged only
    # for matching IDs, so editing an ID/address takes effect immediately.
    persisted = {h.id: h for h in StateStore(state_path).load()} if state_path.exists() else {}
    metadata_path = root / "config/credentials.json"
    metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
    configured = load_hosts(hosts_path) if hosts_path.exists() else []
    hosts = []
    for host in configured:
        old = persisted.get(host.id)
        # Do not carry a state machine position or capability snapshot to a
        # different endpoint merely because a user kept the same inventory ID.
        same_initial_endpoint = old and (
            old.address,
            old.initial_port,
            old.initial_user,
            old.initial_auth,
            old.initial_key,
        ) == (
            host.address,
            host.initial_port,
            host.initial_user,
            host.initial_auth,
            host.initial_key,
        )
        if same_initial_endpoint:
            host.state = old.state
            host.last_error = old.last_error
            host.resume_state = old.resume_state
            host.detected_platform = old.detected_platform
            host.capabilities = old.capabilities
            host.plan_id = old.plan_id
            host.plan_sha256 = old.plan_sha256
            # A reset/deleted credential record invalidates all derived states.
            record = metadata.get(host.id, {})
            credential_valid = bool(record.get("ssh_port") and record.get("private_key") and Path(record["private_key"]).expanduser().exists())
            if host.state != State.NEW.value and not credential_valid:
                host.state = State.NEW.value
                host.last_error = None
                host.resume_state = None
        hosts.append(host)
    if not configured:
        hosts = list(persisted.values())
    policy = load_policy(policy_path) if policy_path.exists() else {}
    return hosts, policy, StateStore(state_path)


def _host_credentials_policy(host: Host, policy: dict) -> dict:
    return resolve_host_policy(policy, host.profile, host.overrides)["credentials"]


def generate_credentials(root: Path, hosts: list[Host], policy: dict, save_to_1password: bool = True):
    cred_path = root / "config/credentials.json"
    session = {}
    metadata = {}
    ssh_dir = Path.home() / ".ssh"
    for host in hosts:
        if host.id in session:
            continue
        credentials_policy = _host_credentials_policy(host, policy)
        user = random_username(int(credentials_policy.get("username_length", MANAGED_USERNAME_LENGTH)))
        password = random_value(int(credentials_policy.get("password_length", MANAGED_PASSWORD_LENGTH)))
        passphrase = random_value(int(credentials_policy.get("passphrase_length", 100)))
        if credentials_policy["ssh_port_mode"] == "manual":
            port = int(credentials_policy["ssh_port"])
        else:
            low, high = credentials_policy["ssh_port_range"]
            port = random_port(int(low), int(high))
        key = ssh_dir / f"vps_{host.id}_ed25519"
        generate_key(key, f"vps-secure-init:{host.id}", passphrase, kdf_rounds=int(credentials_policy["key_kdf_rounds"]))
        session[host.id] = {"managed_user": user, "managed_password": password, "ssh_port": port, "private_key": str(key), "private_key_passphrase": passphrase}
        if save_to_1password:
            vault = policy.get("onepassword_vault", "VPS")
            op = OnePasswordStore(vault)
            op.check()
            ssh_key_item_id = op.create_ssh_key(host.id, str(key), passphrase)
            item_id = op.create_server(host.id, host.address, user, password, port, str(key), passphrase, ssh_key_item_id=ssh_key_item_id)
            session[host.id]["onepassword_item_id"] = item_id
        metadata[host.id] = {"ssh_port": port, "private_key": str(key), "onepassword_item_id": session[host.id].get("onepassword_item_id")}
        host.state = State.CREDENTIALS_READY.value
    cred_path.write_text(json.dumps(metadata, indent=2) + "\n")
    # This file is session material; it is removed at process exit by the caller.
    cred_path.chmod(0o600)
    return session


def select_hosts(hosts: list[Host]) -> list[Host]:
    print("可选主机:")
    for i, host in enumerate(hosts, 1):
        print(f"{i}. {host.id} ({host.address}) [{host.state}]")
    value = input("选择主机（编号逗号分隔，a=全选，q=取消）: ").strip().lower()
    if value in ("q", ""):
        return []
    if value == "a":
        return hosts[:]
    selected = []
    for token in value.split(","):
        try:
            index = int(token.strip()) - 1
            if 0 <= index < len(hosts) and hosts[index] not in selected:
                selected.append(hosts[index])
        except ValueError:
            continue
    return selected


def _credential_refs(root: Path, host: Host, session_credentials: dict[str, dict]) -> dict:
    """Return only non-secret credential references suitable for a plan file."""
    source = session_credentials.get(host.id, {})
    if not source:
        metadata_path = root / "config/credentials.json"
        if metadata_path.exists():
            try:
                source = json.loads(metadata_path.read_text(encoding="utf-8")).get(host.id, {})
            except json.JSONDecodeError:
                source = {}
    references = {}
    mapping = {
        "onepassword_item_id": "onepassword_item_id",
        "private_key": "private_key_path",
        "managed_user": "managed_user",
        "ssh_port": "ssh_port",
    }
    for source_name, reference_name in mapping.items():
        if source.get(source_name) is not None:
            references[reference_name] = source[source_name]
    return references


def build_host_plan(root: Path, host: Host, policy: dict, session_credentials: dict[str, dict]) -> dict:
    """Build a local, non-secret execution-plan preview without writing it."""
    return build_plan(root, host, policy, credential_refs=_credential_refs(root, host, session_credentials))


def _show_plan_summary(plan: dict) -> None:
    resolved = plan["resolved_policy"]
    print(f"计划主机: {plan['host']['id']} ({plan['host']['address']})")
    print(f"profile: {plan['host']['profile']}；凭据引用: {', '.join(plan['credential_refs']) or '尚未生成'}")
    print(
        "SSH: "
        f"LoginGraceTime={resolved['ssh']['login_grace_time']} "
        f"MaxAuthTries={resolved['ssh']['max_auth_tries']} "
        f"MaxSessions={resolved['ssh']['max_sessions']}"
    )
    print(
        "Firewall: "
        f"services={resolved['firewall']['allowed_services']} "
        f"custom-rules={len(resolved['firewall']['allowed_ports'])}；"
        f"Fail2ban: {resolved['fail2ban']['bantime']}/{resolved['fail2ban']['findtime']}/retry={resolved['fail2ban']['maxretry']}"
    )
    print(
        "Controller/report: "
        f"timeout={plan['controller_settings']['connect_timeout']}/"
        f"{plan['controller_settings']['step_timeout']}s "
        f"retries={plan['controller_settings']['transport_retries']} "
        f"formats={plan['report_settings']['formats']}"
    )
    print(f"payload: {len(plan['payload_sha256'])} 个，计划摘要: {plan['plan_sha256']}")


def freeze_host_plan(
    root: Path, host: Host, policy: dict, session_credentials: dict[str, dict], *, preview: dict | None = None
) -> Path:
    """Persist a new immutable plan and attach its identity to runtime state."""
    plan = preview or build_host_plan(root, host, policy, session_credentials)
    path = write_plan(root, plan)
    host.plan_id = plan["plan_id"]
    host.plan_sha256 = plan["plan_sha256"]
    return path


def menu(root: Path):
    hosts, policy, store = setup(root)
    session_credentials = {}
    while True:
        print("\nVPS Secure Init")
        print("1. 查看主机  2. 编辑单台配置  3. 生成凭据  4. 预览/冻结计划  5. 初始化单台  6. 验证主机  7. 保存状态  8. 编辑控制器/报告参数  0. 退出")
        choice = input("选择: ").strip()
        if choice == "1":
            for h in hosts:
                print(f"{h.id:16} {h.address:20} {h.state}")
        elif choice == "2":
            selected = select_hosts(hosts)
            if len(selected) != 1:
                print("请一次只选择一台主机进行交互配置。")
                continue
            original = selected[0]
            updated = edit_host_configuration(original, policy)
            if updated is None:
                print("已取消，配置未改变。")
                continue
            if input("确认写入 config/hosts.yaml？[y/N]: ").strip().lower() not in {"y", "yes"}:
                print("未写入，配置未改变。")
                continue
            hosts[hosts.index(original)] = updated
            save_hosts(root / "config/hosts.yaml", hosts)
            print("主机期望配置已保存；尚未连接 VPS。")
        elif choice == "3":
            selected = select_hosts(hosts)
            if not selected:
                print("未选择主机")
                continue
            try:
                session_credentials.update(generate_credentials(root, selected, policy, save_to_1password=True))
            except OnePasswordError as exc:
                print(f"1Password 保存失败: {exc}")
                continue
            store.save(hosts)
            print("凭据已生成并保存；真实凭据文件已设置 600 权限。")
        elif choice == "4":
            selected = select_hosts(hosts)
            if len(selected) != 1:
                print("请一次只选择一台主机生成执行计划。")
                continue
            host = selected[0]
            try:
                preview = build_host_plan(root, host, policy, session_credentials)
                _show_plan_summary(preview)
                if input("确认冻结为不可变执行计划？[y/N]: ").strip().lower() in {"y", "yes"}:
                    path = freeze_host_plan(root, host, policy, session_credentials, preview=preview)
                    store.save(hosts)
                    print(f"执行计划已冻结: {path}")
                else:
                    print("仅完成预览，未写入执行计划。")
            except PlanError as exc:
                print(f"无法生成执行计划: {exc}")
        elif choice == "5":
            selected = select_hosts(hosts)
            if not selected:
                print("未选择主机")
                continue
            orch = Orchestrator(root, selected, policy, store, session_credentials)
            for host in selected:
                print(f"开始处理 {host.id}，当前状态 {host.state}")
                try:
                    orch.run(host)
                    print(f"{host.id}: 完成")
                except Exception as exc:
                    print(f"{host.id}: 失败（已保留救援入口）: {exc}")
        elif choice == "6":
            selected = select_hosts(hosts)
            if not selected:
                print("未选择主机")
                continue
            orch = Orchestrator(root, selected, policy, store, session_credentials)
            results = []
            for host in selected:
                try:
                    result = orch.audit(host)
                    results.append(result)
                    print(f"{host.id}: non_root={result['non_root']} ssh_port={result['ssh_port_listening']}")
                except Exception as exc:
                    results.append({"host": host.id, "ok": False, "error": str(exc)[:500]})
                    print(f"{host.id}: 验证失败: {exc}")
            if results:
                print(f"审计报告: {write_report(root, results)}")
        elif choice == "7":
            store.save(hosts)
            print("状态已保存。")
        elif choice == "8":
            updated_policy = edit_global_policy(policy)
            if updated_policy is None:
                print("已取消，全局策略未改变。")
                continue
            if input("确认写入 config/policy.yaml？[y/N]: ").strip().lower() not in {"y", "yes"}:
                print("未写入，全局策略未改变。")
                continue
            save_policy(root / "config/policy.yaml", updated_policy)
            policy = updated_policy
            print("全局策略已保存；已有冻结计划不会被修改。")
        elif choice == "0":
            return


def main(argv=None):
    parser = argparse.ArgumentParser(description="Interactive VPS security initialization controller")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--menu", action="store_true")
    args = parser.parse_args(argv)
    menu(args.root)


if __name__ == "__main__":
    main()
