import base64
import json
from pathlib import Path
from getpass import getpass
from .models import Host, State
from .payload_manager import PayloadManager
from .ssh_runner import run_ssh
from .validator import validate_host
from .onepassword import OnePasswordStore, OnePasswordError
from .credentials import MANAGED_USERNAME_LENGTH, is_valid_linux_username, random_username
from .platforms import parse_linux_capabilities, validate_linux_capabilities
from .plan import PlanError, load_execution_plan
from .report import acceptance_check, build_acceptance_report, write_acceptance_reports, write_change_archive
from .ssh_config import upsert_host_config


class Orchestrator:
    def __init__(self, root: Path, hosts: list[Host], policy: dict, store,
                 session_credentials: dict | None = None):
        self.root, self.hosts, self.policy, self.store = root, hosts, policy, store
        self.payloads = PayloadManager(root)
        self.credentials = session_credentials or self._load_metadata()

    def _load_metadata(self):
        path = self.root / "config/credentials.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def _creds(self, host: Host):
        meta = self.credentials.get(host.id)
        if not meta:
            raise RuntimeError(f"主机 {host.id} 尚未生成凭据")
        needed = {"managed_user", "managed_password", "private_key_passphrase"}
        if not needed.issubset(meta) or not all(meta.get(name) for name in needed):
            item_id = meta.get("onepassword_item_id")
            if not item_id:
                raise RuntimeError(f"当前会话没有 {host.id} 的敏感凭据，且没有 1Password 条目 ID")
            print(f"[{host.id}] 正在从 1Password 读取恢复所需凭据…", flush=True)
            try:
                meta.update(
                    OnePasswordStore(self.policy.get("onepassword_vault", "VPS"))
                    .read_server_credentials(item_id)
                )
            except OnePasswordError as exc:
                raise RuntimeError(f"无法从 1Password 载入 {host.id} 凭据: {exc}") from exc
            if not all(meta.get(name) for name in needed):
                raise RuntimeError(f"1Password 项目缺少 {host.id} 的用户名、密码或私钥 passphrase")

        # v0.1.0 used a 64-character username policy. Ubuntu 22.04
        # shadow-utils rejects such names. Repair legacy credentials before any
        # remote mutation and persist the corrected username back to 1Password,
        # while retaining the existing password, SSH key and port.
        if not is_valid_linux_username(meta.get("managed_user", "")):
            item_id = meta.get("onepassword_item_id")
            if not item_id:
                raise RuntimeError(
                    f"{host.id} 的受管用户名不符合 Linux useradd 规则，且无法更新 1Password 条目"
                )
            credentials_policy = self.policy.get("credentials", self.policy)
            replacement_user = random_username(int(credentials_policy.get("username_length", MANAGED_USERNAME_LENGTH)))
            print(
                f"[{host.id}] 检测到旧版不兼容的受管用户名，正在安全迁移为兼容用户名…",
                flush=True,
            )
            try:
                OnePasswordStore(self.policy.get("onepassword_vault", "VPS")).update_server_username(
                    item_id, replacement_user
                )
            except OnePasswordError as exc:
                raise RuntimeError(f"无法修复 {host.id} 的 1Password 用户名: {exc}") from exc
            meta["managed_user"] = replacement_user

        return meta

    def _initial_password(self, host: Host):
        if host.initial_auth != "password":
            return None
        print(
            f"[{host.id}] 将使用初始密码连接 "
            f"{host.initial_user}@{host.address}:{host.initial_port}",
            flush=True,
        )
        value = getpass(f"输入 {host.id} 的初始 SSH 密码（不会显示）: ")
        if not value:
            raise RuntimeError("初始密码不能为空")
        return value

    def _save(self):
        self.store.save(self.hosts)

    @staticmethod
    def _resume_step(host: Host) -> str:
        state = host.resume_state or host.state
        # Old releases could falsely advance through pre-verify steps. Any
        # failure before a proven managed login is therefore safely replayed
        # from preflight. FIREWALL_VERIFIED is intentionally excluded because
        # reaching it requires a successful managed-login check in current
        # releases, and v0.1.3 must be able to repair v0.1.2 UFW LIMIT rules.
        if host.state == State.FAILED.value and state in {
            State.PREFLIGHT_OK.value,
            State.BOOTSTRAPPED.value,
            State.DUAL_SSH_READY.value,
        }:
            state = State.CREDENTIALS_READY.value
        resume_map = {
            State.NEW.value: "preflight",
            State.CREDENTIALS_READY.value: "preflight",
            State.PREFLIGHT_OK.value: "bootstrap",
            State.BOOTSTRAPPED.value: "ssh_hardening",
            State.DUAL_SSH_READY.value: "verify",
            State.NEW_LOGIN_VERIFIED.value: "firewall",
            # Re-run firewall when recovering from this state. v0.1.2 used
            # UFW LIMIT during transition, which can rate-limit the controller's
            # own burst of SSH/SCP sessions. The idempotent firewall payload in
            # v0.1.3 converts legacy LIMIT rules back to transition ALLOW first.
            State.FIREWALL_VERIFIED.value: "firewall",
            State.FAIL2BAN_VERIFIED.value: "finalize",
        }
        return resume_map.get(state, "preflight")

    def _verify_managed_login(self, host: Host, creds: dict) -> None:
        run_ssh(
            host.address,
            int(creds["ssh_port"]),
            creds["managed_user"],
            'test "$(id -u)" -ne 0 && sudo -n true',
            key=creds["private_key"],
            key_passphrase=creds["private_key_passphrase"],
            timeout=getattr(self, "connect_timeout", 60),
            host_key_policy=getattr(self, "host_key_policy", "accept-new"),
        )

    def _security_variables(self, managed_user: str, managed_port: int, effective_policy: dict | None = None) -> dict[str, str]:
        """Translate the public policy into the exact SSH payload inputs."""
        ssh_policy = (effective_policy or {}).get("ssh", self.policy)
        fail2ban_policy = (effective_policy or {}).get("fail2ban", {})
        firewall_policy = (effective_policy or {}).get("firewall", {})

        def ssh_boolean(name: str, default: bool = False) -> str:
            value = ssh_policy.get(name, default)
            if not isinstance(value, bool):
                raise RuntimeError(f"策略 {name} 必须是 true 或 false")
            return "yes" if value else "no"

        def policy_integer(section: dict, name: str, default: int) -> str:
            value = section.get(name, default)
            if isinstance(value, bool) or not isinstance(value, int):
                raise RuntimeError(f"策略 {name} 必须是整数")
            return str(value)

        allowed_ports = firewall_policy.get("allowed_ports", [])
        encoded_rules = base64.b64encode(
            "".join(
                f"{rule['port']}\t{rule['protocol']}\t{rule['source']}\t{rule['comment']}\n"
                for rule in allowed_ports
            ).encode("utf-8")
        ).decode("ascii")

        return {
            "MANAGED_USER": managed_user,
            "NEW_SSH_PORT": str(managed_port),
            "ALLOW_TCP_FORWARDING": ssh_boolean("allow_tcp_forwarding"),
            "ALLOW_AGENT_FORWARDING": ssh_boolean("allow_agent_forwarding"),
            "X11_FORWARDING": ssh_boolean("x11_forwarding"),
            "LOGIN_GRACE_TIME": policy_integer(ssh_policy, "login_grace_time", 45),
            "MAX_AUTH_TRIES": policy_integer(ssh_policy, "max_auth_tries", 5),
            "MAX_SESSIONS": policy_integer(ssh_policy, "max_sessions", 5),
            "CLIENT_ALIVE_INTERVAL": policy_integer(ssh_policy, "client_alive_interval", 300),
            "CLIENT_ALIVE_COUNT_MAX": policy_integer(ssh_policy, "client_alive_count_max", 3),
            "FAIL2BAN_BANTIME": str(fail2ban_policy.get("bantime", "1h")),
            "FAIL2BAN_FINDTIME": str(fail2ban_policy.get("findtime", "10m")),
            "FAIL2BAN_MAXRETRY": policy_integer(fail2ban_policy, "maxretry", 5),
            "FAIL2BAN_BACKEND": str(fail2ban_policy.get("backend", "auto")),
            "FAIL2BAN_IGNOREIP": " ".join(fail2ban_policy.get("ignoreip", [])),
            "FAIL2BAN_SSH_SERVICE": str(getattr(self, "_current_host_ssh_service", "ssh")),
            "FIREWALL_SSH_RATE_LIMIT": "yes" if firewall_policy.get("ssh_rate_limit", True) else "no",
            "FIREWALL_IPV6_MODE": str(firewall_policy.get("ipv6_mode", "auto")),
            "SUDO_FINAL_MODE": str((effective_policy or {}).get("sudo", {}).get("final_mode", "nopasswd-all")),
            "FIREWALL_ALLOWED_SERVICES": ",".join(firewall_policy.get("allowed_services", [])),
            "FIREWALL_ALLOWED_PORTS_B64": encoded_rules,
            "SSH_SOCKET_MODE": "yes" if getattr(self, "_current_host_ssh_socket", False) else "no",
        }

    def _execution_contract(self, host: Host) -> tuple[dict, dict]:
        """Freeze all mutable execution inputs before opening an SSH connection."""
        try:
            plan = load_execution_plan(self.root, host)
        except PlanError as exc:
            raise RuntimeError(f"{exc}；请先在菜单中预览并冻结计划") from exc
        controller = plan["controller_settings"]
        self.connect_timeout = int(controller.get("connect_timeout", 30))
        self.host_key_policy = str(controller.get("host_key_policy", "accept-new-then-pin"))
        if self.host_key_policy == "accept-new-then-pin":
            self.host_key_policy = "accept-new"
        self.payloads.timeout = int(controller.get("step_timeout", 300))
        self.payloads.transport_retries = int(controller.get("transport_retries", 1))
        self.payloads.host_key_policy = self.host_key_policy
        return plan, plan["resolved_policy"]

    def _write_final_acceptance_report(self, host: Host, creds: dict, plan: dict, effective_policy: dict) -> dict:
        """Perform the current read-only acceptance probes and persist both reports."""
        expected = dict(effective_policy)
        expected["controller"] = plan["controller_settings"]
        observed = validate_host(host, creds, expected=expected)
        fields = observed["fields"]
        ssh = effective_policy["ssh"]
        expected_ssh = {
            "SSHD_ROOT": "no", "SSHD_PASSWORD": "no",
            "SSHD_TCP_FORWARD": "yes" if ssh["allow_tcp_forwarding"] else "no",
            "SSHD_AGENT_FORWARD": "yes" if ssh["allow_agent_forwarding"] else "no",
            "SSHD_X11_FORWARD": "yes" if ssh["x11_forwarding"] else "no",
            "SSHD_LOGIN_GRACE": str(ssh["login_grace_time"]),
            "SSHD_MAX_AUTH": str(ssh["max_auth_tries"]),
            "SSHD_MAX_SESSIONS": str(ssh["max_sessions"]),
            "SSHD_ALIVE_INTERVAL": str(ssh["client_alive_interval"]),
            "SSHD_ALIVE_COUNT": str(ssh["client_alive_count_max"]),
        }
        checks = [
            acceptance_check("user.exists", "critical", "yes", fields.get("USER_EXISTS"), fields.get("USER_EXISTS") == "yes", "getent passwd"),
            acceptance_check("connection.non_root", "critical", True, observed["non_root"], observed["non_root"], "id -u"),
            acceptance_check("user.home", "high", f"/home/{creds['managed_user']}", fields.get("USER_HOME"), fields.get("USER_HOME") == f"/home/{creds['managed_user']}", "getent passwd"),
            acceptance_check("user.shell", "medium", "/bin/bash", fields.get("USER_SHELL"), fields.get("USER_SHELL") == "/bin/bash", "getent passwd"),
            acceptance_check("user.sudo_group", "critical", "yes", fields.get("USER_SUDO_GROUP"), fields.get("USER_SUDO_GROUP") == "yes", "id -nG"),
            acceptance_check("user.password_state", "medium", "P", fields.get("USER_PASSWORD_STATE"), fields.get("USER_PASSWORD_STATE") == "P", "passwd -S"),
            acceptance_check("sudo.final_mode", "high", effective_policy["sudo"]["final_mode"], fields.get("SUDO_MODE"), fields.get("SUDO_MODE") == effective_policy["sudo"]["final_mode"], "sudoers managed entry"),
            acceptance_check("user.ssh_dir", "high", f"{creds['managed_user']}:700", fields.get("SSH_DIR"), fields.get("SSH_DIR") == f"{creds['managed_user']}:700", "stat .ssh"),
            acceptance_check("user.authorized_keys", "high", f"{creds['managed_user']}:600", fields.get("AUTH_KEYS"), fields.get("AUTH_KEYS") == f"{creds['managed_user']}:600", "stat authorized_keys"),
            acceptance_check("files.ssh_config", "high", "root:644", fields.get("SSH_CONFIG"), fields.get("SSH_CONFIG") == "root:644", "stat sshd drop-in"),
            acceptance_check("files.fail2ban_config", "high", "root:644", fields.get("F2B_CONFIG"), fields.get("F2B_CONFIG") == "root:644", "stat fail2ban jail"),
            acceptance_check("ssh.syntax", "critical", "pass", fields.get("SSHD_SYNTAX"), fields.get("SSHD_SYNTAX") == "pass", "sshd -t"),
            acceptance_check("ssh.managed_port", "critical", str(creds["ssh_port"]), fields.get("SSHD_PORT"), fields.get("SSHD_PORT") == str(creds["ssh_port"]), "sshd -T port"),
            acceptance_check("ssh.managed_listener", "critical", "yes", fields.get("MANAGED_LISTENER"), fields.get("MANAGED_LISTENER") == "yes", "ss -ltn"),
            acceptance_check("ssh.old_listener", "critical", "no", fields.get("OLD_LISTENER"), fields.get("OLD_LISTENER") == "no", "ss -ltn"),
        ]
        for name, expected in expected_ssh.items():
            checks.append(acceptance_check(
                f"ssh.{name.lower()}", "high", expected, fields.get(name), fields.get(name) == expected, "sshd -T effective configuration"
            ))
        checks.extend([
            acceptance_check("ufw.active", "critical", "yes", fields.get("UFW_ACTIVE"), fields.get("UFW_ACTIVE") == "yes", "ufw status"),
            acceptance_check("ufw.ipv6", "medium", "yes" if effective_policy["firewall"]["ipv6_mode"] == "enabled" else "no" if effective_policy["firewall"]["ipv6_mode"] == "disabled" else fields.get("UFW_IPV6"), fields.get("UFW_IPV6"), effective_policy["firewall"]["ipv6_mode"] == "auto" or fields.get("UFW_IPV6") == ("yes" if effective_policy["firewall"]["ipv6_mode"] == "enabled" else "no"), "/etc/default/ufw"),
            acceptance_check("ufw.managed_port", "high", "yes", fields.get("UFW_MANAGED"), fields.get("UFW_MANAGED") == "yes", "ufw status"),
            acceptance_check("ufw.old_port", "high", "no", fields.get("UFW_OLD"), fields.get("UFW_OLD") == "no", "ufw status"),
            acceptance_check("fail2ban.active", "high", "yes", fields.get("FAIL2BAN_ACTIVE"), fields.get("FAIL2BAN_ACTIVE") == "yes", "systemctl is-active fail2ban"),
            acceptance_check("fail2ban.enabled", "medium", "yes", fields.get("FAIL2BAN_ENABLED"), fields.get("FAIL2BAN_ENABLED") == "yes", "systemctl is-enabled fail2ban"),
            acceptance_check("fail2ban.sshd_jail", "high", "yes", fields.get("FAIL2BAN_JAIL"), fields.get("FAIL2BAN_JAIL") == "yes", "fail2ban-client status sshd"),
        ])
        service_ports = {"http": "80", "https": "443"}
        for service in effective_policy["firewall"]["allowed_services"]:
            service_port = service_ports[service]
            field = f"UFW_SERVICE_{service_port}"
            checks.append(acceptance_check(
                f"ufw.service.{service}", "medium", "yes", fields.get(field), fields.get(field) == "yes", "ufw status"
            ))
        for index, rule in enumerate(effective_policy["firewall"]["allowed_ports"]):
            field = f"UFW_RULE_{index}"
            checks.append(acceptance_check(
                f"ufw.custom_rule.{index}", "medium", "yes", fields.get(field), fields.get(field) == "yes", "ufw status"
            ))
        fail2ban = effective_policy["fail2ban"]
        effective_fail2ban_backend = fail2ban["backend"]
        if effective_fail2ban_backend == "auto":
            effective_fail2ban_backend = "systemd" if host.capabilities.get("journal_available") else "polling"
        expected_fail2ban = {
            "FAIL2BAN_BANTIME": str(fail2ban["bantime"]),
            "FAIL2BAN_FINDTIME": str(fail2ban["findtime"]),
            "FAIL2BAN_MAXRETRY": str(fail2ban["maxretry"]),
            "FAIL2BAN_BACKEND": str(effective_fail2ban_backend),
            "FAIL2BAN_IGNOREIP": " ".join(fail2ban["ignoreip"]),
        }
        for name, expected in expected_fail2ban.items():
            checks.append(acceptance_check(
                f"fail2ban.{name.removeprefix('FAIL2BAN_').lower()}", "medium", expected,
                fields.get(name), fields.get(name) == expected, "项目管理的 Fail2ban jail 配置"
            ))
        report = build_acceptance_report(
            host.id, host.address, checks, plan=plan,
            address_display=plan["report_settings"].get("address_display", "masked"),
        )
        if plan["report_settings"].get("include_raw_evidence"):
            # Never persist the unfiltered SSH transcript.  The optional raw
            # channel is a bounded, machine-readable field map instead.
            report["raw_evidence"] = {"format": "structured-fields", "fields": dict(fields)}
        paths = write_acceptance_reports(self.root, report)
        print(f"[{host.id}] 最终验收报告: {' / '.join(str(path) for path in paths.values())}", flush=True)
        return report

    def run(self, host: Host, start: str | None = None):
        plan, effective_policy = self._execution_contract(host)
        self._current_host_ssh_service = host.capabilities.get("ssh_service", "ssh")
        self._current_host_ssh_socket = bool(host.capabilities.get("ssh_socket_active") or host.capabilities.get("ssh_socket_enabled"))
        c = self._creds(host)
        # A completed frozen plan must never be replayed from the provider's
        # retired rescue endpoint.  Re-running it is instead a read-only
        # acceptance refresh and produces fresh evidence/report files.
        if host.state == State.COMPLETED.value and start is None:
            report = self._write_final_acceptance_report(host, c, plan, effective_policy)
            if report["overall_status"] != "PASS":
                raise RuntimeError("已完成主机的重新验收未通过；请查看验收报告")
            return
        if start is None and host.state == State.FAILED.value and host.resume_state in {
            State.NEW_LOGIN_VERIFIED.value, State.FIREWALL_VERIFIED.value, State.FAIL2BAN_VERIFIED.value,
        }:
            # A later-step state claims the managed endpoint was already proven.
            # If that endpoint is no longer usable, do not blindly reconnect to
            # a possibly retired rescue port; require an explicit operator
            # recovery decision instead.
            try:
                self._verify_managed_login(host, c)
            except Exception as exc:
                host.state = State.MANUAL.value
                host.last_error = f"恢复前 managed SSH 对账失败: {exc}"[:500]
                self._save()
                raise RuntimeError("远端状态与本地恢复状态冲突，已转人工处理") from exc
        pub = Path(c["private_key"] + ".pub").read_text().strip()
        key = c["private_key"]
        key_passphrase = c["private_key_passphrase"]
        managed_port = int(c["ssh_port"])
        managed_user = c["managed_user"]
        steps = ["preflight", "bootstrap", "ssh_hardening", "verify", "firewall", "fail2ban", "finalize"]

        if start is None:
            start = self._resume_step(host)
        if start in steps:
            steps = steps[steps.index(start):]

        # The original provider password is required only while the old rescue
        # connection is used. After verify, every privileged step uses the new
        # managed key endpoint plus sudo -n.
        initial_password = (
            self._initial_password(host)
            if any(step in {"preflight", "bootstrap", "ssh_hardening"} for step in steps)
            else None
        )

        try:
            for step in steps:
                print(f"[{host.id}] 开始: {step}", flush=True)
                variables = self._security_variables(managed_user, managed_port, effective_policy)
                variables.update({
                    "MANAGED_PASSWORD": c["managed_password"],
                    "PUBLIC_KEY": pub,
                })

                if step == "preflight":
                    result = self.payloads.execute(
                        host, step, {}, host.initial_port, host.initial_user,
                        host.initial_key, initial_password,
                    )
                    snapshot = parse_linux_capabilities(result.stdout)
                    validate_linux_capabilities(
                        snapshot,
                        {"platforms": {"supported": plan["supported_platforms"]}},
                        host.platform,
                        allow_bootstrap_sudo=(host.initial_user == "root"),
                    )
                    host.detected_platform = snapshot.platform
                    host.capabilities = snapshot.to_dict()
                    host.state = State.PREFLIGHT_OK.value

                elif step == "bootstrap":
                    self.payloads.execute(
                        host, step, variables, host.initial_port, host.initial_user,
                        host.initial_key, initial_password,
                    )
                    host.state = State.BOOTSTRAPPED.value

                elif step == "ssh_hardening":
                    self.payloads.execute(
                        host, step, variables, host.initial_port, host.initial_user,
                        host.initial_key, initial_password,
                    )
                    host.state = State.DUAL_SSH_READY.value

                elif step == "verify":
                    print(
                        f"[{host.id}] 正在以新用户和新端口建立独立验证连接…",
                        flush=True,
                    )
                    self._verify_managed_login(host, c)
                    host.state = State.NEW_LOGIN_VERIFIED.value

                elif step == "firewall":
                    self.payloads.execute(
                        host, step, variables, managed_port, managed_user, key,
                        key_passphrase=key_passphrase,
                    )
                    print(f"[{host.id}] 正在验证启用防火墙后的新 SSH 入口…", flush=True)
                    self._verify_managed_login(host, c)
                    host.state = State.FIREWALL_VERIFIED.value

                elif step == "fail2ban":
                    self.payloads.execute(
                        host, step, variables, managed_port, managed_user, key,
                        key_passphrase=key_passphrase,
                    )
                    host.state = State.FAIL2BAN_VERIFIED.value

                elif step == "finalize":
                    self.payloads.execute(
                        host, step, variables, managed_port, managed_user, key,
                        key_passphrase=key_passphrase,
                    )
                    print(f"[{host.id}] 正在验证最终 key-only SSH 入口…", flush=True)
                    self._verify_managed_login(host, c)
                    host.state = State.OLD_PORT_REMOVED.value

                self._save()
                print(f"[{host.id}] 完成: {step}", flush=True)

            final_report = self._write_final_acceptance_report(host, c, plan, effective_policy)
            if final_report["overall_status"] != "PASS":
                raise RuntimeError("最终验收未通过；请查看已生成的验收报告")
            config_path, config_backup = upsert_host_config(
                host.id, host.address, int(c["ssh_port"]), c["managed_user"], c["private_key"]
            )
            print(f"[{host.id}] 本机 SSH config 已更新: {config_path}", flush=True)
            if config_backup:
                print(f"[{host.id}] 本机 SSH config 已备份: {config_backup}", flush=True)
            change_paths = write_change_archive(
                self.root, host.id, host.address, plan, effective_policy,
                managed_user=c["managed_user"], ssh_port=int(c["ssh_port"]),
                private_key_path=c["private_key"],
            )
            print(f"[{host.id}] 配置变更档案: {' / '.join(str(path) for path in change_paths.values())}", flush=True)
            host.state = State.COMPLETED.value
            host.resume_state = None
            host.last_error = None
            self._save()

        except Exception as exc:
            host.resume_state = host.state
            host.state = State.FAILED.value
            host.last_error = str(exc)[:500]
            self._save()
            raise

    def audit(self, host: Host) -> dict:
        return validate_host(host, self._creds(host))
