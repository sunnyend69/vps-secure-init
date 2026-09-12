import re
from .ssh_runner import run_ssh


_AUDIT_FIELD = re.compile(r"^VPS_AUDIT_([A-Z0-9_]+)=(.*)$")


def _audit_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = _AUDIT_FIELD.match(line.strip())
        if match:
            fields[match.group(1)] = match.group(2)
    return fields


def validate_host(host, metadata: dict, expected: dict | None = None) -> dict:
    """Read-only validation over the managed SSH connection."""
    key = metadata["private_key"]
    user = metadata.get("managed_user")
    if not user:
        raise RuntimeError(f"当前会话中缺少 {host.id} 用户名")
    port = int(metadata["ssh_port"])
    old_port = int(getattr(host, "initial_port", 22))
    # Every line is a stable, machine-readable observation.  Human-oriented
    # command output is intentionally excluded from the report evidence.
    command = (
        "printf 'VPS_AUDIT_UID=%s\\n' \"$(id -u)\"; "
        f"getent passwd {user} >/dev/null 2>&1 && echo VPS_AUDIT_USER_EXISTS=yes || echo VPS_AUDIT_USER_EXISTS=no; "
        f"user_entry=$(getent passwd {user} 2>/dev/null || true); user_home=$(printf '%s' \"$user_entry\" | awk -F: '{{print $6}}'); user_shell=$(printf '%s' \"$user_entry\" | awk -F: '{{print $7}}'); printf 'VPS_AUDIT_USER_HOME=%s\\nVPS_AUDIT_USER_SHELL=%s\\n' \"$user_home\" \"$user_shell\"; "
        f"id -nG {user} 2>/dev/null | tr ' ' '\\n' | grep -qx sudo && echo VPS_AUDIT_USER_SUDO_GROUP=yes || (id -nG {user} 2>/dev/null | tr ' ' '\\n' | grep -qx wheel && echo VPS_AUDIT_USER_SUDO_GROUP=yes || echo VPS_AUDIT_USER_SUDO_GROUP=no); "
        f"sudo -n stat -c 'VPS_AUDIT_SSH_DIR=%U:%a' \"$(getent passwd {user} | awk -F: '{{print $6}}')/.ssh\" 2>/dev/null || echo VPS_AUDIT_SSH_DIR=missing; "
        f"sudo -n stat -c 'VPS_AUDIT_AUTH_KEYS=%U:%a' \"$(getent passwd {user} | awk -F: '{{print $6}}')/.ssh/authorized_keys\" 2>/dev/null || echo VPS_AUDIT_AUTH_KEYS=missing; "
        "sudo -n stat -c 'VPS_AUDIT_SSH_CONFIG=%U:%a' /etc/ssh/sshd_config.d/00-vps-secure-init.conf 2>/dev/null || echo VPS_AUDIT_SSH_CONFIG=missing; "
        "sudo -n stat -c 'VPS_AUDIT_F2B_CONFIG=%U:%a' /etc/fail2ban/jail.d/99-vps-secure-init.local 2>/dev/null || echo VPS_AUDIT_F2B_CONFIG=missing; "
        "sudo -n awk '/VPS_INIT_AUDIT/{found=1} END{print \"VPS_AUDIT_SUDO_MODE=\" (found ? \"command-allowlist\" : \"nopasswd-all\")}' /etc/sudoers.d/90-vps-secure-init-managed 2>/dev/null || echo VPS_AUDIT_SUDO_MODE=missing; "
        f"sudo -n passwd -S {user} 2>/dev/null | awk '{{print \"VPS_AUDIT_USER_PASSWORD_STATE=\"$2}}'; "
        f"sudo -n /usr/sbin/sshd -t >/dev/null 2>&1 && echo VPS_AUDIT_SSHD_SYNTAX=pass || echo VPS_AUDIT_SSHD_SYNTAX=fail; "
        f"sudo -n /usr/sbin/sshd -T -C user={user},host=localhost,addr=127.0.0.1 2>/dev/null | awk '$1==\"port\"{{print \"VPS_AUDIT_SSHD_PORT=\"$2; next}} $1==\"permitrootlogin\"{{print \"VPS_AUDIT_SSHD_ROOT=\"$2}} $1==\"passwordauthentication\"{{print \"VPS_AUDIT_SSHD_PASSWORD=\"$2}} $1==\"allowtcpforwarding\"{{print \"VPS_AUDIT_SSHD_TCP_FORWARD=\"$2}} $1==\"allowagentforwarding\"{{print \"VPS_AUDIT_SSHD_AGENT_FORWARD=\"$2}} $1==\"x11forwarding\"{{print \"VPS_AUDIT_SSHD_X11_FORWARD=\"$2}} $1==\"logingracetime\"{{print \"VPS_AUDIT_SSHD_LOGIN_GRACE=\"$2}} $1==\"maxauthtries\"{{print \"VPS_AUDIT_SSHD_MAX_AUTH=\"$2}} $1==\"maxsessions\"{{print \"VPS_AUDIT_SSHD_MAX_SESSIONS=\"$2}} $1==\"clientaliveinterval\"{{print \"VPS_AUDIT_SSHD_ALIVE_INTERVAL=\"$2}} $1==\"clientalivecountmax\"{{print \"VPS_AUDIT_SSHD_ALIVE_COUNT=\"$2}}'; "
        f"ss -ltn | awk '$4 ~ /(:|\\]){port}$/{{found=1}} $4 ~ /(:|\\]){old_port}$/{{old=1}} END{{print \"VPS_AUDIT_MANAGED_LISTENER=\"(found ? \"yes\" : \"no\"); print \"VPS_AUDIT_OLD_LISTENER=\"(old ? \"yes\" : \"no\")}}'; "
        "sudo -n ufw status verbose 2>/dev/null | awk 'NR==1{{print \"VPS_AUDIT_UFW_ACTIVE=\"($2==\"active\" ? \"yes\" : \"no\")}}'; "
        "sudo -n awk -F= '/^IPV6=/{gsub(/[[:space:]]/, \"\", $2); print \"VPS_AUDIT_UFW_IPV6=\" $2}' /etc/default/ufw 2>/dev/null || true; "
        f"sudo -n ufw status 2>/dev/null | grep -Eq '^{port}/tcp[[:space:]]+(ALLOW|LIMIT)' && echo VPS_AUDIT_UFW_MANAGED=yes || echo VPS_AUDIT_UFW_MANAGED=no; "
        f"sudo -n ufw status 2>/dev/null | grep -Eq '^{old_port}/tcp[[:space:]]' && echo VPS_AUDIT_UFW_OLD=yes || echo VPS_AUDIT_UFW_OLD=no; "
        "for service_port in 80 443; do sudo -n ufw status 2>/dev/null | grep -Eq \"^${service_port}/tcp[[:space:]]+ALLOW\" && printf 'VPS_AUDIT_UFW_SERVICE_%s=yes\\n' \"$service_port\" || printf 'VPS_AUDIT_UFW_SERVICE_%s=no\\n' \"$service_port\"; done; "
        "sudo -n systemctl is-active --quiet fail2ban && echo VPS_AUDIT_FAIL2BAN_ACTIVE=yes || echo VPS_AUDIT_FAIL2BAN_ACTIVE=no; "
        "sudo -n systemctl is-enabled --quiet fail2ban && echo VPS_AUDIT_FAIL2BAN_ENABLED=yes || echo VPS_AUDIT_FAIL2BAN_ENABLED=no; "
        "sudo -n fail2ban-client status sshd >/dev/null 2>&1 && echo VPS_AUDIT_FAIL2BAN_JAIL=yes || echo VPS_AUDIT_FAIL2BAN_JAIL=no; "
        "for setting in bantime findtime maxretry backend ignoreip; do "
        "value=$(sudo -n awk -F= -v key=\"$setting\" '$1 ~ \"^[[:space:]]*\" key \"[[:space:]]*$\" {gsub(/^[[:space:]]+|[[:space:]]+$/, \"\", $2); print $2; exit}' /etc/fail2ban/jail.d/99-vps-secure-init.local 2>/dev/null || true); "
        "printf 'VPS_AUDIT_FAIL2BAN_%s=%s\\n' \"$(printf '%s' \"$setting\" | tr '[:lower:]' '[:upper:]')\" \"$value\"; done"
    )
    custom_rules = (expected or {}).get("firewall", {}).get("allowed_ports", [])
    for index, rule in enumerate(custom_rules):
        # Port/protocol are normalized by policy validation before reaching
        # this function; rule source is also restricted to IP/CIDR or ``any``.
        port_rule = f"{rule['port']}/{rule['protocol']}"
        if rule["source"] == "any":
            probe = f"grep -F '{port_rule}'"
        else:
            probe = f"grep -F '{port_rule}' | grep -F '{rule['source']}'"
        command += f"; sudo -n ufw status 2>/dev/null | {probe} >/dev/null && echo VPS_AUDIT_UFW_RULE_{index}=yes || echo VPS_AUDIT_UFW_RULE_{index}=no"
    controller = (expected or {}).get("controller", {})
    host_key_policy = controller.get("host_key_policy", "accept-new-then-pin")
    if host_key_policy == "accept-new-then-pin":
        host_key_policy = "accept-new"
    result = run_ssh(
        host.address, port, user, command,
        key=key,
        key_passphrase=metadata.get("private_key_passphrase"),
        timeout=int(controller.get("connect_timeout", 60)),
        host_key_policy=host_key_policy,
    )
    text = result.stdout
    fields = _audit_fields(text)
    return {
        "host": host.id,
        "port": port,
        "user": user,
        "non_root": fields.get("UID") not in {None, "0"},
        "ssh_port_listening": fields.get("MANAGED_LISTENER") == "yes",
        "fields": fields,
        "raw": text,
    }
