import hashlib
import re
import shlex
import tempfile
from pathlib import Path
from .ssh_runner import copy_file, run_ssh


class PayloadError(RuntimeError):
    pass


class PayloadManager:
    def __init__(self, root: Path, timeout: int = 120, *, host_key_policy: str = "accept-new", transport_retries: int = 0):
        self.root = root
        self.payload_dir = root / "payloads"
        self.timeout = timeout
        self.host_key_policy = host_key_policy
        self.transport_retries = transport_retries

    def _run_ssh(self, *args, retry: bool = True, **kwargs):
        last_error = None
        attempts = self.transport_retries + 1 if retry else 1
        for attempt in range(attempts):
            try:
                return run_ssh(*args, **kwargs, host_key_policy=self.host_key_policy)
            except Exception as exc:
                last_error = exc
                if attempt >= self.transport_retries:
                    raise
        raise last_error  # pragma: no cover

    def _copy_file(self, *args, retry: bool = True, **kwargs):
        last_error = None
        attempts = self.transport_retries + 1 if retry else 1
        for attempt in range(attempts):
            try:
                return copy_file(*args, **kwargs, host_key_policy=self.host_key_policy)
            except Exception as exc:
                last_error = exc
                if attempt >= self.transport_retries:
                    raise
        raise last_error  # pragma: no cover

    @staticmethod
    def _safe_token(value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
        return (cleaned or "host")[:48]

    @staticmethod
    def _validate_protocol(step: str, output: str) -> None:
        fields: dict[str, str] = {}
        for raw_line in output.splitlines():
            line = raw_line.strip().strip("\r")
            if line.startswith("VPS_INIT_") and "=" in line:
                name, value = line.split("=", 1)
                fields[name] = value
        expected = {
            "VPS_INIT_PROTOCOL": "1",
            "VPS_INIT_STEP": step,
            "VPS_INIT_RESULT": "ok",
        }
        missing = [f"{name}={value}" for name, value in expected.items() if fields.get(name) != value]
        if missing:
            tail = "\n".join(output.splitlines()[-12:]).strip()
            detail = f"；远端输出末尾: {tail}" if tail else ""
            raise PayloadError(f"{step} 未返回有效成功协议（缺少/不匹配: {', '.join(missing)}）{detail}")

    def execute(self, host, step: str, variables: dict[str, str], port: int,
                user: str, key: str | None, password: str | None = None,
                key_passphrase: str | None = None):
        local = self.payload_dir / f"{step}.sh"
        common = self.payload_dir / "common.sh"
        if not local.exists():
            raise PayloadError(f"payload 不存在: {step}")
        if not common.exists():
            raise PayloadError("payload 公共脚本不存在: common.sh")

        script_digest = hashlib.sha256(local.read_bytes()).hexdigest()
        common_digest = hashlib.sha256(common.read_bytes()).hexdigest()
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="vps-init-vars-", delete=False) as vf:
            for name, value in variables.items():
                if "\n" in value or "\r" in value:
                    raise PayloadError(f"变量包含换行符: {name}")
                vf.write(f"{name}={shlex.quote(value)}\n")
            var_file = Path(vf.name)

        token = self._safe_token(host.id)
        remote_dir = f"/tmp/.vps-secure-init-{token}-{step}"
        remote_script = f"{remote_dir}/step.sh"
        remote_common = f"{remote_dir}/common.sh"
        remote_vars = f"{remote_dir}/vars.env"
        qdir = shlex.quote(remote_dir)

        try:
            print(f"[{host.id}] 创建远端临时目录…", flush=True)
            self._run_ssh(host.address, port, user, f"umask 077; rm -rf {qdir}; mkdir -m 700 {qdir}",
                          key, password, key_passphrase, self.timeout)
            print(f"[{host.id}] 上传 {step} 脚本及 common.sh…", flush=True)
            self._copy_file(host.address, port, user, local, remote_script, key, password, key_passphrase, self.timeout)
            self._copy_file(host.address, port, user, common, remote_common, key, password, key_passphrase, self.timeout)
            print(f"[{host.id}] 上传 {step} 参数…", flush=True)
            self._copy_file(host.address, port, user, var_file, remote_vars, key, password, key_passphrase, self.timeout)

            inner = (
                f"set -a; . {shlex.quote(remote_vars)}; set +a; "
                f"bash {shlex.quote(remote_script)}"
            )
            execute = inner if user == "root" else f"sudo -n bash -c {shlex.quote(inner)}"
            command = (
                f"chmod 700 {shlex.quote(remote_script)} {shlex.quote(remote_common)}; "
                f"chmod 600 {shlex.quote(remote_vars)}; "
                f"printf '%s  %s\\n' {script_digest} {shlex.quote(remote_script)} | sha256sum -c - >/dev/null || exit 70; "
                f"printf '%s  %s\\n' {common_digest} {shlex.quote(remote_common)} | sha256sum -c - >/dev/null || exit 71; "
                f"{execute}; rc=$?; rm -rf {qdir}; exit $rc"
            )
            print(f"[{host.id}] 远端执行 {step}（最长 {self.timeout} 秒）…", flush=True)
            result = self._run_ssh(host.address, port, user, command, key, password, key_passphrase, self.timeout, retry=False)
            self._validate_protocol(step, result.stdout)
            print(f"[{host.id}] 远端 {step} 返回成功并通过协议校验", flush=True)
            return result
        finally:
            var_file.unlink(missing_ok=True)
