import subprocess
from pathlib import Path


class SSHError(RuntimeError):
    pass


def _pexpect_status(child) -> int:
    """Close a pexpect child and return its real process status."""
    child.close()
    if child.exitstatus is not None:
        return int(child.exitstatus)
    if child.signalstatus is not None:
        return 128 + int(child.signalstatus)
    raise SSHError("无法取得 SSH/SCP 子进程退出状态")


def _run_key_ssh(args: list[str], passphrase: str, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        import pexpect
    except ImportError as exc:
        raise SSHError("带 passphrase 的私钥需要安装 pexpect") from exc

    # A protected local key needs one local passphrase prompt. BatchMode must be
    # disabled for that prompt, while IdentitiesOnly keeps large SSH agents
    # (for example 1Password) from offering unrelated keys.
    interactive_args = ["BatchMode=no" if value == "BatchMode=yes" else value for value in args[1:]]
    child = pexpect.spawn(args[0], interactive_args, encoding="utf-8", timeout=timeout)
    output: list[str] = []
    try:
        while True:
            index = child.expect([r"(?i)enter passphrase for key.*:", pexpect.EOF, pexpect.TIMEOUT])
            output.append(child.before or "")
            if index == 0:
                child.sendline(passphrase)
            elif index == 1:
                break
            else:
                raise SSHError("SSH 私钥解锁或连接超时")
        status = _pexpect_status(child)
        text = "".join(output)
        if status != 0:
            raise SSHError(text.strip() or f"SSH/SCP 私钥认证失败 (exit {status})")
        return subprocess.CompletedProcess(args, 0, text, "")
    finally:
        if child.isalive():
            child.close(force=True)


def run_ssh(host: str, port: int, user: str, command: str, key: str | None = None,
            password: str | None = None, key_passphrase: str | None = None,
            timeout: int = 60, host_key_policy: str = "accept-new") -> subprocess.CompletedProcess[str]:
    if host_key_policy not in {"accept-new", "pinned"}:
        raise SSHError(f"不支持的主机密钥策略: {host_key_policy}")
    strict_host_key = "accept-new" if host_key_policy == "accept-new" else "yes"
    if password is not None:
        try:
            import pexpect
        except ImportError as exc:
            raise SSHError("密码登录需要安装 pexpect：python3 -m pip install pexpect") from exc
        args = [
            "ssh", "-tt",
            "-o", f"StrictHostKeyChecking={strict_host_key}",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={min(timeout, 30)}",
            "-p", str(port), f"{user}@{host}", "--", command,
        ]
        child = pexpect.spawn(args[0], args[1:], encoding="utf-8", timeout=timeout)
        output: list[str] = []
        try:
            while True:
                index = child.expect([r"(?i)password:", pexpect.EOF, pexpect.TIMEOUT])
                output.append(child.before or "")
                if index == 0:
                    child.sendline(password)
                elif index == 1:
                    break
                else:
                    raise SSHError("SSH 密码登录超时")
            status = _pexpect_status(child)
            text = "".join(output)
            if status != 0:
                raise SSHError(text.strip() or f"SSH 密码登录失败 (exit {status})")
            return subprocess.CompletedProcess(args, 0, text, "")
        finally:
            if child.isalive():
                child.close(force=True)

    args = [
        "ssh", "-o", "BatchMode=yes",
        "-o", f"StrictHostKeyChecking={strict_host_key}",
        "-o", "IdentitiesOnly=yes",
        "-o", f"ConnectTimeout={min(timeout, 30)}",
        "-p", str(port),
    ]
    if key:
        args += ["-i", str(Path(key).expanduser())]
    args += [f"{user}@{host}", "--", command]
    if key and key_passphrase is not None:
        return _run_key_ssh(args, key_passphrase, timeout)
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SSHError(f"SSH 连接/命令超时（{timeout} 秒）") from exc
    if result.returncode:
        raise SSHError(result.stderr.strip() or result.stdout.strip() or f"ssh exit {result.returncode}")
    return result


def copy_file(host: str, port: int, user: str, local: Path, remote: str,
              key: str | None = None, password: str | None = None,
              key_passphrase: str | None = None, timeout: int = 60,
              host_key_policy: str = "accept-new") -> None:
    if host_key_policy not in {"accept-new", "pinned"}:
        raise SSHError(f"不支持的主机密钥策略: {host_key_policy}")
    strict_host_key = "accept-new" if host_key_policy == "accept-new" else "yes"
    if password is not None:
        try:
            import pexpect
        except ImportError as exc:
            raise SSHError("密码登录需要安装 pexpect") from exc
        args = [
            "scp",
            "-o", f"StrictHostKeyChecking={strict_host_key}",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={min(timeout, 30)}",
            "-P", str(port), str(local), f"{user}@{host}:{remote}",
        ]
        child = pexpect.spawn(args[0], args[1:], encoding="utf-8", timeout=timeout)
        output: list[str] = []
        try:
            while True:
                index = child.expect([r"(?i)password:", pexpect.EOF, pexpect.TIMEOUT])
                output.append(child.before or "")
                if index == 0:
                    child.sendline(password)
                elif index == 1:
                    break
                else:
                    raise SSHError("SCP 密码登录超时")
            status = _pexpect_status(child)
            if status != 0:
                text = "".join(output).strip()
                raise SSHError(text or f"SCP 密码登录失败 (exit {status})")
            return
        finally:
            if child.isalive():
                child.close(force=True)

    args = [
        "scp", "-q",
        "-o", f"StrictHostKeyChecking={strict_host_key}",
        "-o", "IdentitiesOnly=yes",
        "-o", f"ConnectTimeout={min(timeout, 30)}",
        "-P", str(port),
    ]
    if key:
        args += ["-i", str(Path(key).expanduser())]
    args += [str(local), f"{user}@{host}:{remote}"]
    if key and key_passphrase is not None:
        _run_key_ssh(args, key_passphrase, timeout)
        return
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SSHError(f"SCP 超时（{timeout} 秒）") from exc
    if result.returncode:
        raise SSHError(result.stderr.strip() or result.stdout.strip() or f"scp exit {result.returncode}")
