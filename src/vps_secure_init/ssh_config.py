"""Safely maintain the operator's local OpenSSH client configuration."""
from datetime import datetime, timezone
from pathlib import Path

def _without_host_block(text: str, alias: str) -> str:
    lines = text.splitlines(keepends=True); kept = []; block = []; remove = False
    def flush():
        nonlocal block
        if block and not remove: kept.extend(block)
        block = []
    for line in lines:
        stripped = line.strip()
        if stripped and not line[:1].isspace() and stripped.lower().startswith("host "):
            flush(); remove = alias in stripped.split()[1:]; block = [line]
        elif block: block.append(line)
        else: kept.append(line)
    flush()
    return "".join(kept)

def upsert_host_config(alias: str, address: str, port: int, user: str,
                       identity_file: str, config_path: Path | None = None):
    if not alias or any(ch.isspace() for ch in alias):
        raise ValueError("SSH Host 别名不能为空且不能包含空白")
    path = (config_path or Path.home() / ".ssh" / "config").expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    backup = None
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        backup = path.with_name(f"{path.name}.backup-{stamp}")
        path.replace(backup)
    body = _without_host_block(old, alias)
    if body and not body.endswith("\n"): body += "\n"
    block = (f"\nHost {alias}\n    HostName {address}\n    Port {int(port)}\n"
             f"    User {user}\n    IdentityFile {Path(identity_file).expanduser()}\n"
             "    IdentitiesOnly yes\n")
    tmp = path.with_name(f".{path.name}.tmp")
    try:
        tmp.write_text(body + block, encoding="utf-8"); tmp.chmod(0o600); tmp.replace(path); path.chmod(0o600)
    except Exception:
        tmp.unlink(missing_ok=True)
        if backup and backup.exists() and not path.exists(): backup.replace(path)
        raise
    return path, backup
