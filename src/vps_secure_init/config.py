import json
from pathlib import Path
from typing import Any
from .models import Host
from .policy import normalize_policy


def load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError(f"需要 PyYAML 才能读取 YAML 文件: {path}") from exc
        return yaml.safe_load(text) or {}


def load_hosts(path: Path) -> list[Host]:
    data = load_mapping(path)
    return [Host.from_dict(item) for item in data.get("hosts", [])]


def save_hosts(path: Path, hosts: list[Host]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"hosts": [h.to_dict() for h in hosts]}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def save_policy(path: Path, policy: dict[str, Any]) -> None:
    """Validate and atomically write a canonical v2 policy as YAML."""
    normalized = normalize_policy(policy)
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError("需要 PyYAML 才能保存 YAML 策略文件") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        yaml.safe_dump(normalized, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    tmp.chmod(0o600)
    tmp.replace(path)
    path.chmod(0o600)


def load_policy(path: Path) -> dict[str, Any]:
    """Load a policy into its canonical v2 in-memory representation.

    A v1 file is migrated in memory only.  Persisting an explicit migration is
    an interactive Phase-B operation so a normal controller run never rewrites
    user configuration unexpectedly.
    """
    return normalize_policy(load_mapping(path))
