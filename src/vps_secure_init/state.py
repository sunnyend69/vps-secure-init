import json
from pathlib import Path
from .models import Host


class StateStore:
    def __init__(self, path: Path):
        self.path = path

    def save(self, hosts: list[Host]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps({"hosts": [h.to_dict() for h in hosts]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def load(self) -> list[Host]:
        if not self.path.exists():
            return []
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return [Host.from_dict(item) for item in data.get("hosts", [])]
