from pathlib import Path
from vps_secure_init.ssh_config import upsert_host_config

def test_upsert_removes_only_exact_alias_and_backups(tmp_path: Path):
    config = tmp_path / "config"
    config.write_text("Host wildcard-*\n    User old\n\nHost demo\n    HostName old\n\nHost demo-old\n    User keep\n", encoding="utf-8")
    path, backup = upsert_host_config("demo", "192.0.2.10", 22022, "admin", "~/.ssh/demo", config)
    text = path.read_text(encoding="utf-8")
    assert backup and backup.exists()
    assert "Host demo-old" in text and text.count("Host demo\n") == 1
    assert "HostName 192.0.2.10" in text and "Port 22022" in text
    assert path.stat().st_mode & 0o777 == 0o600
