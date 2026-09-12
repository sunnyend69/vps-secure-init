from pathlib import Path

from vps_secure_init.credentials import generate_key


def test_generate_key_uses_configured_kdf_rounds(tmp_path: Path, monkeypatch):
    calls = []

    class Result:
        returncode = 0

    def fake_run(args, check):
        calls.append(args)
        (tmp_path / "key").write_text("key")
        (tmp_path / "key.pub").write_text("pub")
        return Result()

    monkeypatch.setattr("vps_secure_init.credentials.subprocess.run", fake_run)
    generate_key(tmp_path / "key", "test", "pass", kdf_rounds=222)

    assert calls[0][calls[0].index("-a") + 1] == "222"
