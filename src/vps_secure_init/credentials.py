import secrets
import string
import subprocess
from pathlib import Path

USERNAME_PREFIX = "u_"
USERNAME_ALPHABET = string.ascii_lowercase + string.digits
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "_-"
MANAGED_USERNAME_LENGTH = 18
MANAGED_PASSWORD_LENGTH = 100
MAX_LINUX_USERNAME_LENGTH = 32


def random_value(length: int = MANAGED_PASSWORD_LENGTH) -> str:
    """Generate a shell/YAML-friendly random secret.

    The alphabet deliberately excludes whitespace, quotes, backslashes, shell
    metacharacters and punctuation that commonly requires escaping.
    """
    if length < 1:
        raise ValueError("密码长度至少为 1")
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


def random_username(length: int = MANAGED_USERNAME_LENGTH) -> str:
    """Generate a portable Linux login name.

    shadow-utils/useradd on Ubuntu 22.04 rejects login names longer than 32
    characters.  Clamp legacy policy values (the old default was 64) instead
    of generating credentials that can never be provisioned.
    """
    if length < len(USERNAME_PREFIX) + 1:
        raise ValueError("用户名长度至少为 3")
    length = min(length, MAX_LINUX_USERNAME_LENGTH)
    return USERNAME_PREFIX + "".join(
        secrets.choice(USERNAME_ALPHABET)
        for _ in range(length - len(USERNAME_PREFIX))
    )


def is_valid_linux_username(value: str) -> bool:
    """Return True for the conservative username subset used by this project."""
    if not value or len(value) > MAX_LINUX_USERNAME_LENGTH:
        return False
    if not (value[0].islower() or value[0] == "_"):
        return False
    return all(ch.islower() or ch.isdigit() or ch in "_-" for ch in value)


def random_port(low: int = 20000, high: int = 60000) -> int:
    return secrets.randbelow(high - low + 1) + low


def generate_key(path: Path, comment: str, passphrase: str, *, kdf_rounds: int = 100) -> None:
    if not 16 <= kdf_rounds <= 1000:
        raise ValueError("key_kdf_rounds 必须在 16 到 1000 之间")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-a", str(kdf_rounds), "-f", str(path), "-N", passphrase, "-C", comment], check=True)
    path.chmod(0o600)
    path.with_name(path.name + ".pub").chmod(0o644)
