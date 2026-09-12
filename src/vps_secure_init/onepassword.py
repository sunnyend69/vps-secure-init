import json
import shutil
import subprocess
import tempfile
from pathlib import Path


class OnePasswordError(RuntimeError):
    pass


class OnePasswordStore:
    def __init__(self, vault: str = "VPS"):
        self.vault = vault
        if not shutil.which("op"):
            raise OnePasswordError("未找到 1Password CLI（op），请先安装并登录")

    def upload_private_key(self, host_id: str, key_path: str) -> str:
        result = subprocess.run(["op", "document", "create", key_path, "--vault", self.vault, "--title", f"SSH Private Key / {host_id}", "--tags", "vps-secure-init,ssh-key"], text=True, capture_output=True)
        if result.returncode:
            raise OnePasswordError(result.stderr.strip() or "私钥上传失败")
        try:
            return json.loads(result.stdout)["id"]
        except (ValueError, KeyError) as exc:
            raise OnePasswordError("无法解析 1Password 私钥文档 ID") from exc

    def create_ssh_key(self, host_id: str, key_path: str, passphrase: str) -> str:
        """Create a native SSH Key item using a JSON template over stdin."""
        template = subprocess.run(["op", "item", "template", "get", "SSH Key", "--format", "json"], text=True, capture_output=True)
        if template.returncode:
            raise OnePasswordError("无法读取 1Password SSH Key 模板")
        try:
            item = json.loads(template.stdout)
            # 1Password's native SSHKEY field expects a parseable key. Work on
            # a temporary copy and remove its passphrase; the vault protects
            # the stored value and the original local key remains encrypted.
            public_key = Path(key_path + ".pub").read_text().strip()
            with tempfile.TemporaryDirectory(prefix="vps-op-key-") as td:
                unlocked = Path(td) / "id_ed25519"
                shutil.copy2(key_path, unlocked)
                subprocess.run(["ssh-keygen", "-p", "-m", "PKCS8", "-P", passphrase, "-N", "", "-f", str(unlocked)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                private_key = unlocked.read_text()
                fingerprint = subprocess.run(["ssh-keygen", "-lf", str(unlocked)], text=True, capture_output=True, check=True).stdout.split()[1]
                key_type = public_key.split()[0].removeprefix("ssh-")
        except (ValueError, OSError) as exc:
            raise OnePasswordError("无法读取 SSH Key 模板或私钥") from exc
        item["title"] = f"SSH Key / {host_id}"
        item["vault"] = self.vault
        # SSH Key templates use top-level fields (not section fields).
        for field in item.get("fields", []):
            field_id = str(field.get("id", "")).lower()
            label = str(field.get("label", "")).lower()
            if field_id == "private_key" or ("private" in label and "key" in label):
                field["type"] = "SSHKEY"
                field["value"] = private_key
            elif field_id == "passphrase" or "passphrase" in label:
                field["value"] = passphrase
            elif field_id == "public_key" or ("public" in label and "key" in label):
                field["value"] = public_key
            elif field_id == "fingerprint" or "fingerprint" in label:
                field["value"] = fingerprint
            elif field_id in ("key_type", "key-type") or "key type" in label:
                field["value"] = key_type
        # Preserve the passphrase as a concealed custom field in the same item.
        if not any(str(f.get("id", "")) == "passphrase" for f in item.get("fields", [])):
            item.setdefault("fields", []).append({"id": "passphrase", "type": "CONCEALED", "label": "passphrase", "value": passphrase})
        known = {str(f.get("id", "")) for f in item.get("fields", [])}
        for field_id, label, value in (("public_key", "public key", public_key), ("fingerprint", "fingerprint", fingerprint), ("key_type", "key type", key_type)):
            if field_id not in known:
                item.setdefault("fields", []).append({"id": field_id, "type": "STRING", "label": label, "value": value})
        result = subprocess.run(["op", "item", "create", "-", "--format", "json"], input=json.dumps(item), text=True, capture_output=True)
        if result.returncode:
            raise OnePasswordError(result.stderr.strip() or "SSH Key 项目创建失败")
        try:
            return json.loads(result.stdout)["id"]
        except (ValueError, KeyError) as exc:
            raise OnePasswordError("无法解析 SSH Key 项目 ID") from exc

    def create_server(self, host_id: str, address: str, user: str, password: str, port: int, key_path: str, passphrase: str, key_document_id: str | None = None, ssh_key_item_id: str | None = None) -> str:
        fields = {
            "title": f"VPS / {host_id}",
            "category": "Server",
            "vault": self.vault,
            "hostname[text]": address,
            "username[text]": user,
            "password[password]": password,
            "ssh_port[text]": str(port),
            "private_key_path[text]": key_path,
            "private_key_passphrase[password]": passphrase,
            "vps_id[text]": host_id,
        }
        if key_document_id:
            fields["private_key_document_id[text]"] = key_document_id
        if ssh_key_item_id:
            fields["ssh_key_item_id[text]"] = ssh_key_item_id
        args = ["op", "item", "create", "--format", "json"]
        for key, value in fields.items():
            if key in {"title", "category", "vault"}:
                args += [f"--{key}", value]
            else:
                args.append(f"{key}={value}")
        result = subprocess.run(args, text=True, capture_output=True)
        if result.returncode:
            raise OnePasswordError(result.stderr.strip() or "1Password 条目创建失败")
        try:
            return json.loads(result.stdout)["id"]
        except (ValueError, KeyError) as exc:
            raise OnePasswordError("无法解析 1Password 返回的条目 ID") from exc

    def update_server_username(self, item_id: str, username: str) -> None:
        """Update only the Server item's username field in-place."""
        result = subprocess.run(
            [
                "op", "item", "edit", item_id,
                f"username[text]={username}",
                "--vault", self.vault,
                "--format", "json",
            ],
            text=True,
            capture_output=True,
        )
        if result.returncode:
            raise OnePasswordError(result.stderr.strip() or "无法更新 1Password Server 用户名")

    def check(self) -> None:
        result = subprocess.run(["op", "account", "list"], text=True, capture_output=True)
        if result.returncode:
            raise OnePasswordError("1Password CLI 未登录或当前会话已锁定")

    def read_server_credentials(self, item_id: str) -> dict[str, str]:
        """Read only fields required for an existing VPS run; never print values."""
        result = subprocess.run(
            ["op", "item", "get", item_id, "--vault", self.vault, "--reveal", "--format", "json"],
            text=True,
            capture_output=True,
        )
        if result.returncode:
            raise OnePasswordError(result.stderr.strip() or "无法读取 1Password Server 项目")
        try:
            fields = json.loads(result.stdout).get("fields", [])
        except ValueError as exc:
            raise OnePasswordError("无法解析 1Password Server 项目") from exc
        values = {}
        for field in fields:
            field_id = str(field.get("id", ""))
            label = str(field.get("label", ""))
            value = field.get("value")
            if value is not None:
                values[field_id] = str(value)
                values[label] = str(value)
        return {
            "managed_user": values.get("username", ""),
            "managed_password": values.get("password", ""),
            "private_key_passphrase": values.get("private_key_passphrase", ""),
        }
