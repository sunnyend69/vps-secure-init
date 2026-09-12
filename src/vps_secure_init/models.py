from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any


class State(str, Enum):
    NEW = "NEW"
    CREDENTIALS_READY = "CREDENTIALS_READY"
    PREFLIGHT_OK = "PREFLIGHT_OK"
    BOOTSTRAPPED = "BOOTSTRAPPED"
    DUAL_SSH_READY = "DUAL_SSH_READY"
    NEW_LOGIN_VERIFIED = "NEW_LOGIN_VERIFIED"
    FIREWALL_VERIFIED = "FIREWALL_VERIFIED"
    OLD_PORT_REMOVED = "OLD_PORT_REMOVED"
    FAIL2BAN_VERIFIED = "FAIL2BAN_VERIFIED"
    COMPLETED = "COMPLETED"
    FAILED = "STEP_FAILED_KEEP_RESCUE_ACCESS"
    MANUAL = "MANUAL_INTERVENTION_REQUIRED"


@dataclass
class Host:
    id: str
    address: str
    initial_port: int = 22
    initial_user: str = "root"
    initial_auth: str = "key"
    initial_key: str | None = None
    platform: str = "auto"
    profile: str = "standard"
    overrides: dict[str, Any] = field(default_factory=dict)
    detected_platform: str | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    plan_id: str | None = None
    plan_sha256: str | None = None
    state: str = State.NEW.value
    last_error: str | None = None
    resume_state: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Host":
        fields = {f for f in cls.__dataclass_fields__}
        values = {k: v for k, v in data.items() if k in fields}
        # The 0.1.x example named its sole profile "default".  Preserve old
        # inventories while moving the in-memory model to the v2 standard
        # profile; config files are not rewritten during a normal load.
        if values.get("profile") == "default":
            values["profile"] = "standard"
        return cls(**values)
