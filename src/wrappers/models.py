from dataclasses import dataclass
from enum import Enum

class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"

@dataclass
class AuthorizationRequest:
    script_id: str
    language: str
    resource_type: str   # "file", "network", "process"
    resource: str
    action: str          # "read", "write", "execute", "connect"
    container_id: str | None = None

@dataclass
class AuthorizationDecision:
    decision: Decision
    reason: str
    rule_id: str | None = None  # EKLENDİ: Hata önlendi