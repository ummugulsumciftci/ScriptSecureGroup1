from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class AuthorizationRequest:
    script_id: str
    language: str
    resource_type: str
    action: str
    resource: str
    container_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationDecision:
    decision: Decision
    reason: str
    rule_id: Optional[str] = None


@dataclass
class LogEvent:
    timestamp: str
    request: AuthorizationRequest
    decision: AuthorizationDecision
