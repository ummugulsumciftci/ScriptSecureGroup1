from datetime import datetime
from typing import List
from .models import AuthorizationRequest, AuthorizationDecision, LogEvent


class InMemoryLogger:

    def __init__(self):
        self.logs: List[LogEvent] = []

    def log(self, request: AuthorizationRequest, decision: AuthorizationDecision):
        event = LogEvent(
            timestamp=datetime.utcnow().isoformat(),
            request=request,
            decision=decision
        )
        self.logs.append(event)
        return event
