from typing import Dict
from .models import LogEvent, Decision


class SimpleAnomalyDetector:

    def __init__(self, deny_threshold: int = 3):
        self.deny_threshold = deny_threshold
        self.denied_count: Dict[str, int] = {}

    def analyze(self, event: LogEvent) -> bool:
        script_id = event.request.script_id

        if event.decision.decision == Decision.DENY:
            self.denied_count[script_id] = self.denied_count.get(script_id, 0) + 1

        return self.denied_count.get(script_id, 0) >= self.deny_threshold
