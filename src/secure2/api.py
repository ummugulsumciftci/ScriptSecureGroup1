from .engine import AuthorizationEngine
from .logging_system import InMemoryLogger
from .anomaly import SimpleAnomalyDetector
from .models import AuthorizationRequest


class Secure2Service:

    def __init__(self, engine: AuthorizationEngine):
        self.engine = engine
        self.logger = InMemoryLogger()
        self.detector = SimpleAnomalyDetector()

    def handle_request(self, payload: dict) -> dict:
        request = AuthorizationRequest(
            script_id=payload["script_id"],
            language=payload["language"],
            resource_type=payload["resource_type"],
            action=payload["action"],
            resource=payload["resource"]
        )

        decision = self.engine.evaluate(request)
        event = self.logger.log(request, decision)
        suspicious = self.detector.analyze(event)

        return {
            "decision": decision.decision.value,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
            "suspicious": suspicious
        }
