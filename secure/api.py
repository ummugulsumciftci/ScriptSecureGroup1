# api.py
from .engine import AuthorizationEngine
from .models import AuthorizationRequest, AuthorizationDecision

auth_engine = AuthorizationEngine()

def handle_auth_request(payload: dict) -> dict:
    """
    Sandbox'tan JSON gibi gelecek isteği AuthorizationRequest'e çevirip
    evaluate edip, tekrar JSON response dönen mock fonksiyon.
    """
    req = AuthorizationRequest(
        script_id=payload.get("script_id", "unknown"),
        language=payload.get("language", "python"),
        resource_type=payload["resource_type"],
        resource=payload["resource"],
        action=payload["action"],
        container_id=payload.get("container_id")
    )

    decision: AuthorizationDecision = auth_engine.evaluate(req)

    return {
        "decision": decision.decision.value,
        "reason": decision.reason
    }
