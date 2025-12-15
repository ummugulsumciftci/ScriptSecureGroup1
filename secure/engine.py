# engine.py
from .models import AuthorizationRequest, AuthorizationDecision, Decision

class AuthorizationEngine:
    def __init__(self):
        # policy store vs. Faz 3'te detaylanacak
        pass

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecision:
        # Phase 1: default deny placeholder
        return AuthorizationDecision(
            decision=Decision.DENY,
            reason="Default deny policy (Phase 1 placeholder)"
        )
