from .models import AuthorizationRequest, AuthorizationDecision, Decision
from .policy_store import PolicyStore


class AuthorizationEngine:

    def __init__(self, policy_store: PolicyStore):
        self.policy_store = policy_store

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecision:
        rule = self.policy_store.match_rule(
            request.resource_type,
            request.action,
            request.resource
        )

        if rule:
            if rule.effect == "allow":
                return AuthorizationDecision(
                    decision=Decision.ALLOW,
                    reason="Allowed by policy",
                    rule_id=rule.id
                )
            else:
                return AuthorizationDecision(
                    decision=Decision.DENY,
                    reason="Denied by policy",
                    rule_id=rule.id
                )

        return AuthorizationDecision(
            decision=Decision.DENY,
            reason="Denied by default (zero-trust)"
        )
