# logging_system.py
from .models import AuthorizationRequest, AuthorizationDecision
from datetime import datetime

def log_decision(request: AuthorizationRequest, decision: AuthorizationDecision):
    # Şimdilik sadece konsola veya basit bir dosyaya yazılabilir
    print(
        f"[{datetime.now().isoformat()}] "
        f"script={request.script_id} "
        f"lang={request.language} "
        f"type={request.resource_type} "
        f"action={request.action} "
        f"resource={request.resource} "
        f"-> {decision.decision.value} ({decision.reason})"
    )
