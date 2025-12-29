from secure2.policy_store import PolicyStore
from secure2.engine import AuthorizationEngine
from secure2.models import AuthorizationRequest


policy = PolicyStore.load_from_file("policies_example.json")
engine = AuthorizationEngine(policy)

req = AuthorizationRequest(
    script_id="test.py",
    language="python",
    resource_type="file",
    action="read",
    resource="/etc/passwd"
)

print(engine.evaluate(req))
