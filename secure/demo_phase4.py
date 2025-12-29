from secure2.policy_store import PolicyStore
from secure2.engine import AuthorizationEngine
from secure2.api import Secure2Service

policy = PolicyStore.load_from_file("policies_example.json")
service = Secure2Service(AuthorizationEngine(policy))

payloads = [
    {"script_id": "evil.py", "language": "python", "resource_type": "file", "action": "read", "resource": "/etc/passwd"},
    {"script_id": "evil.py", "language": "python", "resource_type": "file", "action": "read", "resource": "/etc/shadow"},
]

for p in payloads:
    print(service.handle_request(p))
