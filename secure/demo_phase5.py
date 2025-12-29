from secure2.policy_store import PolicyStore
from secure2.engine import AuthorizationEngine
from secure2.api import Secure2Service

policy = PolicyStore.load_from_file("policies_example.json")
service = Secure2Service(AuthorizationEngine(policy))

tests = [
    {"script_id": "ok.js", "language": "javascript", "resource_type": "file", "action": "read", "resource": "/app/data/file.txt"},
    {"script_id": "ok.js", "language": "javascript", "resource_type": "process", "action": "execute", "resource": "rm -rf /"}
]

for t in tests:
    print(service.handle_request(t))
