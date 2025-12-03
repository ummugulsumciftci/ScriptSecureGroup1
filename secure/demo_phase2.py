# demo_phase2.py
from auth_engine.api import handle_auth_request

if __name__ == "__main__":
    sample_payload = {
        "script_id": "test_script.py",
        "language": "python",
        "resource_type": "file",
        "resource": "/etc/passwd",
        "action": "read",
        "container_id": "container-123"
    }

    resp = handle_auth_request(sample_payload)
    print("Auth response:", resp)
