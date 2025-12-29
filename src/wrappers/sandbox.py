import builtins
import os
from pathlib import Path

from engine import AuthorizationEngine
from models import AuthorizationRequest
from policy_store import PolicyStore, Rule  # Rule ve Store eklendi

# =====================================================
# POİLCY AYARLARI (Testlerin geçmesi için kurallar)
# =====================================================
store = PolicyStore()

# Test dosyasının tam yolunu bul (Path resolve kullandığımız için)
test_file_path = str(Path("test.txt").resolve())

# KURAL 1: test.txt dosyasına YAZMA izni ver (Test 1 için)
store.add_rule(Rule(
    id="allow-write-test",
    effect="allow",
    resource_type="file",
    resource=test_file_path,
    action="write"
))

# KURAL 2: test.txt dosyasını OKUMA izni ver (Test 2 için)
store.add_rule(Rule(
    id="allow-read-test",
    effect="allow",
    resource_type="file",
    resource=test_file_path,
    action="read"
))

# NOT: /etc/passwd veya os.system için kural yok -> Default DENY (Test 3 ve 4 geçecek)

# =====================================================
# ENGINE BAŞLATMA
# =====================================================
# ARTIK BOŞ DEĞİL, STORE İLE BAŞLIYOR
engine = AuthorizationEngine(store)

_original_open = builtins.open
_original_os_system = os.system

# =====================================================
# WRAPPERS
# =====================================================
def secure_open(file, mode="r", *args, **kwargs):
    action = "write" if any(m in mode for m in ["w", "a", "x"]) else "read"
    resource = str(Path(file).resolve())

    request = AuthorizationRequest(
        script_id="python_script",
        language="python",
        resource_type="file",
        resource=resource,
        action=action
    )

    decision = engine.evaluate(request)

    if decision.decision.name == "DENY":
        raise PermissionError(f"ScriptSecure: {decision.reason}")

    return _original_open(file, mode, *args, **kwargs)

def secure_os_system(command):
    request = AuthorizationRequest(
        script_id="python_script",
        language="python",
        resource_type="process",
        resource=str(command),
        action="execute"
    )

    decision = engine.evaluate(request)

    if decision.decision.name == "DENY":
        raise PermissionError(f"ScriptSecure: {decision.reason}")

    return _original_os_system(command)

def enable_python_sandbox():
    builtins.open = secure_open
    os.system = secure_os_system
    # print("✅ Python sandbox aktif") # Test çıktısı karışmasın diye kapattım