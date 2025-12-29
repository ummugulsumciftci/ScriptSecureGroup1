import sys
from pathlib import Path

# 🔑 src dizinini Python path'ine ekle (kritik)
SRC_PATH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC_PATH))

import builtins
import os

from engine import AuthorizationEngine
from models import AuthorizationRequest

# Orijinal fonksiyonları sakla
_original_open = builtins.open
_original_os_system = os.system

# Tek engine instance (ÖNEMLİ)
engine = AuthorizationEngine()

# =====================================================
# open() WRAPPER
# =====================================================
def secure_open(file, mode="r", *args, **kwargs):
    action = "write" if any(m in mode for m in ["w", "a", "x"]) else "read"
    resource = str(Path(file).resolve())

    request = AuthorizationRequest(
        subject="python_script",
        resource_type="file",
        resource=resource,
        action=action
    )

    decision = engine.evaluate(request)

    if decision.decision.name == "DENY":
        raise PermissionError(f"ScriptSecure: {decision.reason}")

    return _original_open(file, mode, *args, **kwargs)

# =====================================================
# os.system WRAPPER
# =====================================================
def secure_os_system(command):
    request = AuthorizationRequest(
        subject="python_script",
        resource_type="process",
        resource=str(command),
        action="execute"
    )

    decision = engine.evaluate(request)

    if decision.decision.name == "DENY":
        raise PermissionError(f"ScriptSecure: {decision.reason}")

    return _original_os_system(command)

# =====================================================
# AKTİVASYON
# =====================================================
def enable_python_sandbox():
    builtins.open = secure_open
    os.system = secure_os_system
    print("✅ Python sandbox aktif (engine + PoLP)")
