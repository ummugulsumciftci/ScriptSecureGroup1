import builtins
import os
import sys
from datetime import datetime

# ORİJİNAL FONKSİYONLARI SAKLA
_original_open = builtins.open
_original_system = os.system


# =====================================================
# YETKİLENDİRME MOTORU (PROTOTİP)
# =====================================================
def check_permission(action: str, target: str) -> bool:
    # Basit politika: "izinli" geçen her şeye izin
    if "izinli" in target.lower():
        return True
    return False


# =====================================================
# LOGGING (RECURSION YOK!)
# =====================================================
def log_access(action, target, decision):
    timestamp = datetime.now().isoformat()
    line = f"{timestamp} | {action} | {target} | {decision}\n"

    # Log dosyasını yazılabilir olan /tmp klasörüne yönlendiriyoruz
    try:
        with _original_open("/tmp/access.log", "a", encoding="utf-8") as f:
            f.write(line)
    except:
        pass # Log yazılamazsa bile sistemin çökmesini engelle

# =====================================================
# OPEN() WRAPPER
# =====================================================
def secure_open(file, mode="r", *args, **kwargs):
    action = "FILE_WRITE" if any(m in mode for m in ["w", "a", "x"]) else "FILE_READ"
    target = os.path.abspath(file)

    if not check_permission(action, target):
        log_access(action, target, "DENY")
        raise PermissionError(f"ScriptSecure: {target} erişimi reddedildi")

    log_access(action, target, "ALLOW")
    return _original_open(file, mode, *args, **kwargs)


# =====================================================
# os.system WRAPPER
# =====================================================
def secure_os_system(command):
    action = "OS_EXECUTE"
    target = str(command)

    if not check_permission(action, target):
        log_access(action, target, "DENY")
        print("ScriptSecure: OS komutu engellendi")
        return -1

    log_access(action, target, "ALLOW")
    return _original_system(command)


# =====================================================
# ENTEGRASYON
# =====================================================
def enable_script_secure_wrappers():
    builtins.open = secure_open
    os.system = secure_os_system
    print("✅ ScriptSecure Python Wrapper aktif")
