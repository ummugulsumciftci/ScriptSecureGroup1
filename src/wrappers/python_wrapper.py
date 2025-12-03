# Scripts/Wrappers/Python_Wrapper_Skeleton.py

import os
import sys
import builtins # Yerleşik fonksiyonları değiştirmek için
import subprocess # subprocess modülünü sarmalamak için

# ====================================================================
# FAZ 1/2: YETKİLENDİRME MOTORU İLE İLETİŞİM PROTOTİPİ
# ====================================================================

def check_permission(action_type: str, resource_target: str) -> bool:
    """
    Yetkilendirme Motoru'na izin sorgusu gönderen prototip. 
    Faz 3'te buraya gerçek iletişim kodu gelecek.
    """
    # Geçici Kural: 'izinli' kelimesi geçmeyen tüm hassas işlemleri engelle.
    if "izinli" not in resource_target.lower():
        print(f"DEBUG: Izin engellendi (PROTOTİP) -> Eylem: {action_type}, Hedef: {resource_target}", file=sys.stderr)
        return False
        
    print(f"DEBUG: Izin verildi (PROTOTİP) -> Eylem: {action_type}, Hedef: {resource_target}")
    return True

# ====================================================================
# FAZ 3 HEDEFİ 1: YERLEŞİK FONKSİYONLARI SARMALAMA
# ====================================================================

ORIGINAL_OPEN = builtins.open

def secure_open(file, mode='r', **kwargs):
    """ open() fonksiyonunu sarmalar. Dosya erişiminden önce izin kontrolü yapar. """
    resource_target = str(file)
    action = 'FILE_WRITE' if 'w' in mode or 'a' in mode or 'x' in mode else 'FILE_READ'

    if not check_permission(action, resource_target):
        raise PermissionError(f"ScriptSecure Engellemesi: {resource_target} adresine {action} erişimi yasak.")

    return ORIGINAL_OPEN(file, mode, **kwargs)

# ====================================================================
# FAZ 3 HEDEFİ 2: SİSTEM KOMUTU FONKSİYONLARINI SARMALAMA
# ====================================================================

ORIGINAL_OS_SYSTEM = os.system

def secure_os_system(command):
    """ os.system() fonksiyonunu sarmalar. OS komutu çalıştırmadan önce izin kontrolü yapar. """
    resource_target = str(command)
    action = 'OS_EXECUTE'

    if not check_permission(action, resource_target):
        print(f"UYARI: Yetkisiz OS komutu engellendi: {command}", file=sys.stderr)
        return -1 # os.system'ın başarısızlık kodu

    return ORIGINAL_OS_SYSTEM(command)
    
# TODO: subprocess.run, os.popen, socket modülleri de buraya eklenecektir.

# ====================================================================
# ENTEGRASYON NOKTASI
# ====================================================================

def enable_script_secure_wrappers():
    """ Tüm sarmalayıcıları etkinleştirir. """
    builtins.open = secure_open
    os.system = secure_os_system
    # TODO: Diğer sarmalayıcıları burada aktif edin.
    print("ScriptSecure Python Wrapperlar yüklendi.")


if __name__ == '__main__':
    enable_script_secure_wrappers()
    print("--- Python Prototip Testi Çalışıyor ---")
    
    # Engellenmeli
    try:
        os.system("rm -rf /") 
    except Exception:
        pass
    
    # İzin verilmeli (prototip kuralına göre)
    try:
        with secure_open("izinli_config.txt", "w") as f:
            f.write("OK.")
        print("İzinli dosya yazma başarılı.")
        os.remove("izinli_config.txt")
    except Exception as e:
        print(f"HATA: İzinli işlem engellendi: {e}")