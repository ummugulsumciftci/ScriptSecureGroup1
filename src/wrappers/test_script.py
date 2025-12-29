# Sandbox'u aktif et (ÇOK ÖNEMLİ: her şeyden önce)
from sandbox import enable_python_sandbox

enable_python_sandbox()

print("▶ Sandbox aktif, test başlıyor...\n")

# =====================================================
# TEST 1: İZİNLİ DOSYA YAZMA (policy'e bağlı)
# =====================================================
try:
    with open("test.txt", "w") as f:
        f.write("Bu bir sandbox testidir.")
    print("✅ TEST 1 BAŞARILI: Dosya yazma izni verildi")
except PermissionError as e:
    print("❌ TEST 1 ENGELLENDİ:", e)

# =====================================================
# TEST 2: İZİNLİ DOSYA OKUMA
# =====================================================
try:
    with open("test.txt", "r") as f:
        content = f.read()
    print("✅ TEST 2 BAŞARILI: Dosya okundu ->", content)
except PermissionError as e:
    print("❌ TEST 2 ENGELLENDİ:", e)

# =====================================================
# TEST 3: YASAKLI DİZİNE ERİŞİM (mutlaka DENY)
# =====================================================
try:
    with open("/etc/passwd", "r") as f:
        f.read()
    print("❌ TEST 3 HATA: Yasaklı dosyaya erişildi (OLMAMALI)")
except PermissionError as e:
    print("✅ TEST 3 BAŞARILI: Yasaklı erişim engellendi")

# =====================================================
# TEST 4: OS KOMUTU ÇALIŞTIRMA (DENY beklenir)
# =====================================================
import os

try:
    os.system("echo HACK")
    print("❌ TEST 4 HATA: OS komutu çalıştı (OLMAMALI)")
except PermissionError as e:
    print("✅ TEST 4 BAŞARILI: OS komutu engellendi")

print("\n▶ Tüm testler tamamlandı.")
