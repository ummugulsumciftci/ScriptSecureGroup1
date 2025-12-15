import sys
import os

# PROJE KÖKÜNÜ sys.path'e ekle
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)
sys.path.insert(0, PROJECT_ROOT)

from src.wrappers.python_wrapper import enable_script_secure_wrappers

enable_script_secure_wrappers()

print("=== TEST BAŞLADI ===")

# İZİNLİ DOSYA
with open("izinli_test.txt", "w") as f:
    f.write("OK")

# ENGELLİ DOSYA
try:
    with open("yasak_test.txt", "w") as f:
        f.write("FAIL")
except PermissionError as e:
    print("Beklenen engelleme:", e)

# ENGELLİ OS KOMUTU
os.system("rm -rf /")

print("=== TEST BİTTİ ===")
