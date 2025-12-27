# Secure-1 Teknik Özet: ScriptSecure Güvenlik Mimarisi

## Genel Bakış

Bu belge, ScriptSecure projesi için Secure-1 sorumlulukları kapsamında geliştirilen güvenlik mimarisini, politikalarını ve kontrollerini özetlemektedir. Sistem, **zero-trust** prensibi ve **PoLP (principle of least privilege)** ilkelerine dayanmaktadır.

---

## 1. Sıfır-Güven (Zero-Trust) Güvenlik Politikası

### 1.1 Varsayılan Reddetme Prensibi

ScriptSecure sistemi, **varsayılan olarak tüm erişimleri reddetme (default deny)** prensibi ile çalışır. Bu yaklaşım:

- **Tüm dosya sistemi erişimleri** varsayılan olarak reddedilir
- **Tüm ağ erişimleri** varsayılan olarak reddedilir
- **Tüm system command execution'lar** varsayılan olarak reddedilir
- Sadece **açıkça izin verilen** kaynaklar ve eylemler kabul edilir

### 1.2 Politika Dosyası Yapısı

Güvenlik politikası `Policies/policy.json` dosyasında tanımlanmıştır:

```json
{
  "version": "1.0",
  "default_action": "DENY",
  "file_system": {
    "default": "DENY",
    "allowed_paths": [...],
    "forbidden_paths": [...]
  },
  "network": {
    "default": "DENY"
  },
  "process": {
    "default": "DENY"
  }
}
```

### 1.3 Çok Katmanlı Güvenlik Kontrolü

Güvenlik kontrolü üç katmanda uygulanır:

1. **Container Seviyesi:**
   - Docker container izolasyonu
   - Network disabled
   - Read-only filesystem
   - Capabilities dropped
   - Resource limits

2. **Seccomp Seviyesi:**
   - Sistem çağrıları (syscalls) filtrelenir
   - Sadece gerekli syscall'lar izin verilir
   - Tehlikeli syscall'lar engellenir

3. **Uygulama Seviyesi:**
   - Wrapper'lar ile API sarmalama
   - Yetkilendirme motoru ile politika kontrolü
   - Erişim kontrol kuralları ile ek kontroller

### 1.4 Runtime Uygulama

Güvenlik politikası, `secure/engine.py` içindeki `AuthorizationEngine` sınıfı tarafından runtime'da uygulanır:

- Her erişim isteği `evaluate()` metodu ile değerlendirilir
- Politika yükleyici (`PolicyLoader`) politika dosyasını okur ve doğrular
- Varsayılan politika her zaman `DENY`'dır
- Sadece politika kurallarına uyan istekler `ALLOW` alır

---

## 2. En Az Ayrıcalık (PoLP) Erişim Kontrol Kuralları

### 2.1 Dosya Sistemi Kuralları

#### İzin Verilen Yollar
- **`/tmp`**: Sadece okuma ve yazma, maksimum 10MB dosya boyutu, sadece `.tmp`, `.log`, `.txt` uzantıları
- **`/app/wrappers`**: Sadece okuma ve çalıştırma (read-only)

#### Yasaklı Yollar
- `/etc`: Sistem yapılandırması
- `/root`: Root kullanıcı dizini
- `/home`: Kullanıcı dizinleri
- `/usr/bin`, `/bin`, `/sbin`: Sistem ikili dosyaları
- `/sys`, `/proc`: Sistem bilgileri
- `/dev`: Cihaz dosyaları (istisnalar hariç)

#### Güvenlik Kontrolleri
- **Path Traversal Koruması:** `../` gibi patternler tespit edilir
- **Tehlikeli Dosya Desenleri:** `.sh`, `.py`, `.exe` gibi dosyalar yasaklanır
- **Dosya Uzantısı Kontrolü:** Sadece izin verilen uzantılar kabul edilir

### 2.2 Ağ Erişim Kuralları

- **Varsayılan:** Tüm ağ erişimi reddedilir
- **Container Seviyesi:** `network_disabled=True`
- **Seccomp Seviyesi:** `socket`, `connect`, `bind` syscall'ları engellenir
- **Uygulama Seviyesi:** `socket` modülü wrapper ile sarmalanır

### 2.3 İşlem Çalıştırma Kuralları

- **Varsayılan:** Tüm sistem komutları reddedilir
- **Command Injection Koruması:** `;`, `|`, `&`, `` ` ``, `$` gibi karakterler tespit edilir
- **Tehlikeli API'ler:** `os.system`, `subprocess`, `eval`, `exec` engellenir

### 2.4 Capabilities Kuralları

- **Tüm Linux capabilities reddedilir:** `cap_drop=["ALL"]`
- Özellikle tehlikeli capabilities:
  - `CAP_SYS_ADMIN`: Sistem yönetimi
  - `CAP_SYS_MODULE`: Kernel modül yükleme
  - `CAP_NET_ADMIN`: Ağ yönetimi
  - `CAP_SETUID`, `CAP_SETGID`: Kullanıcı kimliği değiştirme

### 2.5 Sistem Çağrısı (Syscalls) Kuralları

Seccomp profili (`seccomp_profile.json`) ile sadece gerekli syscall'lar izin verilir:

**İzin Verilen Syscall'lar:**
- `read`, `write`: Dosya okuma/yazma
- `exit`, `exit_group`: Program sonlandırma
- `brk`, `mmap`, `munmap`: Bellek yönetimi
- `openat`, `close`, `fstat`: Dosya işlemleri
- `execve`: Program çalıştırma

**Yasaklı Syscall'lar:**
- `socket`, `connect`, `bind`: Ağ işlemleri
- `mount`, `umount`: Dosya sistemi mount
- `chmod`, `chown`: Dosya izinleri
- `setuid`, `setgid`: Kullanıcı kimliği
- `ptrace`: Process tracing
- `clone`, `fork`, `vfork`: Process oluşturma (sınırlı)

---

## 3. Güvenlik Denetimi ve Penetrasyon Test Senaryoları

### 3.1 Test Senaryoları Kategorileri

1. **Dosya Sistemi Erişim Bypass Denemeleri**
   - Doğrudan sistem dosyalarına erişim
   - Path traversal saldırıları
   - Symlink saldırıları

2. **Ağ Erişimi ve Veri Sızıntısı**
   - HTTP/HTTPS bağlantıları
   - Socket ile raw bağlantılar
   - DNS sorguları ile veri sızıntısı

3. **Komut Injection ve Sistem Komut Çalıştırma**
   - `os.system` ile komut çalıştırma
   - Command injection saldırıları
   - `eval`/`exec` ile kod çalıştırma

4. **Privilege Escalation**
   - `setuid`/`setgid` denemeleri
   - Capability abuse
   - `/proc` manipülasyonu

5. **Sandbox Escape**
   - Docker socket erişimi
   - Host filesystem erişimi
   - Kernel modül yükleme

6. **Kaynak Tüketimi (DoS)**
   - Fork bomb
   - Bellek tüketimi
   - CPU tüketimi

7. **Policy Bypass**
   - Path traversal ile policy bypass
   - Unicode normalization bypass
   - Case sensitivity bypass

8. **Log Manipulation**
   - Log dosyasını silme
   - Log dosyasını manipüle etme

9. **TOCTOU Saldırıları**
   - Race condition saldırıları
   - Symlink race conditions

10. **Wrapper Bypass**
    - `__builtins__` manipülasyonu
    - `ctypes` ile doğrudan syscall

### 3.2 Beklenen Sistem Davranışı

Her senaryo için sistem şu şekilde davranmalıdır:

- ✅ **Tüm saldırı denemeleri tespit edilmeli ve engellenmelidir**
- ✅ **Tüm engellemeler loglanmalıdır (audit trail)**
- ✅ **Sistem kararlılığını korumalıdır**
- ✅ **Yanlış pozitif (false positive) oranı düşük olmalıdır**

---

## 4. Güvenlik Mimarisi Bileşenleri

### 4.1 Yetkilendirme Motoru (`secure/engine.py`)

- Sıfır-güven prensibi ile çalışır
- Her isteği policy kurallarına göre değerlendirir
- Varsayılan karar: `DENY`
- Tüm kararları loglar

### 4.2 Politika Yükleyici (`secure/policy_loader.py`)

- JSON formatındaki policy dosyasını yükler
- Policy yapısını doğrular
- Varsayılan aksiyonun `DENY` olduğunu garanti eder
- Dosya, ağ ve işlem erişimlerini kontrol eder

### 4.3 Erişim Kontrol Kuralları (`secure/access_control_rules.py`)

- En az ayrıcalık prensibi ile çalışır
- Path traversal koruması
- Command injection koruması
- API kısıtlamaları
- Capability kontrolleri

### 4.4 Wrapper'lar

- **Python Wrapper** (`src/wrappers/python_wrapper.py`): `open()`, `os.system()` sarmalar
- **Node.js Wrapper** (`src/wrappers/nodejs_wrapper.js`): `fs.readFile()`, `child_process.exec()` sarmalar

### 4.5 Container Yönetimi (`pool_manager_final.py`)

- Docker container havuzu yönetimi
- Güvenlik ayarları:
  - `network_disabled=True`
  - `read_only=True`
  - `cap_drop=["ALL"]`
  - `pids_limit=15`
  - `mem_limit="64m"`

---

## 5. Güvenlik Kontrol Noktaları

### 5.1 Çok Katmanlı Savunma

1. **Container İzolasyonu:** Docker seviyesinde izolasyon
2. **Seccomp Filtreleme:** Syscall seviyesinde kontrol
3. **Capabilities Kısıtlaması:** Linux capability düşürme
4. **Politika Motoru:** Uygulama seviyesinde yetkilendirme
5. **Wrapper Sarmalama:** API seviyesinde kontrol
6. **Erişim Kontrol Kuralları:** Ek güvenlik kontrolleri

### 5.2 Audit Trail (Denetim İzi)

- Tüm yetkilendirme kararları loglanır
- Log dosyası: `/tmp/access.log`
- Log formatı: `timestamp | action | target | decision`
- Log manipülasyonu engellenir

---

## 6. Sonuç

ScriptSecure sistemi, sıfır-güven prensibi ve en az ayrıcalık ilkelerine dayanan kapsamlı bir güvenlik mimarisi ile korunmaktadır. Çok katmanlı savunma yaklaşımı, container seviyesinden uygulama seviyesine kadar her katmanda güvenlik kontrolleri sağlar.

Sistem, gerçek dünya saldırı senaryolarına karşı test edilmiş ve bu saldırılara karşı dayanıklılığı doğrulanmıştır. Sürekli iyileştirme ve güncelleme ile sistemin güvenliği daha da artırılabilir.

---

**Belge Versiyonu:** 1.0  
**Son Güncelleme:** 2025  
**Hazırlayan:** Egemen Karaaytu

