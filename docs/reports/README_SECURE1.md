# Secure-1 Sorumlulukları - Teslim Edilenler

Bu dizin, ScriptSecure projesi için Secure-1 sorumlulukları kapsamında hazırlanan tüm güvenlik yapılandırmalarını, kodları ve dokümantasyonu içerir.

## 📁 Dosya Yapısı

```
ScriptSecureGroup1/
├── Policies/
│   └── policy.json                          # Sıfır-güven güvenlik politikası
├── secure/
│   ├── engine.py                            # Güncellenmiş yetkilendirme motoru
│   ├── policy_loader.py                     # Politika yükleyici ve doğrulayıcı
│   └── access_control_rules.py              # En az ayrıcalık erişim kontrol kuralları
└── docs/reports/
    ├── secure1_technical_summary.md         # Teknik özet (Türkçe)
    ├── penetration_test_scenarios.md        # Penetrasyon test senaryoları (Türkçe)
    └── README_SECURE1.md                    # Bu dosya
```

## 🎯 Tamamlanan Görevler

### 1. ✅ Sıfır-Güven (Zero-Trust) Güvenlik Politikası

**Dosya:** `Policies/policy.json`

- Varsayılan reddetme (default deny) prensibi uygulandı
- Dosya sistemi, ağ ve işlem erişimleri için detaylı kurallar tanımlandı
- Sistem çağrıları (syscalls) için seccomp kuralları belirlendi
- Kaynak limitleri (bellek, CPU, PID) tanımlandı

**Özellikler:**
- Tüm erişimler varsayılan olarak reddedilir
- Sadece açıkça izin verilen yollar ve eylemler kabul edilir
- Kritik sistem dizinleri yasaklanmıştır
- Ağ erişimi tamamen kapalıdır
- Sistem komut çalıştırma tamamen kapalıdır

### 2. ✅ En Az Ayrıcalık (PoLP) Erişim Kontrol Kuralları

**Dosya:** `secure/access_control_rules.py`

- Dosya yolu tabanlı erişim kontrolü
- API tabanlı erişim kontrolü
- Linux capabilities kontrolü
- Komut injection koruması
- Path traversal koruması

**Özellikler:**
- Kritik sistem dizinlerine erişim engellenir
- Tehlikeli dosya desenleri tespit edilir
- Komut injection saldırıları tespit edilir
- Path traversal saldırıları tespit edilir
- Tehlikeli Python/Node.js API'leri engellenir

### 3. ✅ Yetkilendirme Motoru Güncellemesi

**Dosya:** `secure/engine.py`

- Politika yükleyici entegrasyonu
- Erişim kontrol kuralları entegrasyonu
- Çok katmanlı güvenlik kontrolü
- Audit trail (denetim izi) desteği

**Özellikler:**
- Her istek politika kurallarına göre değerlendirilir
- Varsayılan karar: DENY
- Tüm kararlar loglanır
- Ek güvenlik kontrolleri uygulanır

### 4. ✅ Politika Yükleyici

**Dosya:** `secure/policy_loader.py`

- JSON formatındaki politika dosyasını yükler
- Politika yapısını doğrular
- Dosya, ağ ve işlem erişimlerini kontrol eder
- Varsayılan aksiyonun DENY olduğunu garanti eder

**Özellikler:**
- Politika dosyası yüklenemezse güvenli mod aktif olur
- Dosya yolu normalizasyonu
- İzin verilen yollar ve eylemler kontrol edilir
- Yasaklı yollar kontrol edilir

### 5. ✅ Güvenlik Denetimi ve Penetrasyon Test Senaryoları

**Dosya:** `docs/reports/penetration_test_scenarios.md`

10 gerçekçi saldırı senaryosu hazırlandı:

1. Dosya Sistemi Erişim Bypass Denemesi
2. Ağ Erişimi ve Veri Sızıntısı Denemesi
3. Komut Injection ve Sistem Komut Çalıştırma
4. Privilege Escalation ve Capability Abuse
5. Sandbox Escape - Container Kaçış Denemesi
6. Kaynak Tüketimi (DoS) Saldırıları
7. Policy Bypass ve Misconfiguration Abuse
8. Log Manipulation ve Audit Trail Bypass
9. Time-of-Check-Time-of-Use (TOCTOU) Saldırısı
10. Wrapper Bypass - Doğrudan Sistem Çağrıları

Her senaryo için:
- Saldırı hedefi
- Saldırı yöntemi (kod örnekleri)
- Beklenen sistem davranışı
- Güvenlik kontrolü açıklaması
- Test sonucu beklentisi

### 6. ✅ Teknik Özet ve Dokümantasyon

**Dosya:** `docs/reports/secure1_technical_summary.md`

Kapsamlı teknik dokümantasyon:
- Genel bakış ve mimari
- Sıfır-güven politikası açıklaması
- En az ayrıcalık kuralları
- Güvenlik denetimi senaryoları
- Güvenlik mimarisi bileşenleri
- Güvenlik kontrol noktaları
- İyileştirme önerileri

## 🔧 Kullanım

### Politika Dosyasını Yükleme

```python
from secure.policy_loader import PolicyLoader

# Politika yükleyiciyi başlat
policy_loader = PolicyLoader("Policies/policy.json")

# Dosya erişimini kontrol et
decision, reason = policy_loader.check_file_access("/tmp/test.txt", "read")
print(f"Karar: {decision}, Sebep: {reason}")
```

### Yetkilendirme Motorunu Kullanma

```python
from secure.engine import AuthorizationEngine
from secure.models import AuthorizationRequest

# Yetkilendirme motorunu başlat
engine = AuthorizationEngine()

# İstek oluştur
request = AuthorizationRequest(
    script_id="test_script.py",
    language="python",
    resource_type="file",
    resource="/etc/passwd",
    action="read",
    container_id="container-123"
)

# Değerlendir
decision = engine.evaluate(request)
print(f"Karar: {decision.decision}, Sebep: {decision.reason}")
```

### Erişim Kontrol Kurallarını Kullanma

```python
from secure.access_control_rules import AccessControlRules

# Erişim kontrol kurallarını başlat
rules = AccessControlRules()

# Path traversal kontrolü
decision, reason = rules.check_path_traversal("../../etc/passwd")
print(f"Karar: {decision}, Sebep: {reason}")

# Komut injection kontrolü
decision, reason = rules.check_command_injection("ls; cat /etc/passwd")
print(f"Karar: {decision}, Sebep: {reason}")
```

## 🛡️ Güvenlik Özellikleri

### Çok Katmanlı Savunma

1. **Container Seviyesi:**
   - Docker izolasyonu
   - Network disabled
   - Read-only filesystem
   - Capabilities dropped
   - Resource limits

2. **Seccomp Seviyesi:**
   - Syscall filtreleme
   - Sadece gerekli syscall'lar izin verilir

3. **Uygulama Seviyesi:**
   - Wrapper sarmalama
   - Yetkilendirme motoru
   - Erişim kontrol kuralları

### Varsayılan Reddetme

- Tüm erişimler varsayılan olarak reddedilir
- Sadece açıkça izin verilen kaynaklar kabul edilir
- Politika dosyası yüklenemezse güvenli mod aktif olur

### Audit Trail

- Tüm yetkilendirme kararları loglanır
- Log dosyası: `/tmp/access.log`
- Log manipülasyonu engellenir

## 📝 Notlar

- Politika dosyası JSON formatındadır ve kolayca genişletilebilir
- Güvenlik kontrolleri modüler yapıdadır ve kolayca test edilebilir
- Penetrasyon test senaryoları gerçek dünya saldırılarını simüle eder

---

**Hazırlayan:** Egemen Karaaytu
**Tarih:** 2025  
**Versiyon:** 1.0

