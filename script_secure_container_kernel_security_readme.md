# ScriptSecure – Güvenli Çalıştırma Altyapısı (Container & Kernel Seviyesi)

Bu doküman, **ScriptSecure** projesinde benim sorumluluğumda geliştirilen **container ve kernel seviyesinde güvenlik altyapısını**, bu alanda eğitim gören bir **üniversite öğrencisinin rahatça anlayabileceği** bir dil ve seviyede açıklamak için hazırlanmıştır. Metin, bir ders kapsamında ya da proje ödevi olarak okuyan bir öğrencinin; Docker, Linux ve temel işletim sistemi kavramlarına aşina olduğu varsayımıyla yazılmıştır.

Anlatım boyunca yalnızca teorik kavramlar değil; **gerçek kod parçaları**, **basit saldırı örnekleri** ve bu saldırıların **hangi güvenlik katmanında nasıl engellendiği** de adım adım ele alınmaktadır. Böylece okuyucu, güvenliğin sadece tek bir yerde değil, **birden fazla katmanın birlikte çalışmasıyla** sağlandığını net biçimde görebilir.

Amaç yalnızca sistemin *ne yaptığı* değil; aynı zamanda **neden bu şekilde tasarlandığını**, **hangi tehditleri hedef aldığını** ve **bu tehditleri hangi seviyede durdurduğunu** açık ve anlaşılır biçimde ortaya koymaktır.

---

## 📁 İncelenen Dosyalar

Bu bölümde sorumluluğumda olan ve altyapı güvenliğini doğrudan ilgilendiren üç ana dosya bulunmaktadır:

```
.
├── Dockerfile
├── seccomp_profile.json
└── pool_manager_final.py
```

Bu dosyalar birlikte çalışarak, Python scriptlerinin **izole**, **ağ erişimi olmayan**, **yetkisiz** ve **kaynakları sınırlı** bir ortamda çalıştırılmasını sağlar. Burada hedeflenen güvenlik, uygulama kodundan bağımsız olarak **altyapı ve işletim sistemi seviyesinde** uygulanır. Yani script içeriği ne olursa olsun, belirli sınırların dışına çıkamaz.

---

# 1️⃣ Dockerfile – İzole Çalışma Ortamı

Dockerfile’ın temel amacı, çalıştırılacak scriptlerin **doğrudan host bilgisayarda değil**, izole bir Docker container içinde çalışmasını sağlamaktır. Bu, ScriptSecure mimarisinde güvenliğin başladığı ilk noktadır.

Docker kullanmadan bir Python scriptini doğrudan host üzerinde çalıştırmak; dosya sistemi, ağ ve sistem kaynakları açısından ciddi riskler doğurabilir. Docker bu riskleri azaltmak için bir **izolasyon katmanı** sunar.

### Neden Docker Kullanıyoruz?

Docker tercih edilmesinin başlıca nedenleri şunlardır:

- Scriptler host işletim sistemine doğrudan erişemez
- Script hata verirse veya sonsuz döngüye girerse sadece container etkilenir
- Bellek ve işlem (process) limitleri uygulanabilir
- Kernel seviyesinde ek güvenlik mekanizmaları (seccomp, capabilities) kullanılabilir

Bu Dockerfile, ScriptSecure için **özel ve kontrollü bir image** oluşturur. Pool manager bu image’i kullanarak her çalıştırma için aynı güvenlik ayarlarına sahip container’lar üretir.

> Bu aşamada güvenlik, scriptin *ne yaptığına* değil; **nerede ve hangi koşullarda çalıştığına** odaklanır. Bu nedenle bu katman genellikle *ortamsal (environment-based) güvenlik* olarak adlandırılır.

---

# 2️⃣ seccomp_profile.json – Kernel Seviyesinde Güvenlik

`seccomp_profile.json`, Linux işletim sisteminde bulunan **seccomp (secure computing)** mekanizmasını kullanır. Seccomp, bir programın kernel ile iletişim kurarken **hangi sistem çağrılarını (syscall)** yapabileceğini kısıtlamaya yarar.

Bu mekanizma, Python kodunun ve wrapper’ların da altında yer alır. Yani kod ne kadar karmaşık olursa olsun, **kernel seviyesinde izin verilmeyen bir işlem yapılamaz**.

---

## 2.1 Varsayılan Yaklaşım: Her Şey Yasak (Default Deny)

```json
"defaultAction": "SCMP_ACT_ERRNO"
```

Bu satır, seccomp profilinin temel mantığını belirler. Anlamı şudur:

> Açıkça izin verilmeyen herhangi bir sistem çağrısı yapılırsa, işletim sistemi bu isteği otomatik olarak hata ile reddeder.

Bu yaklaşım, güvenlik dünyasında sıkça kullanılan **"default deny"** (varsayılan olarak reddet) prensibinin kernel seviyesindeki karşılığıdır. Yani önce her şey yasaklanır, sadece gerçekten gerekli olanlara izin verilir.

---

## 2.2 Neden Sadece Az Sayıda Syscall’a İzin Veriliyor?

```json
{ "name": "read", "action": "SCMP_ACT_ALLOW" },
{ "name": "write", "action": "SCMP_ACT_ALLOW" },
{ "name": "execve", "action": "SCMP_ACT_ALLOW" }
```

Bu syscall’lar, Python programlarının **en temel şekilde çalışabilmesi için zorunlu** olan işlemleri temsil eder:

- `read`, `write` → Dosya okuma ve yazma
- `execve` → Python programının başlatılması
- `mmap`, `brk` → Bellek yönetimi

Bunun dışında kalan syscall’lar; ağ bağlantısı kurma, yeni process oluşturma veya yetki yükseltme gibi **potansiyel olarak tehlikeli** işlemler içerdiği için bilinçli olarak yasaklanmıştır.

---

## 2.3 Basit Bir Saldırı Örneği

```python
import socket
s = socket.socket()
s.connect(("example.com", 80))
```

Bu kod çalıştırıldığında şu adımlar gerçekleşir:

1. Python ağ bağlantısı kurmaya çalışır
2. Kernel seviyesinde `socket` syscall’ı çağrılır
3. Bu syscall seccomp profilinde izinli değildir
4. İşletim sistemi çağrıyı otomatik olarak reddeder

Bu aşamada Python kodu veya wrapper’lar devreye girmeden saldırı **en alt seviyede**, yani kernel seviyesinde durdurulmuş olur.

---

# 3️⃣ pool_manager_final.py – Güvenli Container Yönetimi

Bu dosya, güvenli container’ların oluşturulmasını, yönetilmesini ve scriptlerin bu container’lar içinde çalıştırılmasını sağlar. Başka bir ifadeyle, **scriptlerin nasıl, nerede ve hangi sınırlar içinde çalıştırılacağını** kontrol eder.

---

## 3.1 Container Pool Mantığı

```python
self.client = docker.from_env()
self.pool = []
self._initialize_pool()
```

Bu kod parçası:

- Docker ile bağlantıyı başlatır
- Güvenlik ayarları uygulanmış container’ları önceden oluşturur
- Her scripti bu hazır container’lardan birinde çalıştırır

Bu yaklaşım sayesinde hem performans kazanılır hem de her çalıştırmada aynı güvenlik politikalarının tutarlı biçimde uygulanması sağlanır.

---

## 3.2 Uygulanan Güvenlik Ayarları (Kod Üzerinden)

### Ağ Erişiminin Kapatılması

```python
network_disabled=True
```

➡️ Scriptler internete çıkamaz, dış sistemlerle iletişim kuramaz ve veri sızdıramaz.

---

### Salt Okunur Dosya Sistemi

```python
read_only=True
```

➡️ Script sistem dosyalarını değiştiremez.

Örnek:
```python
open('/etc/passwd', 'w')
```
Bu işlem dosya sistemi salt okunur olduğu için kernel tarafından reddedilir.

---

### Fork Bomb ve DoS Koruması

```python
mem_limit="64m"
pids_limit=15
```

➡️ Scriptin kullanabileceği bellek ve process sayısı sınırlandırılır. Böylece fork bomb veya aşırı kaynak tüketimi engellenir.

---

### Linux Yetkilerinin Kapatılması

```python
cap_drop=["ALL"]
```

➡️ Script, `setuid`, `mount` veya benzeri tehlikeli sistem yetkilerine sahip olamaz.

---

### Sadece /tmp Dizininin Yazılabilir Olması

```python
tmpfs={'/tmp': 'size=16m'}
```

➡️ Yazılan dosyalar RAM üzerinde tutulur ve container kapandığında otomatik olarak silinir.

---

## 3.3 Wrapper’ların Zorunlu Olarak Kullanılması

```python
sys.path.append('/app/wrappers')
```

Bu satır sayesinde Python wrapper’ları otomatik olarak yüklenir ve:

- `open`
- `os.system`

 gibi tehlikeli fonksiyonlar kontrol altına alınır. Böylece uygulama seviyesinde ek bir güvenlik katmanı sağlanır.

---

## 3.4 Script Nasıl Çalıştırılıyor?

```python
container.exec_run("python3 -c \"kod\"")
```

Script:

- İzole bir container içinde
- Ağsız
- Yetkisiz
- Kaynakları sınırlı
- Seccomp korumalı

şekilde çalıştırılır.

---

## 🧠 Genel Özet

Bu üç dosya birlikte çalışarak **katmanlı bir güvenlik yapısı** oluşturur:

- Wrapper seviyesi → Python fonksiyonlarını kontrol eder
- Seccomp seviyesi → Kernel çağrılarını sınırlar
- Container seviyesi → Ortamı izole eder ve kaynakları kısıtlar

Bu yapı sayesinde ScriptSecure sistemi, güvenli script çalıştırma konusunda **sağlam, anlaşılır ve savunulabilir** bir mimari sunar. Bu yaklaşım, üniversite düzeyinde verilen işletim sistemleri ve bilgisayar güvenliği derslerinde anlatılan prensiplerle birebir uyumludur.

