# access_control_rules.py
"""
Principle of Least Privilege (PoLP) ile
Detaylı Erişim Kontrol Kuralları

Bu modül, güvenlik politikasını destekleyen ek kontrol kurallarını içerir.
Her kural, belirli bir güvenlik senaryosuna karşı koruma sağlar.
"""
from typing import Dict, List, Tuple, Optional
from .models import Decision
import re
import os


class AccessControlRules:
    """
    En az ayrıcalık prensibi ile çalışan detaylı erişim kontrol kuralları.
    Her kural, belirli bir saldırı vektörüne karşı koruma sağlar.
    """
    
    def __init__(self):
        """Erişim kontrol kurallarını başlatır."""
        self._initialize_path_rules()
        self._initialize_api_rules()
        self._initialize_capability_rules()
    
    def _initialize_path_rules(self):
        """
        Dosya yolu tabanlı erişim kontrol kuralları.
        Kritik sistem dizinlerine erişimi engeller.
        """
        # Kritik sistem dizinleri - mutlak yasak
        self.forbidden_paths = [
            "/etc",           # Sistem yapılandırması
            "/root",          # Root kullanıcı dizini
            "/home",          # Kullanıcı dizinleri
            "/usr/bin",       # Sistem binary dosyaları
            "/usr/sbin",      # Sistem yönetici binary dosyaları
            "/bin",           # Temel sistem binary dosyaları
            "/sbin",          # Sistem yönetici binary dosyaları
            "/sys",           # Linux sysfs
            "/proc",          # Linux procfs
            "/dev",
            "/var/log",       # Sistem logları
            "/var/run",       # PID dosyaları
            "/boot",          # Boot
            "/lib",           # Kütüphaneler
            "/lib64",         # 64-bit kütüphaneler
            "/opt",           # Üçüncü parti yazılımlar
            "/srv",           # Servis verileri
            "/media",         #  medya
            "/mnt",           # Mount noktaları
        ]
        
        # İzin verilen yollar - sadece gerekli minimum erişim
        self.allowed_paths = {
            "/tmp": {
                "actions": ["read", "write"],
                "max_file_size_mb": 10,
                "allowed_extensions": [".tmp", ".log", ".txt"],
                "description": "Geçici dosyalar için sınırlı erişim"
            },
            "/app/wrappers": {
                "actions": ["read", "execute"],
                "read_only": True,
                "description": "Wrapper dosyaları - sadece okuma ve çalıştırma"
            }
        }
        
        # Tehlikeli dosya desenleri - yasak
        self.dangerous_patterns = [
            r".*\.sh$",           # Shell scriptleri
            r".*\.py$",           # Python scriptleri (wrapper hariç)
            r".*\.js$",           # JavaScript dosyaları (wrapper hariç)
            r".*\.exe$",          # Windows executable
            r".*\.bin$",          # Binary dosyalar
            r".*\.so$",           # Shared object 
            r".*\.dylib$",        # macOS dynamic library
            r".*\.dll$",          # Windows dynamic library
            r".*passwd.*",        # Şifre dosyaları
            r".*shadow.*",        # Shadow dosyaları
            r".*\.key$",          # Private key dosyaları
            r".*\.pem$",          # PEM formatı key dosyaları
            r".*\.p12$",          # PKCS#12 key dosyaları
            r".*\.pfx$",          # PFX key dosyaları
        ]
    
    def _initialize_api_rules(self):
        """
        Sistem API tabanlı erişim kontrol kuralları.
        Tehlikeli sistem çağrılarını engeller.
        """
        # Tehlikeli Python API'leri - yasak
        self.forbidden_python_apis = [
            "os.system",
            "os.popen",
            "os.exec",
            "subprocess",
            "multiprocessing",
            "threading.Thread",
            "socket",
            "urllib",
            "requests",
            "http.client",
            "ftplib",
            "smtplib",
            "telnetlib",
            "__import__",
            "eval",
            "exec",
            "compile",
            "open",  # Wrapper ile kontrol edilir
        ]
        
        # Tehlikeli Node.js API'leri - yasak
        self.forbidden_nodejs_apis = [
            "child_process",
            "cluster",
            "net",
            "dgram",
            "http",
            "https",
            "tls",
            "fs",  # Wrapper ile kontrol edilir
            "eval",
            "Function",
            "vm",
        ]
        
        # İzin verilen güvenli API'ler
        self.allowed_apis = [
            "print",           # Python - standart çıktı
            "console.log",     # Node.js - standart çıktı
            "math",            # Python - matematik işlemleri
            "datetime",        # Python - tarih/saat (sadece okuma)
            "json",            # Python/Node.js - JSON işlemleri
            "re",              # Python - regex
            "string",          # Python - string işlemleri
        ]
    
    def _initialize_capability_rules(self):
        """
        Linux Capabilities tabanlı erişim kontrol kuralları.
        Sistem yeteneklerini kısıtlar.
        """
        # Tüm capabilities reddedilir (en az ayrıcalık)
        self.forbidden_capabilities = [
            "CAP_SYS_ADMIN",      # Sistem yönetimi
            "CAP_SYS_MODULE",     # Kernel modül
            "CAP_SYS_RAWIO",      # Raw I/O erişimi
            "CAP_NET_ADMIN",      # Ağ yönetimi
            "CAP_NET_RAW",        # Raw socket erişimi
            "CAP_DAC_OVERRIDE",   # Dosya izinlerini aşma
            "CAP_SETUID",         # UID değiştirme
            "CAP_SETGID",         # GID değiştirme
            "CAP_SYS_PTRACE",     # Process tracing
            "CAP_CHOWN",          # Dosya sahipliği değiştirme
            "CAP_FOWNER",         # Dosya sahibi izinleri
            "CAP_MKNOD",          # Özel dosya oluşturma
            "CAP_SYS_BOOT",       # Sistem yeniden başlatma
            "CAP_LEASE",          # Dosya kiralama
            "CAP_AUDIT_WRITE",    # Audit log yazma
            "CAP_AUDIT_CONTROL",  # Audit kontrolü
            "CAP_MAC_OVERRIDE",   # MAC politikası aşma
            "CAP_MAC_ADMIN",      # MAC yönetimi
            "CAP_SYSLOG",         # Syslog erişimi
            "CAP_WAKE_ALARM",     # Sistem uyandırma
            "CAP_BLOCK_SUSPEND",  # Suspend bloklama
            "CAP_IPC_LOCK",       # IPC kilit
            "CAP_IPC_OWNER",      # IPC sahipliği
            "CAP_SYS_TIME",       # Sistem zamanı değiştirme
            "CAP_SYS_TTY_CONFIG", # TTY yapılandırması
            "CAP_SYS_RESOURCE",   # Kaynak limitleri aşma
            "CAP_KILL",           # İşlem öldürme
            "CAP_SYS_NICE",       # Process nice değeri
        ]
    
    def check_path_rule(self, path: str) -> Tuple[Decision, str]:
        """
        Dosya yolu kuralını kontrol eder.
        
        Args:
            path: Kontrol edilecek dosya yolu
        
        Returns:
            (karar, sebep) tuple'ı
        """
        normalized_path = os.path.abspath(path)
        
        # Yasaklı pathler
        for forbidden_path in self.forbidden_paths:
            if normalized_path.startswith(forbidden_path):
                return (
                    Decision.DENY,
                    f"Yasaklı sistem dizini: {forbidden_path} - kritik sistem kaynağı"
                )
        
        # Tehlikeli dosya patternleri
        for pattern in self.dangerous_patterns:
            if re.match(pattern, normalized_path, re.IGNORECASE):
                return (
                    Decision.DENY,
                    f"Tehlikeli dosya deseni tespit edildi: {pattern}"
                )
        
        # İzin verilen path kontrol et
        for allowed_path, config in self.allowed_paths.items():
            if normalized_path.startswith(allowed_path):
                return (
                    Decision.ALLOW,
                    f"İzin verilen yol: {allowed_path} - {config.get('description', '')}"
                )
        
        # Varsayılan: Reddet (Default deny policy)
        return (
            Decision.DENY,
            "Dosya yolu erişim kontrol kurallarına uymuyor"
        )
    
    def check_api_rule(self, api_name: str, language: str) -> Tuple[Decision, str]:
        """
        API kuralını kontrol eder.
        
        Args:
            api_name: Kontrol edilecek API adı
            language: Programlama dili (python, javascript)
        
        Returns:
            (karar, sebep) tuple'ı
        """
        if language == "python":
            forbidden_apis = self.forbidden_python_apis
        elif language == "javascript":
            forbidden_apis = self.forbidden_nodejs_apis
        else:
            return (
                Decision.DENY,
                f"Desteklenmeyen dil: {language}"
            )
        
        # Yasaklı API check
        for forbidden_api in forbidden_apis:
            if api_name.startswith(forbidden_api):
                return (
                    Decision.DENY,
                    f"Yasaklı API: {forbidden_api} - güvenlik riski"
                )
        
        # İzin verilen API check
        for allowed_api in self.allowed_apis:
            if api_name.startswith(allowed_api):
                return (
                    Decision.ALLOW,
                    f"İzin verilen API: {allowed_api}"
                )
        
        # Bilinmeyen API - default deny
        return (
            Decision.DENY,
            f"Bilinmeyen API: {api_name} - varsayılan reddetme"
        )
    
    def check_capability_rule(self, capability: str) -> Tuple[Decision, str]:
        """
        Linux capability kuralını kontrol eder.
        
        Args:
            capability: Kontrol edilecek capability adı
        
        Returns:
            (karar, sebep) tuple'ı
        """
        if capability in self.forbidden_capabilities:
            return (
                Decision.DENY,
                f"Yasaklı capability: {capability} - sistem güvenliği riski"
            )
        
        # Tüm capability için default deny
        return (
            Decision.DENY,
            f"Capability izinli değil: {capability} - en az ayrıcalık prensibi"
        )
    
    def check_command_injection(self, command: str) -> Tuple[Decision, str]:
        """
        Komut injection saldırılarını tespit eder.
        
        Args:
            command: Kontrol edilecek komut
        
        Returns:
            (karar, sebep) tuple'ı
        """
        # Tehlikeli karakterler ve patternler
        dangerous_chars = [";", "|", "&", "`", "$", "(", ")", "<", ">", "\n", "\r"]
        dangerous_patterns = [
            r".*\$\(.*\).*",      # Command substitution
            r".*`.*`.*",          # Backtick command substitution
            r".*&&.*",            # Command chaining
            r".*\|\|.*",          # Command chaining
            r".*;.*",             # Command separator
            r".*\|.*",            # Pipe
            r".*<.*",             # Input redirection
            r".*>.*",             # Output redirection
            r".*>>.*",            # Append redirection
            r".*2>.*",            # Error redirection
        ]
        
        # Karakter check
        for char in dangerous_chars:
            if char in command:
                return (
                    Decision.DENY,
                    f"Komut injection riski: tehlikeli karakter '{char}' tespit edildi"
                )
        
        # Desen check
        for pattern in dangerous_patterns:
            if re.match(pattern, command):
                return (
                    Decision.DENY,
                    f"Komut injection riski: tehlikeli pattern tespit edildi: {pattern}"
                )
        
        return (
            Decision.ALLOW,
            "Komut injection riski tespit edilmedi"
        )
    
    def check_path_traversal(self, path: str) -> Tuple[Decision, str]:
        """
        Path traversal saldırılarını tespit eder.
        
        Args:
            path: Kontrol edilecek dosya yolu
        
        Returns:
            (karar, sebep) tuple'ı
        """
        # Path traversal patternleri
        traversal_patterns = [
            r".*\.\./.*",         # ../ (parent directory)
            r".*\.\.\\\.\.",      # ..\.. (Windows)
            r".*/\.\./.*",        # /../ (absolute with traversal)
            r".*\.\.%2F.*",       # URL encoded ../
            r".*\.\.%5C.*",       # URL encoded ..\
            r".*%2E%2E%2F.*",     # Double URL encoded ../
        ]
        
        for pattern in traversal_patterns:
            if re.match(pattern, path, re.IGNORECASE):
                return (
                    Decision.DENY,
                    f"Path traversal saldırısı tespit edildi: {pattern}"
                )
        
        return (
            Decision.ALLOW,
            "Path traversal riski tespit edilmedi"
        )

