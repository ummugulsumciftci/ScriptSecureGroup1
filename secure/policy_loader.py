# policy_loader.py
"""
Güvenlik Politikası Yükleyici ve Doğrulayıcı
Zero Trust prensibi ile çalışan politika yönetim modülü
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from .models import Decision


class PolicyLoader:
    """
    Güvenlik politikası dosyasını yükler ve doğrular.
    Varsayılan olarak tüm erişimler reddedilir (default deny).
    """
    
    def __init__(self, policy_path: str = "Policies/policy.json"):
        """
        Policy dosyasını yükler ve doğrular.
        
        Args:
            policy_path: Politika JSON dosyasının yolu
        """
        self.policy_path = policy_path
        self.policy: Dict[str, Any] = {}
        self._load_policy()
        self._validate_policy()
    
    def _load_policy(self):
        """Policy dosyasını diskten yükler."""
        try:
            # Absolute path oluştur
            if not os.path.isabs(self.policy_path):
                # Proje root dizinini bul
                current_dir = Path(__file__).parent.parent
                policy_file = current_dir / self.policy_path
            else:
                policy_file = Path(self.policy_path)
            
            with open(policy_file, 'r', encoding='utf-8') as f:
                self.policy = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Politika dosyası bulunamadı: {self.policy_path}. "
                "Default deny politikası uygulanacak."
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"Politika dosyası geçersiz JSON formatında: {e}")
    
    def _validate_policy(self):
        """Policy yapısını doğrular."""
        required_keys = ["version", "default_action", "file_system", "network", "process"]
        for key in required_keys:
            if key not in self.policy:
                raise ValueError(f"Policy dosyasında gerekli anahtar eksik: {key}")
        
        # Default Action -> DENY olduğundan emin ol
        if self.policy.get("default_action") != "DENY":
            raise ValueError(
                "Güvenlik ihlali: Default action DENY olmalıdır. "
                "Zero Trust prensibi gereği tüm erişimler varsayılan olarak reddedilir."
            )
    
    def get_default_action(self) -> Decision:
        """Varsayılan kararı döndürür (her zaman DENY)."""
        return Decision.DENY
    
    def check_file_access(self, path: str, action: str) -> Tuple[Decision, str]:
        """
        Dosya erişimini kontrol eder.
        
        Args:
            path: Erişilmek istenen dosya yolu
            action: Eylem tipi (read, write, execute)
        
        Returns:
            (karar, sebep) tuple'ı
        """
        # Normalize path
        normalized_path = os.path.abspath(path)
        
        # Yasaklı path kontrol et
        forbidden_paths = self.policy.get("file_system", {}).get("forbidden_paths", [])
        for forbidden in forbidden_paths:
            forbidden_path = forbidden.get("path", "")
            if normalized_path.startswith(forbidden_path):
                return (
                    Decision.DENY,
                    f"Yasaklı path: {forbidden_path} - {forbidden.get('description', '')}"
                )
        
        # İzin verilen path kontrol et
        allowed_paths = self.policy.get("file_system", {}).get("allowed_paths", [])
        for allowed in allowed_paths:
            allowed_path = allowed.get("path", "")
            if normalized_path.startswith(allowed_path):
                allowed_actions = allowed.get("actions", [])
                
                # Eylem kontrolü
                if action not in allowed_actions:
                    return (
                        Decision.DENY,
                        f"Path izinli ancak '{action}' eylemi bu path için izinli değil"
                    )
                
                # Ek kısıtlama check
                restrictions = allowed.get("restrictions", {})
                
                # Dosya uzantısı kontrolü
                if "allowed_extensions" in restrictions:
                    file_ext = os.path.splitext(normalized_path)[1]
                    if file_ext not in restrictions["allowed_extensions"]:
                        return (
                            Decision.DENY,
                            f"Dosya uzantısı '{file_ext}' bu path için izinli değil"
                        )
                
                # Yasaklı pattern kontrolü
                if "forbidden_patterns" in restrictions:
                    for pattern in restrictions["forbidden_patterns"]:
                        if normalized_path.endswith(pattern.replace("*", "")):
                            return (
                                Decision.DENY,
                                f"Dosya patterni '{pattern}' yasaklanmış"
                            )
                
                # Read-only kontrolü
                if restrictions.get("read_only") and action != "read":
                    return (
                        Decision.DENY,
                        "Bu path sadece okuma için izinli (read-only)"
                    )
                
                return (
                    Decision.ALLOW,
                    f"Path ve action izinli: {allowed_path} - {action}"
                )
        
        # Varsayılan: Reddet
        return (
            Decision.DENY,
            "Dosya pathi politika kurallarına uymuyor - varsayılan reddetme"
        )
    
    def check_network_access(self, host: str, port: int, protocol: str) -> Tuple[Decision, str]:
        """
        Ağ erişimini kontrol eder.
        
        Args:
            host: Hedef host
            port: Hedef port
            protocol: Protokol (tcp, udp, etc.)
        
        Returns:
            (karar, sebep) tuple'ı
        """
        network_policy = self.policy.get("network", {})
        
        # Varsayılan olarak tüm ağ erişimi reddedilir
        if network_policy.get("default") == "DENY":
            return (
                Decision.DENY,
                "Ağ erişimi varsayılan olarak reddedilir - Zero Trust prensibi"
            )
        
        # İzin verilen endpoint check
        allowed_endpoints = network_policy.get("allowed_endpoints", [])
        for endpoint in allowed_endpoints:
            if endpoint.get("host") == host and endpoint.get("port") == port:
                if protocol in endpoint.get("allowed_protocols", []):
                    return (
                        Decision.ALLOW,
                        f"Endpoint izinli: {host}:{port} ({protocol})"
                    )
        
        return (
            Decision.DENY,
            "Ağ erişimi policy kurallarına uymuyor"
        )
    
    def check_process_execution(self, command: str) -> Tuple[Decision, str]:
        """
        Process execution check
        
        Args:
            command: Çalıştırılmak istenen komut
        
        Returns:
            (karar, sebep) tuple'ı
        """
        process_policy = self.policy.get("process", {})
        
        # Varsayılan olarak tüm command execution reddedilir
        if process_policy.get("default") == "DENY":
            return (
                Decision.DENY,
                "Sistem command execution varsayılan olarak reddedilir"
            )
        
        # İzin verilen command check
        allowed_commands = process_policy.get("allowed_commands", [])
        for allowed_cmd in allowed_commands:
            if command.startswith(allowed_cmd):
                return (
                    Decision.ALLOW,
                    f"Komut izinli: {command}"
                )
        
        return (
            Decision.DENY,
            f"Command '{command}' policy kurallarına uymuyor"
        )
    
    def get_resource_limits(self) -> Dict[str, Any]:
        """Kaynak limitlerini döndürür."""
        return self.policy.get("resource_limits", {})
    
    def is_logging_enabled(self) -> bool:
        """Loglama etkin mi kontrol eder."""
        return self.policy.get("logging", {}).get("enabled", True)

