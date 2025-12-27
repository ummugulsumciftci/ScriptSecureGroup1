# engine.py
"""
Yetkilendirme Motoru - Zero-Trust Prensibi ile Çalışır
Tüm erişim istekleri varsayılan olarak reddedilir, sadece açıkça izin verilenler kabul edilir.
"""
from .models import AuthorizationRequest, AuthorizationDecision, Decision
from .policy_loader import PolicyLoader
from .access_control_rules import AccessControlRules
from .logging_system import log_decision
from typing import Tuple
import os


class AuthorizationEngine:
    """
    Güvenlik politikalarını değerlendiren yetkilendirme motoru.
    Varsayılan olarak tüm istekleri reddeder (default deny).
    """
    
    def __init__(self, policy_path: str = "Policies/policy.json"):
        """
        Yetkilendirme motorunu başlatır ve güvenlik politikasını yükler.
        
        Args:
            policy_path: Güvenlik politikası JSON dosyasının yolu
        """
        try:
            self.policy_loader = PolicyLoader(policy_path)
        except (FileNotFoundError, ValueError) as e:
            # Politika yüklenemezse, güvenli mod: her şeyi reddet
            print(f"UYARI: Politika yüklenemedi: {e}. Güvenli mod aktif - tüm erişimler reddedilecek.")
            self.policy_loader = None
        
        # Erişim kontrol kurallarını başlat
        self.access_rules = AccessControlRules()
    
    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """
        Yetkilendirme isteğini değerlendirir ve karar verir.
        
        Sıfır-güven prensibi:
        - Varsayılan: REDDET (DENY)
        - Sadece politika dosyasında açıkça izin verilen kaynaklar kabul edilir
        - Tüm kararlar loglanır (audit trail)
        
        Args:
            request: Yetkilendirme isteği
        
        Returns:
            Yetkilendirme kararı
        """
        # Politika yüklenememişse güvenli mod: default deny
        if self.policy_loader is None:
            decision = AuthorizationDecision(
                decision=Decision.DENY,
                reason="Politika yüklenemedi - güvenli mod: tüm erişimler reddedildi"
            )
            log_decision(request, decision)
            return decision
        
        # Kaynak tipine göre değerlendirme yap
        resource_type = request.resource_type.lower()
        action = request.action.lower()
        
        if resource_type == "file":
            decision, reason = self._evaluate_file_access(request, action)
        elif resource_type == "network":
            decision, reason = self._evaluate_network_access(request, action)
        elif resource_type == "process":
            decision, reason = self._evaluate_process_access(request, action)
        else:
            # Bilinmeyen kaynak tipi default deny
            decision = Decision.DENY
            reason = f"Bilinmeyen kaynak tipi: {resource_type} - varsayılan reddetme"
        
        # Ek güvenlik kontrolleri (access control rules)
        if decision == Decision.ALLOW:
            # İzin verilmiş olanlara da ek kontroller yap
            if resource_type == "file":
                # Path traversal check
                path_decision, path_reason = self.access_rules.check_path_traversal(request.resource)
                if path_decision == Decision.DENY:
                    decision = Decision.DENY
                    reason = path_reason
                else:
                    # Path rule check
                    path_rule_decision, path_rule_reason = self.access_rules.check_path_rule(request.resource)
                    if path_rule_decision == Decision.DENY:
                        decision = Decision.DENY
                        reason = path_rule_reason
            elif resource_type == "process":
                # Command injection check
                cmd_decision, cmd_reason = self.access_rules.check_command_injection(request.resource)
                if cmd_decision == Decision.DENY:
                    decision = Decision.DENY
                    reason = cmd_reason
        
        auth_decision = AuthorizationDecision(
            decision=decision,
            reason=reason
        )
        
        # Tüm decision logla (audit trail)
        if self.policy_loader.is_logging_enabled():
            log_decision(request, auth_decision)
        
        return auth_decision
    
    def _evaluate_file_access(self, request: AuthorizationRequest, action: str) -> Tuple[Decision, str]:
        """
        Dosya erişim isteğini değerlendirir.
        
        Args:
            request: Yetkilendirme isteği
            action: Eylem (read, write, execute)
        
        Returns:
            (karar, sebep) tuple'ı
        """
        file_path = request.resource
        
        # Mutlak yol check - relative path riski oluşturabilir
        if not os.path.isabs(file_path):
            # Relative path -> absolute path
            # Sandbox içinde çalıştığı için /app dizininden başlat
            file_path = os.path.abspath(os.path.join("/app", file_path))
        
        return self.policy_loader.check_file_access(file_path, action)
    
    def _evaluate_network_access(self, request: AuthorizationRequest, action: str) -> Tuple[Decision, str]:
        """
        Ağ erişim isteğini değerlendirir.
        
        Args:
            request: Yetkilendirme isteği
            action: Eylem (connect, bind, listen, etc.)
        
        Returns:
            (karar, sebep) tuple'ı
        """
        resource = request.resource
        
        # URL veya host:port formatını parse et
        # ("https://example.com:443" veya "127.0.0.1:8080" gibi)
        try:
            if "://" in resource:
                # URL formatı
                protocol, rest = resource.split("://", 1)
                if "/" in rest:
                    host_port = rest.split("/")[0]
                else:
                    host_port = rest
            else:
                # host:port formatı
                host_port = resource
                protocol = "tcp"  # Varsayılan
            
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_port
                port = 80 if protocol == "http" else 443 if protocol == "https" else 0
        except (ValueError, IndexError):
            # Parse edilemezse reddet
            return (
                Decision.DENY,
                f"Ağ kaynağı parse edilemedi: {resource}"
            )
        
        return self.policy_loader.check_network_access(host, port, protocol)
    
    def _evaluate_process_access(self, request: AuthorizationRequest, action: str) -> Tuple[Decision, str]:
        """
        İşlem çalıştırma isteğini değerlendirir.
        
        Args:
            request: Yetkilendirme isteği
            action: Eylem (execute, fork, etc.)
        
        Returns:
            (karar, sebep) tuple'ı
        """
        command = request.resource
        
        # command injection saldırılarına karşı temel kontrol
        dangerous_chars = [";", "|", "&", "`", "$", "(", ")", "<", ">"]
        for char in dangerous_chars:
            if char in command:
                return (
                    Decision.DENY,
                    f"Komut injection riski: tehlikeli karakter '{char}' tespit edildi"
                )
        
        return self.policy_loader.check_process_execution(command)
