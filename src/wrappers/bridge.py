# bridge.py
import sys
import json
import os
from pathlib import Path

# Python path ayarı (import hatası almamak için)
sys.path.append(str(Path(__file__).parent))

from engine import AuthorizationEngine
from models import AuthorizationRequest
from policy_store import PolicyStore, Rule

def get_engine_with_rules():
    """
    JS Testleri için özel kuralları yükler.
    Gerçek senaryoda bu kurallar veritabanından gelir.
    """
    store = PolicyStore()
    
    # KURAL: js_allowed.txt dosyasına OKUMA izni ver
    store.add_rule(Rule(
        id="js-rule-1",
        effect="allow",
        resource_type="file",
        resource="js_allowed.txt", # Sadece dosya ismi kontrolü yapıyoruz basitlik için
        action="read"
    ))
    
    return AuthorizationEngine(store)

def main():
    try:
        # 1. Node.js'den gelen argümanı (JSON) al
        if len(sys.argv) < 2:
            print(json.dumps({"decision": "deny", "reason": "No input provided"}))
            return

        input_json = sys.argv[1]
        data = json.loads(input_json)

        # 2. Engine'i hazırla
        engine = get_engine_with_rules()

        # 3. İsteği oluştur
        request = AuthorizationRequest(
            script_id="node_script_1",
            language="javascript",
            resource_type=data.get("resource_type"),
            resource=data.get("resource"),
            action=data.get("action")
        )

        # 4. Karar ver
        decision = engine.evaluate(request)

        # 5. Sonucu JSON olarak yazdır
        response = {
            "decision": decision.decision.value, # "allow" veya "deny"
            "reason": decision.reason
        }
        print(json.dumps(response))

    except Exception as e:
        # Hata olursa güvenli taraf (DENY)
        print(json.dumps({"decision": "deny", "reason": f"Bridge Error: {str(e)}"}))

if __name__ == "__main__":
    main()