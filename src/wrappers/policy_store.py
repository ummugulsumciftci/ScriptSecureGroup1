from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Rule:
    id: str
    effect: str          # "allow" veya "deny"
    resource_type: str
    resource: str
    action: str

class PolicyStore:
    def __init__(self):
        self.rules: List[Rule] = []

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def match_rule(self, resource_type: str, action: str, resource: str) -> Optional[Rule]:
        # Kuralları sırayla kontrol et (Basit eşleştirme)
        for rule in self.rules:
            if (rule.resource_type == resource_type and 
                rule.action == action and 
                rule.resource == resource):
                return rule
        return None