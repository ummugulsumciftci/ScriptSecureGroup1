import json
from fnmatch import fnmatch
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class Rule:
    id: str
    effect: str
    resource_type: str
    actions: List[str]
    pattern: str


class PolicyStore:

    def __init__(self, rules: List[Rule], default_effect: str = "deny"):
        self.rules = rules
        self.default_effect = default_effect

    @staticmethod
    def load_from_file(path: str) -> "PolicyStore":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        rules = [
            Rule(
                id=r["id"],
                effect=r["effect"],
                resource_type=r["resource_type"],
                actions=r["actions"],
                pattern=r["pattern"],
            )
            for r in data.get("rules", [])
        ]

        return PolicyStore(rules, data.get("default_effect", "deny"))

    def match_rule(self, resource_type: str, action: str, resource: str) -> Optional[Rule]:
        for rule in self.rules:
            if rule.resource_type != resource_type:
                continue
            if action not in rule.actions:
                continue
            if fnmatch(resource, rule.pattern):
                return rule
        return None
