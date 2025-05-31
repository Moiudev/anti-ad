import json
from pathlib import Path

def convert_to_json(rules_dict, output_path: Path):
    exact_rules = rules_dict.get("exact", [])
    suffix_rules = rules_dict.get("suffix", [])

    rule_objects = []

    if exact_rules:
        rule_objects.append({
            "domain": exact_rules
        })

    if suffix_rules:
        rule_objects.append({
            "domain_suffix": suffix_rules
        })

    ruleset = {
        "version": 3,
        "rules": rule_objects
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, indent=2, ensure_ascii=False)