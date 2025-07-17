import json
from pathlib import Path


def convert_to_json(rules_dict, output_path: Path):
    suffix_rules = rules_dict.get("suffix", [])

    # 创建规则对象
    rule_objects = []

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

    print(f"已生成规则集: {output_path} (包含 {len(suffix_rules)} 条域名后缀规则)")
