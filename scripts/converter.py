import json
from pathlib import Path

def convert_to_json(rules_dict, output_path: Path):
    exact_rules = rules_dict.get("exact", [])

    # 创建规则对象
    rule_objects = [{
        "domain": exact_rules
    }] if exact_rules else []

    ruleset = {
        "version": 3,
        "rules": rule_objects
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, indent=2, ensure_ascii=False)

    print(f"已生成规则集: {output_path} (包含 {len(exact_rules)} 条完整域名匹配规则。)")
