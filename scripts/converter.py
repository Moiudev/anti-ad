import json
from pathlib import Path


def convert_to_json(rules_dict, output_path: Path):
    suffix_rules = rules_dict.get("suffix", [])
    regex_rules = rules_dict.get("regex", [])

    # 创建规则对象 - 只包含后缀和正则规则
    rule_objects = []

    if suffix_rules:
        rule_objects.append({
            "domain_suffix": suffix_rules
        })

    if regex_rules:
        rule_objects.append({
            "domain_regex": regex_rules
        })

    ruleset = {
        "version": 3,
        "rules": rule_objects
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ruleset, f, indent=2, ensure_ascii=False)

    stats = {
        "域名后缀": len(suffix_rules),
        "正则表达式": len(regex_rules)
    }
    total = sum(stats.values())
    print(f"已生成规则集: {output_path} (包含 {total} 条规则)")
    print(f"规则统计: {', '.join([f'{k} - {v}' for k, v in stats.items()])}")
