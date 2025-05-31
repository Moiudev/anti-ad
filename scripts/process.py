import re
import requests
import os
from pathlib import Path
from converter import convert_to_json

BASE_DIR = Path(__file__).parent.parent
SOURCES_DIR = BASE_DIR / "rules"
SOURCES_LIST = BASE_DIR / "sources.txt"
OUTPUT_JSON = BASE_DIR / "anti-ad.json"


def load_sources():
    with open(SOURCES_LIST, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def safe_filename(url):
    filename = re.sub(r"[^\w\.-]", "_", url.split("/")[-1].split("?")[0])
    return filename or "unnamed.txt"


def download_rules():
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    for file in SOURCES_DIR.glob("*"):
        if file.is_file():
            file.unlink()

    rule_sources = load_sources()
    for url in rule_sources:
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()

            filename = safe_filename(url)
            filepath = SOURCES_DIR / filename

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"下载成功: {filename}")
        except Exception as e:
            print(f"下载失败 [{url}]: {str(e)}")


def is_valid_domain(domain):
    pattern = r"^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None


def classify_rule(rule_str):
    rule = rule_str.strip()

    if not rule or rule.startswith(("!", "#", "@@", "//", "[")) or "##" in rule:
        return None

    if rule.startswith("||") and rule.endswith("^"):
        domain = rule[2:-1]
        if domain and is_valid_domain(domain):
            return ("suffix", f".{domain}")

    if is_valid_domain(rule):
        return ("exact", rule.lower())

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+", rule):
        domains = re.split(r"\s+", rule)[1:]
        return [
            ("exact", d.lower())
            for d in domains
            if d and not d.startswith(("#", "!")) and is_valid_domain(d)
        ]

    if rule.startswith(".") and is_valid_domain(rule[1:]):
        return ("suffix", rule.lower())

    if '.' in rule and ' ' not in rule and not any(c in rule for c in ['/', ':', '!', '#']):
        if is_valid_domain(rule):
            return ("exact", rule.lower())

    return None


def process_rules():
    exact_rules = set()
    suffix_rules = set()

    for file in SOURCES_DIR.glob("*"):
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    result = classify_rule(line)
                    if not result:
                        continue

                    if isinstance(result, list):
                        for item in result:
                            match_type, value = item
                            if match_type == "exact":
                                exact_rules.add(value)
                            elif match_type == "suffix":
                                suffix_rules.add(value)
                    else:
                        match_type, value = result
                        if match_type == "exact":
                            exact_rules.add(value)
                        elif match_type == "suffix":
                            suffix_rules.add(value)
        except Exception as e:
            print(f"处理文件 {file.name} 时出错: {str(e)}")

    return {
        "exact": sorted(exact_rules),
        "suffix": sorted(suffix_rules)
    }


def main():
    download_rules()

    rules_dict = process_rules()

    convert_to_json(rules_dict, OUTPUT_JSON)


if __name__ == "__main__":
    main()
