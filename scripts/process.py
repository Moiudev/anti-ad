import re
import requests
import os
from pathlib import Path
from converter import convert_to_json

BASE_DIR = Path(__file__).parent.parent
SOURCES_DIR = BASE_DIR / "rules"
SOURCES_LIST = BASE_DIR / "sources.txt"
OUTPUT_JSON = BASE_DIR / "anti-ad.json"

# 规则源的名称映射
FRIENDLY_NAME_MAP = {
    "https://pgl.yoyo.org/adservers/serverlist.php?showintro=0;hostformat=hosts": "Peter_Lowe.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt": "AdGuard_Base.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt": "AdGuard_Spyware.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt": "AdGuard_Mobile.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt": "AdGuard_Annoyances.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt": "AdGuard_DNS.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt": "AdGuard_Chinese.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/adblock.txt": "1Hosts_Pro.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt": "CJX_Annoyance.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/dnslist.txt": "BanAD_DNS.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/hosts.txt": "BanAD_Hosts.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt": "BanAD_JiekouAD.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt": "HaGeZi_ADBlock_Pro.txt",
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt": "Loyalsoldier_Reject.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts": "StevenBlack_Fakenews_Gambling.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt": "AWAvenue_Ads.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt": "ChengFeng_MV.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt": "ChengFeng_Rule.txt",
    "https://someonewhocares.org/hosts": "DanPollock_Hosts.txt"
}


def load_sources():
    with open(SOURCES_LIST, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def safe_filename(url):
    if url in FRIENDLY_NAME_MAP:
        return FRIENDLY_NAME_MAP[url]

    # 对于不在映射表中的 URL，使用原始文件名
    filename = re.sub(r"[^\w\.-]", "_", url.split("/")[-1].split("?")[0])
    return filename or "unnamed.txt"


def download_rules():
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    # 清空规则目录
    for file in SOURCES_DIR.glob("*"):
        if file.is_file():
            try:
                file.unlink()
                print(f"已删除旧规则文件: {file.name}")
            except Exception as e:
                print(f"删除文件失败 {file.name}: {str(e)}")

    rule_sources = load_sources()
    total = len(rule_sources)

    print(f"开始下载 {total} 个规则源...")

    for i, url in enumerate(rule_sources, 1):
        try:
            print(f"下载中 ({i}/{total}): {url}")
            response = requests.get(url, timeout=20)
            response.raise_for_status()

            filename = safe_filename(url)
            filepath = SOURCES_DIR / filename

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"下载成功: {filename}")
        except Exception as e:
            print(f"下载失败 [{url}]: {str(e)}")

    print("所有规则源下载完成！")


def is_valid_domain(domain):
    """验证域名是否有效"""
    pattern = r"^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None


def classify_rule(rule_str):
    """
    将规则分类为完整域名匹配
    返回元组 ("exact", domain) 或 None
    """
    rule = rule_str.strip()

    # 跳过注释和例外规则
    if not rule or rule.startswith(("!", "#", "@@", "//", "[")) or "##" in rule:
        return None

    # 处理 ||domain^ 格式 - 转换为完整域名
    if rule.startswith("||") and rule.endswith("^"):
        domain = rule[2:-1]
        if domain and is_valid_domain(domain):
            # 作为完整域名添加到规则集
            return ("exact", domain.lower())

    # 处理完整域名规则
    if is_valid_domain(rule):
        return ("exact", rule.lower())

    # 处理hosts格式规则
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+", rule):
        domains = re.split(r"\s+", rule)[1:]
        return [
            ("exact", d.lower())
            for d in domains
            if d and not d.startswith(("#", "!")) and is_valid_domain(d)
        ]

    # 处理纯域名规则
    if '.' in rule and ' ' not in rule and not any(c in rule for c in ['/', ':', '!', '#']):
        if is_valid_domain(rule):
            return ("exact", rule.lower())

    return None


def process_rules():
    exact_rules = set()

    # 获取所有规则文件
    rule_files = list(SOURCES_DIR.glob("*"))
    total_files = len(rule_files)

    if total_files == 0:
        print("警告: 没有找到任何规则文件！")
        return {"exact": []}

    print(f"开始处理 {total_files} 个规则文件...")

    for i, file in enumerate(rule_files, 1):
        try:
            print(f"处理文件 ({i}/{total_files}): {file.name}")
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
                    else:
                        match_type, value = result
                        if match_type == "exact":
                            exact_rules.add(value)
        except Exception as e:
            print(f"处理文件 {file.name} 时出错: {str(e)}")

    return {"exact": sorted(exact_rules)}


def main():
    print("----- 开始规则处理 -----")
    download_rules()

    print("----- 处理规则内容 -----")
    rules_dict = process_rules()

    exact_count = len(rules_dict["exact"])

    print(f"规则统计: 完整域名匹配 - {exact_count}")

    print("----- 生成规则集 -----")
    convert_to_json(rules_dict, OUTPUT_JSON)
    print("处理完成！🎉🎉🎉")


if __name__ == "__main__":
    main()
