import hashlib
import idna
import json
import os
import re
import requests
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from converter import convert_to_json
from pathlib import Path


# 基础路径配置
BASE_DIR = Path(__file__).parent.parent
SOURCES_DIR = BASE_DIR / "rules"
SOURCES_LIST = BASE_DIR / "sources.txt"
OUTPUT_JSON = BASE_DIR / "ad.json"
HASH_CACHE = BASE_DIR / "hash_cache.json"

# 请求头配置
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

# 规则源的名称映射
FRIENDLY_NAME_MAP = {
    "https://easylist-downloads.adblockplus.org/easylist.txt": "EasyList.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt": "EasyList_China.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt": "EasyPrivacy.txt",
    "https://hblock.molinero.dev/hosts_adblock.txt": "HBlock_AdBlock.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt": "Phishing_Army.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt": "AdGuard_Base.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt": "AdGuard_Spyware.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt": "AdGuard_Mobile.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt": "AdGuard_Annoyances.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt": "AdGuard_DNS.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt": "AdGuard_Chinese.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/adblock.txt": "1Hosts_ADBlock_Pro.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt": "CJX_Annoyance.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/dnslist.txt": "BanAD_DNS.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt": "BanAD_JiekouAD.txt",
    "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt": "KADhosts.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt": "Hagezi_ADBlock_Pro.txt",
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt": "Loyalsoldier_Reject_List.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts": "StevenBlack_Fakenews_Gambling.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt": "AWAvenue_Ads_Rule.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt": "uBlock_Filters.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt": "ChengFeng_MV.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt": "ChengFeng_Rule.txt",
    "https://someonewhocares.org/hosts": "DanPollock_Hosts.txt",
}


# 加载规则源列表
def load_sources():
    with open(SOURCES_LIST, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# 生成安全的文件名
def safe_filename(url):
    if url in FRIENDLY_NAME_MAP:
        return FRIENDLY_NAME_MAP[url]

    # 对于不在映射表中的 URL，使用原始文件名
    filename = re.sub(r"[^\w\.-]", "_", url.split("/")[-1].split("?")[0])
    return filename or "unnamed.txt"


# 验证域名是否有效 (支持 IDN 域名)
def is_valid_domain(domain):
    # 检查基本长度限制
    if len(domain) > 253 or len(domain) < 1:
        return False

    # 检查首尾字符
    if domain.startswith(".") or domain.endswith("."):
        return False

    # 尝试处理国际化域名 (IDN)
    try:
        domain = idna.encode(domain).decode("ascii")
    except idna.IDNAError:
        return False

    # 验证域名结构
    pattern = r"^([a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])(\.([a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))*$"
    return re.match(pattern, domain) is not None


# 标准化域名
def normalize_domain(domain):
    domain = domain.lower()
    if domain.startswith("www."):
        return domain[4:]
    return domain


# 下载单个规则源
def download_single(url, cache):
    try:
        filename = safe_filename(url)
        filepath = SOURCES_DIR / filename

        print(f"下载中: {url}")
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=25)
        response.raise_for_status()

        # 计算内容哈希
        content = response.text
        content_hash = hashlib.md5(content.encode("utf-8")).hexdigest()

        # 检查是否需要更新
        if url in cache and cache[url] == content_hash and filepath.exists():
            print(f"跳过未更新: {filename}")
            return url, None

        # 保存文件
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"下载成功: {filename}")
        return url, content_hash
    except requests.exceptions.Timeout:
        print(f"下载超时 [{url}]")
        return url, None
    except Exception as e:
        print(f"下载失败 [{url}]: {str(e)}")
        return url, None


# 下载所有规则源 (支持增量更新)
def download_rules():
    # 确保目录存在
    SOURCES_DIR.mkdir(parents=True, exist_ok=True)

    # 加载哈希缓存
    try:
        with open(HASH_CACHE, "r", encoding="utf-8") as f:
            cache = json.load(f)
    except:
        cache = {}

    rule_sources = load_sources()
    total = len(rule_sources)

    print(f"开始处理 {total} 个规则源...")

    # 使用线程池并行下载
    updated_cache = cache.copy()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(download_single, url, cache) for url in rule_sources]

        for future in as_completed(futures):
            url, new_hash = future.result()
            if new_hash:
                updated_cache[url] = new_hash

    # 保存更新后的缓存
    with open(HASH_CACHE, "w", encoding="utf-8") as f:
        json.dump(updated_cache, f, indent=2)

    print("所有规则源处理完成！")


# 将规则分类为完整域名、域名后缀或正则表达式
def classify_rule(rule_str):
    rule = rule_str.strip()

    # 跳过注释和例外规则
    if not rule or rule.startswith(("!", "#", "@@", "//", "[")) or "##" in rule:
        return None

    # 处理 ||domain^ 格式 - 转换为域名后缀匹配
    if rule.startswith("||") and rule.endswith("^"):
        domain = rule[2:-1]
        if domain and is_valid_domain(domain):
            # 标准化域名并作为后缀规则
            return ("suffix", normalize_domain(domain))

    # 处理完整域名规则 - 转换为后缀规则
    if is_valid_domain(rule):
        return ("suffix", normalize_domain(rule))

    # 处理hosts格式规则
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+", rule):
        domains = re.split(r"\s+", rule)[1:]
        return [
            ("suffix", normalize_domain(d))
            for d in domains
            if d and not d.startswith(("#", "!")) and is_valid_domain(d)
        ]

    # 处理正则表达式规则
    if rule.startswith("/") and rule.endswith("/"):
        regex_pattern = rule[1:-1]
        # 简单验证正则表达式有效性
        try:
            re.compile(regex_pattern)
            return ("regex", regex_pattern)
        except re.error:
            return None

    # 处理域名后缀规则 (*.example.com)
    if rule.startswith("*.") and is_valid_domain(rule[2:]):
        return ("suffix", normalize_domain(rule[2:]))

    # 处理通配符域名规则
    if "*" in rule and "." in rule and not any(c in rule for c in ["/", ":", "!", "#"]):
        # 尝试转换为域名后缀
        if rule.startswith("*.") and is_valid_domain(rule[2:]):
            return ("suffix", normalize_domain(rule[2:]))

        # 尝试转换为正则表达式
        try:
            # 将通配符转换为正则表达式
            regex_pattern = rule.replace(".", r"\.").replace("*", ".*")
            re.compile(regex_pattern)  # 验证有效性
            return ("regex", regex_pattern)
        except re.error:
            return None

    return None


# 处理所有规则文件
def process_rules():
    suffix_rules = set()
    regex_rules = set()

    # 获取所有规则文件
    rule_files = list(SOURCES_DIR.glob("*"))
    total_files = len(rule_files)

    if total_files == 0:
        print("警告: 没有找到任何规则文件！")
        return {"suffix": [], "regex": []}

    print(f"开始处理 {total_files} 个规则文件...")

    for i, file in enumerate(rule_files, 1):
        try:
            print(f"处理文件 ({i}/{total_files}): {file.name}")
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    result = classify_rule(line)
                    if not result:
                        continue

                    # 处理单条规则或多条规则
                    if isinstance(result, list):
                        for item in result:
                            rule_type, value = item
                            if rule_type == "suffix":
                                suffix_rules.add(value)
                            elif rule_type == "regex":
                                regex_rules.add(value)
                    else:
                        rule_type, value = result
                        if rule_type == "suffix":
                            suffix_rules.add(value)
                        elif rule_type == "regex":
                            regex_rules.add(value)
        except Exception as e:
            print(f"处理文件 {file.name} 时出错: {str(e)}")

    # 返回处理后的规则
    return {"suffix": sorted(suffix_rules), "regex": sorted(regex_rules)}


def main():
    print("----- 开始规则处理 -----")
    download_rules()

    print("----- 处理规则内容 -----")
    rules_dict = process_rules()

    print("----- 生成规则集 -----")
    convert_to_json(rules_dict, OUTPUT_JSON)

    # 打印统计信息
    suffix_count = len(rules_dict["suffix"])
    regex_count = len(rules_dict["regex"])
    total = suffix_count + regex_count
    print(
        f"规则统计: 域名后缀 - {suffix_count}, 正则表达式 - {regex_count}, 总计 - {total}"
    )
    print("处理完成！🎉🎉🎉")


if __name__ == "__main__":
    main()
