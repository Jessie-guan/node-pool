# -*- coding: utf-8 -*-
"""
discover.py —— 自动发现新的节点源（全网搜索，可持续迭代）

三条发现路径：
  1. GitHub 仓库搜索：按关键词找最近活跃的节点仓库，提取 raw 链接
  2. 已知聚合站深挖：从聚合站的目录页找子链接
  3. 交叉引用：从已抓到的源里提取 "referenced" 仓库名

验证：拉取 → 解析 → 至少 5 个有效节点才算通过 → 写入 sources.txt

用法：
  python discover.py            # 默认跑一轮
  python discover.py --dry      # 只打印不写入
  python discover.py --limit 30 # 最多新增 30 个源
"""
import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = os.path.join(HERE, "sources.txt")
RETIRED = os.path.join(HERE, "retired.txt")
DISCOVERED = os.path.join(HERE, "discovered.json")

# GitHub token（可选，有的话搜索额度 5000/小时，没有 60/小时）
GH_TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""

REQ_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"

# 搜索关键词（GitHub 仓库）
KEYWORDS = [
    "clash free nodes",
    "v2ray free subscribe",
    "free proxies clash",
    "clash meta nodes",
    "机场 节点 订阅",
    "ssr v2ray 免费节点",
    "free vmess subscribe",
    "clash node pool",
    "proxy pool clash",
    "free node daily",
]

# 已知会持续更新的仓库（白名单，直接尝试常见路径）
KNOWN_REPOS = [
    "peasoft/NoMoreWalls",
    "ripaojiedian/freenode",
    "ermaozi/get_subscribe",
    "aiboboxx/clashfree",
    "aiboboxx/v2rayfree",
    "mahdibland/V2RayAggregator",
    "mahdibland/ShadowsocksAggregator",
    "anaer/Sub",
    "chengaopan/AutoMergePublicNodes",
    "Barabama/FreeNodes",
    "mfuu/v2ray",
    "ts-sf/fly",
    "vveg26/get_proxy",
    "Leon406/SubCrawler",
    "snakem982/proxypool",
    "freefq/free",
    "Pawdroid/Free-servers",
    "ndsx2002/Collect-Node",
    "wrfree/free",
    "ZywChannel/free",
    "mianfeifq/share",
    "Jsnzkpg/Jsnzkpg",
    "Flik6/getNode",
    "a2479072579/free-node",
]

# 常见文件名（拼在仓库后面的路径候选）
COMMON_PATHS = [
    "clash.yaml", "clash.yml", "clash-meta.yaml", "clash.config.yaml",
    "sub/sub_merge.txt", "sub/sub_merge_base64.txt",
    "dist/clash.yaml", "dist/clash.config.yaml",
    "main/clash.yaml", "output/clash.yaml",
    "list.yml", "list.yaml", "list.txt",
    "all.txt", "all.yaml", "all.yml",
    "v2", "v2ray.txt", "v2ray", "nodes.txt", "nodefree.txt",
    "main.yml", "share/all", "sub/share/all",
    "Eternity.yml", "clash.yml",
]


def log(msg):
    print(msg, flush=True)


def gh_api(path, timeout=20):
    """GitHub API 请求"""
    headers = {"User-Agent": REQ_UA, "Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"token {GH_TOKEN}"
    req = urllib.request.Request("https://api.github.com" + path, headers=headers)
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return json.loads(op.open(req, timeout=timeout).read().decode())


def fetch(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": "clash-meta/1.19"})
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return op.open(req, timeout=timeout).read()


def count_nodes(raw):
    """粗略统计一个源能产出多少节点"""
    try:
        text = raw.decode("utf-8", "ignore")
    except Exception:
        return 0
    if not text or len(text) < 100:
        return 0

    # YAML 格式：数 name: 或 proxies:
    if "proxies:" in text:
        n = len(re.findall(r"^\s*-\s*\{?\s*name:", text, re.M))
        if n == 0:
            n = len(re.findall(r"name:\s*", text)) // 3
        return n

    # 分享链接格式
    if "://" in text:
        return len(re.findall(r"(?:ss|vmess|vless|trojan|hysteria2|hy2|tuic)://", text))

    # base64
    try:
        import base64
        s = text.strip().replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        dec = base64.b64decode(s).decode("utf-8", "ignore")
        return len(re.findall(r"(?:ss|vmess|vless|trojan|hysteria2|hy2|tuic)://", dec))
    except Exception:
        return 0


def validate(url):
    """验证一个源，返回节点数（0 = 无效）"""
    try:
        raw = fetch(url)
        return count_nodes(raw)
    except Exception:
        return 0


def search_github(keyword, per_page=10):
    """GitHub 搜索仓库，返回 [(owner/repo, stars, updated)]"""
    try:
        q = urllib.parse.quote(keyword)
        d = gh_api(f"/search/repositories?q={q}&sort=updated&order=desc&per_page={per_page}")
        out = []
        for item in d.get("items", []):
            full = item.get("full_name", "")
            if not full:
                continue
            out.append((full, item.get("stargazers_count", 0),
                        item.get("updated_at", "")[:10]))
        return out
    except Exception as e:
        log(f"  搜索失败 [{keyword}]: {type(e).__name__}")
        return []


def build_candidates():
    """构造候选 URL 列表"""
    cands = set()

    # 1) 已知仓库 + 常见路径
    for repo in KNOWN_REPOS:
        for path in COMMON_PATHS:
            for branch in ("main", "master"):
                cands.add(f"https://raw.githubusercontent.com/{repo}/{branch}/{path}")

    # 2) GitHub 搜索
    log("GitHub 搜索仓库...")
    seen_repos = set()
    for kw in KEYWORDS:
        repos = search_github(kw, per_page=8)
        for full, stars, upd in repos:
            if full in seen_repos:
                continue
            seen_repos.add(full)
            # 只尝试 star >= 3 的（太低质量差）
            if stars < 3:
                continue
            for path in COMMON_PATHS[:14]:
                for branch in ("main", "master"):
                    cands.add(f"https://raw.githubusercontent.com/{full}/{branch}/{path}")
        time.sleep(0.8)

    log(f"候选 URL: {len(cands)} 个")
    return cands


def main():
    dry = "--dry" in sys.argv
    limit = 30
    for i, a in enumerate(sys.argv):
        if a == "--limit" and i + 1 < len(sys.argv):
            try:
                limit = int(sys.argv[i + 1])
            except Exception:
                pass

    # 现有源（含淘汰的，避免重复发现）
    existing = set()
    if os.path.exists(SOURCES):
        existing |= {l.strip() for l in io.open(SOURCES, encoding="utf-8")
                     if l.strip() and not l.strip().startswith("#")}
    if os.path.exists(RETIRED):
        for line in io.open(RETIRED, encoding="utf-8"):
            if line.strip() and not line.startswith("#"):
                existing.add(line.split("\t")[0].strip())

    log(f"现有源 {len(existing)} 个（含已淘汰）")

    cands = build_candidates()
    todo = [u for u in cands if u not in existing]
    log(f"待验证 {len(todo)} 个")

    log("并发验证...")
    good = []
    done = [0]

    def work(u):
        n = validate(u)
        done[0] += 1
        if done[0] % 100 == 0:
            log(f"  进度 {done[0]}/{len(todo)}  有效 {len(good)}")
        return (u, n)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=40) as ex:
        for u, n in ex.map(work, todo):
            if n >= 5:      # 至少 5 个节点才算有效源
                good.append((u, n))

    good.sort(key=lambda x: -x[1])
    log(f"验证完成 {time.time()-t0:.0f}s，有效 {len(good)} 个")

    if not good:
        log("没有发现新源")
        return

    # 去重：同域名同路径只留节点最多的
    picked, seen_key = [], set()
    for u, n in good:
        p = urllib.parse.urlparse(u)
        key = (p.netloc, p.path)
        if key in seen_key:
            continue
        seen_key.add(key)
        picked.append((u, n))
        if len(picked) >= limit:
            break

    log(f"\n=== 新增 {len(picked)} 个源 ===")
    for u, n in picked:
        log(f"  +{n:<5d} {u}")

    if dry:
        log("\n[--dry] 未写入")
        return

    # 写入 sources.txt
    lines = []
    if os.path.exists(SOURCES):
        lines = [l.rstrip("\n") for l in io.open(SOURCES, encoding="utf-8")]
    lines.append("")
    lines.append(f"# ===== 自动发现 {time.strftime('%Y-%m-%d %H:%M')} =====")
    for u, n in picked:
        lines.append(u)
    io.open(SOURCES, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")

    # 记录发现历史
    hist = {}
    if os.path.exists(DISCOVERED):
        try:
            hist = json.load(io.open(DISCOVERED, encoding="utf-8"))
        except Exception:
            pass
    for u, n in picked:
        hist[u] = {"found_at": time.strftime("%Y-%m-%d %H:%M"), "nodes": n}
    json.dump(hist, io.open(DISCOVERED, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    log(f"\n已写入 sources.txt，共 {len(lines)} 行")
    log(f"发现历史已记录到 discovered.json")


if __name__ == "__main__":
    main()
