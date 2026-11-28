# -*- coding: utf-8 -*-
"""
prune.py —— 源健康度管理（自动淘汰无效源，可持续迭代）

思路：
  每次跑完流水线，记录每个源的产出（返回几个节点、是否报错），
  连续 N 次零产出 → 自动移到 retired.txt（不再抓）
  连续 M 次有产出 → 从 retired.txt 恢复

文件：
  sources.txt    活跃源（每行一个 URL）
  retired.txt    已淘汰源（每行 "URL<TAB>淘汰时间<TAB>原因"）
  source_stats.json  统计（每个源的历史表现）

用法：
  python prune.py check     # 检查并更新统计（跑在 collect 之后）
  python prune.py report    # 打印源健康报告
  python prune.py revive    # 手动恢复所有淘汰源（重试）
"""
import io
import json
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = os.path.join(HERE, "sources.txt")
RETIRED = os.path.join(HERE, "retired.txt")
STATS = os.path.join(HERE, "source_stats.json")

# 淘汰阈值：连续 3 次零产出就淘汰
RETIRE_AFTER = 3
# 恢复阈值：淘汰源重试时只要有产出就恢复
REVIVE_MIN = 1


def load_sources():
    if not os.path.exists(SOURCES):
        return []
    return [l.strip() for l in io.open(SOURCES, encoding="utf-8")
            if l.strip() and not l.strip().startswith("#")]


def load_retired():
    if not os.path.exists(RETIRED):
        return []
    rows = []
    for line in io.open(RETIRED, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        rows.append({
            "url": parts[0],
            "retired_at": parts[1] if len(parts) > 1 else "",
            "reason": parts[2] if len(parts) > 2 else "",
        })
    return rows


def load_stats():
    if not os.path.exists(STATS):
        return {}
    try:
        return json.load(io.open(STATS, encoding="utf-8"))
    except Exception:
        return {}


def save_stats(stats):
    json.dump(stats, io.open(STATS, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1, sort_keys=True)


def check(collect_log=None):
    """根据最近一次 collect 的结果更新统计，自动淘汰/恢复源"""
    stats = load_stats()
    retired = {r["url"] for r in load_retired()}
    active = load_sources()

    # collect.py 应该写一个 collect_result.json：{"url": {"count": N, "error": null|str}}
    result_file = os.path.join(HERE, "collect_result.json")
    if not os.path.exists(result_file):
        print("[prune] 没有 collect_result.json，跳过（先跑 collect）")
        return

    result = json.load(io.open(result_file, encoding="utf-8"))
    now = time.strftime("%Y-%m-%d %H:%M")

    to_retire, to_revive = [], []
    for url, info in result.items():
        st = stats.setdefault(url, {
            "runs": 0, "zero_streak": 0, "total_nodes": 0,
            "last_count": 0, "last_error": None, "last_seen": "",
        })
        cnt = int(info.get("count") or 0)
        err = info.get("error")

        st["runs"] += 1
        st["last_count"] = cnt
        st["last_error"] = err
        st["last_seen"] = now
        st["total_nodes"] += cnt

        if cnt > 0:
            st["zero_streak"] = 0
            # 淘汰源重新有产出 → 恢复
            if url in retired and cnt >= REVIVE_MIN:
                to_revive.append(url)
        else:
            st["zero_streak"] = st.get("zero_streak", 0) + 1

        # 连续零产出达到阈值 → 淘汰
        if (st["zero_streak"] >= RETIRE_AFTER
                and url not in retired
                and url not in to_retire):
            reason = err or f"连续{st['zero_streak']}次零产出"
            to_retire.append((url, reason))

    save_stats(stats)

    # ---- 执行淘汰 ----
    if to_retire:
        retire_set = {u for u, _ in to_retire}
        keep = [u for u in active if u not in retire_set]
        io.open(SOURCES, "w", encoding="utf-8", newline="\n").write(
            "\n".join(keep) + "\n")

        existing = load_retired()
        for url, reason in to_retire:
            existing.append({"url": url, "retired_at": now, "reason": reason})
        write_retired(existing)
        print(f"[prune] 淘汰 {len(to_retire)} 个源 → retired.txt")
        for u, r in to_retire:
            print(f"  - {short(u)}  ({r})")

    # ---- 执行恢复 ----
    if to_revive:
        rev_set = set(to_revive)
        existing = [r for r in load_retired() if r["url"] not in rev_set]
        write_retired(existing)
        cur = load_sources()
        cur.extend(to_revive)
        io.open(SOURCES, "w", encoding="utf-8", newline="\n").write(
            "\n".join(cur) + "\n")
        print(f"[prune] 恢复 {len(to_revive)} 个源")
        for u in to_revive:
            print(f"  + {short(u)}")

    if not to_retire and not to_revive:
        print("[prune] 源列表无变化")


def write_retired(rows):
    lines = ["# 已淘汰的源（连续多次零产出）",
             "# 格式：URL<TAB>淘汰时间<TAB>原因"]
    for r in rows:
        lines.append(f'{r["url"]}\t{r.get("retired_at","")}\t{r.get("reason","")}')
    io.open(RETIRED, "w", encoding="utf-8", newline="\n").write(
        "\n".join(lines) + "\n")


def report():
    stats = load_stats()
    active = load_sources()
    retired = load_retired()

    print(f"=== 源健康报告 ===")
    print(f"活跃源：{len(active)}")
    print(f"淘汰源：{len(retired)}")

    if stats:
        rows = []
        for url, st in stats.items():
            rows.append((st.get("last_count", 0), st.get("runs", 0),
                         st.get("zero_streak", 0), url))
        rows.sort(key=lambda x: -x[0])

        print(f"\n--- 产出最高的 15 个 ---")
        for cnt, runs, zs, url in rows[:15]:
            print(f"  +{cnt:<5d} ({runs}次)  {short(url)}")

        print(f"\n--- 零产出最多的 15 个 ---")
        rows.sort(key=lambda x: (-x[2], x[1]))
        for cnt, runs, zs, url in rows[:15]:
            if zs == 0:
                continue
            print(f"  连续{zs}次零产出  {short(url)}")

    if retired:
        print(f"\n--- 已淘汰 ---")
        for r in retired[:20]:
            print(f"  {short(r['url'])}  {r.get('retired_at','')}  {r.get('reason','')}")


def revive():
    retired = load_retired()
    if not retired:
        print("[prune] 没有淘汰源")
        return
    active = load_sources()
    active.extend(r["url"] for r in retired)
    io.open(SOURCES, "w", encoding="utf-8", newline="\n").write(
        "\n".join(active) + "\n")
    write_retired([])
    print(f"[prune] 全部恢复 {len(retired)} 个源，下一轮会重新验证")


def short(url):
    """短显示"""
    try:
        p = url.split("/")
        host = p[2] if len(p) > 2 else url
        tail = "/".join(p[3:])[:36]
        return f"{host}/{tail}"
    except Exception:
        return url[:50]


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "check":
        check()
    elif cmd == "report":
        report()
    elif cmd == "revive":
        revive()
    else:
        print(f"未知命令: {cmd}")
        print("用法: python prune.py [check|report|revive]")
