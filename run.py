# -*- coding: utf-8 -*-
"""
run.py —— 节点池清洗流水线（在 GitHub Actions 上每天跑一次）

流程：
  1. collect  拉全网订阅源，解析成 mihomo proxies
  2. probe    用 mihomo 内核并发测延迟 + 抽样测带宽，只留真能用的
  3. build    生成极简配置（2 个策略组），写到 dist/clash.yaml

用法：
  python run.py              # 全流程
  python run.py collect      # 只拉源
  python run.py probe        # 只测速（需已有 pool.json）
  python run.py build        # 只生成配置（需已有 alive.json）
"""
import base64
import collections
import io
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
POOL_JSON = os.path.join(HERE, "pool.json")
ALIVE_JSON = os.path.join(HERE, "alive.json")
DIST_DIR = os.path.join(HERE, "dist")
WORK = os.path.join(HERE, "_work")

API = "http://127.0.0.1:19090"
MIXED = 17890
TEST_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=30000000"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

KEEP_TYPES = {"ss", "vmess", "vless", "trojan", "hysteria2", "hysteria", "tuic", "anytls"}


def log(msg):
    print(msg, flush=True)


# ----------------------------------------------------------------------------
# 1. 采集
# ----------------------------------------------------------------------------

def _b64(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def parse_share_link(line):
    try:
        if line.startswith("ss://"):
            body = line[5:]
            name = ""
            if "#" in body:
                body, frag = body.split("#", 1)
                name = urllib.parse.unquote(frag)
            body = body.split("?")[0]
            if "@" in body:
                userpart, hostport = body.rsplit("@", 1)
                dec = _b64(userpart)
                method, password = (dec.split(":", 1) if ":" in dec else userpart.split(":", 1))
            else:
                dec = _b64(body)
                userpart, hostport = dec.rsplit("@", 1)
                method, password = userpart.split(":", 1)
            host, port = hostport.rsplit(":", 1)
            return {"name": name or f"{host}:{port}", "type": "ss", "server": host,
                    "port": int(port), "cipher": method, "password": password, "udp": True}

        if line.startswith("vmess://"):
            j = json.loads(_b64(line[8:]))
            port = int(j.get("port", 0))
            if not j.get("add") or not port:
                return None
            return {"name": j.get("ps") or f'{j["add"]}:{port}', "type": "vmess",
                    "server": j["add"], "port": port, "uuid": j.get("id", ""),
                    "alterId": int(j.get("aid", 0) or 0), "cipher": "auto",
                    "tls": str(j.get("tls", "")).lower() == "tls",
                    "servername": j.get("sni") or "", "network": j.get("net", "tcp") or "tcp",
                    "skip-cert-verify": True, "udp": True}

        if line.startswith("vless://"):
            u = urllib.parse.urlparse(line)
            if not u.hostname or not u.port:
                return None
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            px = {"name": urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}",
                  "type": "vless", "server": u.hostname, "port": u.port,
                  "uuid": u.username or "", "udp": True, "skip-cert-verify": True}
            sec = q.get("security", "none")
            if sec in ("tls", "reality"):
                px["tls"] = True
                px["servername"] = q.get("sni") or q.get("host") or ""
                if sec == "reality":
                    px["reality-opts"] = {"public-key": q.get("pbk", ""),
                                          "short-id": q.get("sid", "")}
                    px["client-fingerprint"] = q.get("fp", "chrome")
            if q.get("flow"):
                px["flow"] = q["flow"]
            net = q.get("type", "tcp")
            if net == "ws":
                px["network"] = "ws"
                px["ws-opts"] = {"path": q.get("path", "/"),
                                 "headers": {"Host": q["host"]} if q.get("host") else {}}
            elif net == "grpc":
                px["network"] = "grpc"
                px["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
            else:
                px["network"] = "tcp"
            return px

        if line.startswith("trojan://"):
            u = urllib.parse.urlparse(line)
            if not u.hostname or not u.port:
                return None
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            return {"name": urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}",
                    "type": "trojan", "server": u.hostname, "port": u.port,
                    "password": u.username or "", "udp": True, "skip-cert-verify": True,
                    "sni": q.get("sni") or q.get("peer") or ""}

        if line.startswith(("hysteria2://", "hy2://")):
            u = urllib.parse.urlparse(line)
            if not u.hostname or not u.port:
                return None
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            return {"name": urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}",
                    "type": "hysteria2", "server": u.hostname, "port": u.port,
                    "password": u.username or "", "sni": q.get("sni", ""),
                    "skip-cert-verify": True}

        if line.startswith("tuic://"):
            u = urllib.parse.urlparse(line)
            if not u.hostname or not u.port:
                return None
            return {"name": urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}",
                    "type": "tuic", "server": u.hostname, "port": u.port,
                    "uuid": u.username or "", "password": u.password or "",
                    "skip-cert-verify": True}
    except Exception:
        return None
    return None


def load_source(url, timeout=25):
    """一个源可能返回 clash yaml、分享链接列表、或整段 base64"""
    req = urllib.request.Request(url, headers={"User-Agent": "clash-meta/1.19"})
    raw = urllib.request.urlopen(req, timeout=timeout).read()
    text = raw.decode("utf-8", "ignore")

    # 尝试 clash yaml
    try:
        d = yaml.safe_load(text)
        if isinstance(d, dict) and isinstance(d.get("proxies"), list):
            return d["proxies"]
    except Exception:
        pass

    # 尝试整段 base64
    if "://" not in text:
        dec = _b64(text)
        if "://" in dec:
            text = dec

    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" not in line:
            dec = _b64(line)
            if "://" not in dec:
                continue
            line = dec.strip().splitlines()[0].strip()
        px = parse_share_link(line)
        if px:
            out.append(px)
    return out


def collect():
    src_file = os.path.join(HERE, "sources.txt")
    urls = [l.strip() for l in io.open(src_file, encoding="utf-8")
            if l.strip() and not l.strip().startswith("#")]
    log(f"订阅源数量: {len(urls)}")

    nodes, seen = [], set()
    stat = []
    for i, url in enumerate(urls, 1):
        name = urllib.parse.urlparse(url).netloc + urllib.parse.urlparse(url).path[-28:]
        try:
            got = load_source(url)
        except Exception as e:
            stat.append((name, 0, f"{type(e).__name__}"))
            log(f"  [{i}/{len(urls)}] {name[:46]:48s} 失败 {type(e).__name__}")
            continue
        added = 0
        for px in got:
            if not isinstance(px, dict):
                continue
            if px.get("type") not in KEEP_TYPES:
                continue
            srv, port = px.get("server"), px.get("port")
            if not srv or not port:
                continue
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            key = (str(srv), port, px["type"])
            if key in seen:
                continue
            seen.add(key)
            nm = str(px.get("name") or f"{srv}:{port}").strip()[:60]
            px["name"] = nm
            nodes.append(px)
            added += 1
        stat.append((name, added, "ok"))
        log(f"  [{i}/{len(urls)}] {name[:46]:48s} +{added:<5d} 累计 {len(nodes)}")

    # 重名去重（同名会让 mihomo 报错）
    counter = collections.Counter()
    for px in nodes:
        counter[px["name"]] += 1
        if counter[px["name"]] > 1:
            px["name"] = f'{px["name"]}#{counter[px["name"]]}'

    json.dump(nodes, io.open(POOL_JSON, "w", encoding="utf-8"), ensure_ascii=False)
    log(f"\n采集完成：{len(nodes)} 个节点 -> pool.json")
    log("协议分布: " + str(dict(collections.Counter(n["type"] for n in nodes))))
    return nodes


# ----------------------------------------------------------------------------
# 2. 测速
# ----------------------------------------------------------------------------

def get_mihomo():
    os.makedirs(WORK, exist_ok=True)
    exe = os.path.join(WORK, "mihomo.exe" if sys.platform.startswith("win") else "mihomo")

    # 本地已有内核直接用（离线/复用）
    if os.path.exists(exe):
        return exe
    local = os.path.join(os.path.dirname(HERE), "tools", "mihomo",
                         "mihomo-windows-amd64-compatible.exe")
    if sys.platform.startswith("win") and os.path.exists(local):
        shutil.copy(local, exe)
        return exe

    ver = "v1.19.34"
    if sys.platform.startswith("win"):
        fname = f"mihomo-windows-amd64-compatible-{ver}.zip"
    else:
        fname = f"mihomo-linux-amd64-{ver}.gz"
    urls = [
        f"https://ghfast.top/https://github.com/MetaCubeX/mihomo/releases/download/{ver}/{fname}",
        f"https://github.com/MetaCubeX/mihomo/releases/download/{ver}/{fname}",
    ]
    import gzip
    import zipfile
    for u in urls:
        try:
            log(f"  下载内核: {u.split('/')[2]}")
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
            data = urllib.request.urlopen(req, timeout=180).read()
            if fname.endswith(".zip"):
                zp = os.path.join(WORK, "mihomo.zip")
                open(zp, "wb").write(data)
                with zipfile.ZipFile(zp) as z:
                    for nm in z.namelist():
                        if nm.lower().endswith(".exe"):
                            open(exe, "wb").write(z.read(nm))
                            break
            else:
                raw = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
                open(exe, "wb").write(raw)
            if not sys.platform.startswith("win"):
                os.chmod(exe, 0o755)
            return exe
        except Exception as e:
            log(f"  失败 {type(e).__name__}")
    raise RuntimeError("mihomo 内核下载失败")


def _api(path, timeout=8):
    return json.load(urllib.request.urlopen(API + path, timeout=timeout))


def _wait_api(sec=30):
    for _ in range(sec):
        try:
            _api("/version", timeout=3)
            return True
        except Exception:
            time.sleep(1)
    return False


def probe(max_nodes=2000, max_test_bandwidth=25):
    nodes = json.load(io.open(POOL_JSON, encoding="utf-8"))
    if len(nodes) > max_nodes:
        log(f"节点过多（{len(nodes)}），截取前 {max_nodes} 个测速")
        nodes = nodes[:max_nodes]
    names = [n["name"] for n in nodes]

    os.makedirs(WORK, exist_ok=True)
    cfg = {
        "mixed-port": MIXED, "allow-lan": False, "mode": "global", "log-level": "warning",
        "external-controller": "127.0.0.1:19090", "secret": "",
        "proxies": nodes,
        "proxy-groups": [{"name": "ALL", "type": "url-test", "url": TEST_URL,
                          "interval": 3600, "tolerance": 5, "lazy": True,
                          "proxies": [n["name"] for n in nodes] + ["DIRECT"]}],
        "rules": ["MATCH,ALL"],
    }
    cfg_path = os.path.join(WORK, "test.yaml")
    io.open(cfg_path, "w", encoding="utf-8").write(
        yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=100000))

    exe = get_mihomo()
    log("启动内核...")
    proc = subprocess.Popen([exe, "-d", WORK, "-f", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not _wait_api():
            raise RuntimeError("内核 API 未就绪")

        d = _api("/proxies")["proxies"]
        skip = {"Selector", "URLTest", "Fallback", "LoadBalance", "Direct",
                "Reject", "Compatible", "Pass", "RejectDrop", "PassRule"}
        targets = [k for k, v in d.items() if v.get("type") not in skip]
        log(f"开始测延迟：{len(targets)} 个")

        results, lock = {}, threading.Lock()
        q = queue.Queue()
        for n in targets:
            q.put(n)
        done = [0]

        def worker():
            while True:
                try:
                    n = q.get_nowait()
                except queue.Empty:
                    return
                path = (f"/proxies/{urllib.parse.quote(n)}/delay"
                        f"?timeout=2500&url={urllib.parse.quote(TEST_URL)}")
                try:
                    r = _api(path, timeout=8)
                    dl = r.get("delay", 0)
                except Exception:
                    dl = 0
                with lock:
                    done[0] += 1
                    if dl and dl > 0:
                        results[n] = dl
                    if done[0] % 400 == 0:
                        log(f"  进度 {done[0]}/{len(targets)}  通过 {len(results)}")

        ths = [threading.Thread(target=worker, daemon=True) for _ in range(100)]
        t0 = time.time()
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        log(f"延迟测试完成 {time.time()-t0:.0f}s，通过 {len(results)} 个")

        # 抽样测带宽
        byname = {n["name"]: n for n in nodes}
        order = sorted(results.items(), key=lambda x: x[1])[:max_test_bandwidth]
        log(f"抽样测带宽：{len(order)} 个")

        def switch(name):
            body = json.dumps({"name": name}).encode()
            req = urllib.request.Request(API + "/proxies/GLOBAL", data=body, method="PUT",
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()

        def measure(sec=5):
            proxy = f"http://127.0.0.1:{MIXED}"
            op = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            t0 = time.time()
            got = 0
            try:
                r = op.open(urllib.request.Request(
                    SPEED_URL, headers={"User-Agent": UA, "Accept": "*/*"}), timeout=12)
                while time.time() - t0 < sec:
                    c = r.read(131072)
                    if not c:
                        break
                    got += len(c)
            except Exception:
                pass
            return got / max(time.time() - t0, 0.001)

        alive = []
        for name, dl in order:
            try:
                switch(name)
                time.sleep(0.6)
                bps = measure()
            except Exception:
                bps = 0
            if bps > 30000:  # >30KB/s 才算真能用
                px = dict(byname[name])
                px["_delay"] = dl
                px["_bps"] = int(bps)
                alive.append(px)
                log(f"  ✅ {bps*8/1048576:6.2f} Mbps  {dl:>4d}ms  {name[:44]}")
            else:
                log(f"  ❌ {bps*8/1048576:6.2f} Mbps  {dl:>4d}ms  {name[:44]}")

        alive.sort(key=lambda x: -x["_bps"])
        json.dump(alive, io.open(ALIVE_JSON, "w", encoding="utf-8"), ensure_ascii=False)
        log(f"\n可上机节点：{len(alive)} / {len(nodes)}")
        return alive
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


# ----------------------------------------------------------------------------
# 3. 生成配置
# ----------------------------------------------------------------------------

def _ascii_name(s):
    """FlClash 解析带中文的 txt 会报 invalid leading UTF-8 octet，统一转 ASCII"""
    s = re.sub(r"[^\x20-\x7E]", "", str(s))
    s = re.sub(r"\s+", " ", s).strip(" -|")
    return s or "node"


def build(max_nodes=40):
    alive = json.load(io.open(ALIVE_JSON, encoding="utf-8")) if os.path.exists(ALIVE_JSON) else []
    if not alive:
        log("没有可用节点，使用兜底节点 + WARP")

    proxies, names = [], []
    seen = set()

    def add(px, alias=None):
        nm = _ascii_name(alias or px["name"])
        base, k = nm, 2
        while nm in seen:
            nm = f"{base}-{k}"
            k += 1
        seen.add(nm)
        q = {k2: v for k2, v in px.items() if not k2.startswith("_")}
        q["name"] = nm
        proxies.append(q)
        names.append(nm)

    # 1) 实测可用节点；若一个都没有，用 assets/fallback.yaml 兜底
    if alive:
        for px in alive[:max_nodes]:
            mbps = int(px["_bps"] * 8 / 1048576)
            add(px, f'{px["name"][:22]} {mbps}M {px["_delay"]}ms')
    else:
        fb = os.path.join(HERE, "assets", "fallback.yaml")
        if os.path.exists(fb):
            items = (yaml.safe_load(io.open(fb, encoding="utf-8")) or {}).get("proxies", [])
            for px in items:
                add(px, px.get("name") or "fallback")
            log(f"  使用兜底节点 {len(items)} 个")

    # 2) WARP（Cloudflare 官方，不失效）
    warp_file = os.path.join(HERE, "assets", "warp.yaml")
    if os.path.exists(warp_file):
        for w in (yaml.safe_load(io.open(warp_file, encoding="utf-8")) or {}).get("proxies", []):
            add(w, "WARP-CF")
    else:
        add({
            "type": "wireguard", "server": "162.159.192.9", "port": 2408,
            "ip": "172.16.0.2",
            "private-key": "MDu1BL3B2IqNF+GliBdV28jBqHS3S8ZgmC/eIkAKMJM=",
            "public-key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "reserved": [242, 213, 200], "mtu": 1280, "udp": True,
        }, "WARP-CF")

    # 3) 自建 Hysteria2（有 assets/hy2.yaml 才加，放最前面优先用）
    hy2_names = []
    hy2_file = os.path.join(HERE, "assets", "hy2.yaml")
    if os.path.exists(hy2_file):
        for h in (yaml.safe_load(io.open(hy2_file, encoding="utf-8")) or {}).get("proxies", []):
            before = len(names)
            add(h, h.get("name") or "SelfHost-Hy2")
            hy2_names = names[before:]

    # ---- 终极极简：只有 1 个策略组，全 ASCII 名 ----
    pool = list(dict.fromkeys(hy2_names + names))

    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "url-test",
             "url": "https://www.gstatic.com/generate_204",
             "interval": 180, "tolerance": 50, "lazy": False,
             "proxies": pool},
        ],
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }

    os.makedirs(DIST_DIR, exist_ok=True)
    body = yaml.safe_dump(cfg, allow_unicode=False, sort_keys=False,
                          default_flow_style=False, width=100000)
    header = ("# auto-generated " + time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()) + "\n"
              f"# available {len(alive)} nodes after cleaning\n"
              "# groups: AUTO (url-test) / NODE (select)\n")
    out = os.path.join(DIST_DIR, "clash.yaml")
    io.open(out, "w", encoding="ascii", newline="\n").write(header + body)

    # 订阅用 base64（部分客户端要）
    b64 = base64.b64encode((header + body).encode()).decode()
    io.open(os.path.join(DIST_DIR, "sub.txt"), "w", encoding="ascii").write(b64)

    log(f"已生成 {out}")
    log(f"  节点 {len(proxies)} 个，策略组 1 个（PROXY）")
    return out


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else "all"
    t0 = time.time()
    if stage in ("all", "collect"):
        collect()
    if stage in ("all", "probe"):
        probe()
    if stage in ("all", "build"):
        build()
    log(f"\n总耗时 {time.time()-t0:.0f}s")
