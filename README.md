# 节点池自动清洗流水线

每天在 GitHub Actions 上跑一次：拉全网免费订阅 → 用 mihomo 内核真机测速 → 只留能用的 → 生成极简配置。
你设备上不需要装任何东西，只需要订阅一个 URL。

## 一、它做什么

```
每天 11:17（北京时间）
   │
   ├─ 采集：20 个订阅源（clash yaml / 分享链接 / base64 全支持）
   ├─ 测速：mihomo 内核并发测延迟（墙外 runner，测的是真连通性）
   ├─ 带宽：对延迟通过的节点实测下载速度，>30KB/s 才留
   ├─ 生成：极简配置（2 个策略组）+ 兜底 WARP
   └─ 提交：dist/clash.yaml 更新到仓库
```

产出的配置结构（只有 2 个组）：

| 策略组 | 类型 | 作用 |
|---|---|---|
| `AUTO` | url-test | 每 180 秒测一轮，自动选最快 |
| `NODE` | select | 手动指定，默认跟随 AUTO |

规则：YouTube / Google / Netflix / Telegram 走 `AUTO`，国内 GEOIP 直连，其余 `MATCH,AUTO`。

## 二、部署（3 步，一次性）

### 1. 建仓库

打开 <https://github.com/new>，仓库名随便（例如 `node-pool`），**必须选 Public**（公开仓库 Actions 不计费、无限时长）。

### 2. 上传代码

在电脑上执行（把 `你的用户名` 和 `仓库名` 换掉）：

```powershell
cd D:\HuaweiMoveData\Users\Gzb14\Documents\deepseek-harness\default-workspace
powershell -ExecutionPolicy Bypass -File .\push-github.ps1 -User 你的用户名 -Repo node-pool
```

脚本会提示你粘贴 GitHub Token（在 <https://github.com/settings/tokens> 生成，勾选 `repo` 权限）。

### 3. 启用 Actions

仓库页面 → `Actions` 标签 → 如果提示 "Workflows aren't being run on this fork"，点 **I understand my workflows, go ahead and enable them**。
之后点 `daily-node-refresh` → `Run workflow` 手动跑一次，等 5–10 分钟出结果。

## 三、订阅地址

跑完之后，你的配置地址是：

```
https://raw.githubusercontent.com/你的用户名/node-pool/main/dist/clash.yaml
```

如果 raw 被墙，用这两个之一（同一个文件）：

```
https://ghfast.top/https://raw.githubusercontent.com/你的用户名/node-pool/main/dist/clash.yaml
https://cdn.jsdelivr.net/gh/你的用户名/node-pool@main/dist/clash.yaml
```

## 四、平板怎么用（一次设置，永久自动更新）

FlClash → 配置 → 右上 `+` → **链接** → 粘贴上面的地址 → 保存。

然后关键一步：配置卡片 → 长按 → **编辑** → 把「自动更新」改成 **6 小时**（或 24 小时）。
这样每次打开 FlClash 它自己拉最新配置，你什么都不用管。

> 注意：FlClash 的链接框对输入法不友好，用**长按粘贴**，别手打 URL。

## 五、本地调试

```powershell
cd pipeline
pip install pyyaml
python run.py              # 全流程
python run.py collect      # 只拉源（看哪个源还活着）
python run.py probe        # 只测速（需已有 pool.json）
python run.py build        # 只生成配置（需已有 alive.json）
```

Windows 上会自动复用 `../tools/mihomo/mihomo-windows-amd64-compatible.exe`。

## 六、已知的坑（都踩过了）

| 坑 | 现象 | 处理 |
|---|---|---|
| **中文进 txt 就报错** | FlClash 导入报 `yaml: invalid leading UTF-8 octet` | 产出强制 ASCII：注释英文、节点名去中文。`run.py` 里 `_ascii_name()` 负责 |
| **组名改了引用没改** | 报 `proxy group[1]: NODE: '自动' not found` | ASCII 化时组名和组内引用必须同时映射，`build()` 已保证 |
| **url-test 选到 DIRECT** | 直连 29ms 比代理快，YouTube 反而打不通 | `AUTO` 组列表里**不放 DIRECT**；`NODE` 里保留供手动切换 |
| **文件管理器不显示 .yaml** | FlClash 文件选择器里找不到配置 | 推送到设备时统一用 `.txt` 后缀（内容仍是 yaml） |
| **免费节点寿命以小时计** | 早上能用晚上就死 | 这就是要每天跑流水线的原因，自动淘汰 |

## 七、想加自建 Hysteria2

1. 服务器上跑 `deploy-hy2-4k.sh`（脚本会打印 `hysteria2://` 链接）
2. 在 `pipeline/assets/hy2.yaml` 写：

```yaml
proxies:
  - name: SelfHost-Hy2
    type: hysteria2
    server: 你的服务器IP
    port: 443
    ports: 20000-30000
    password: 你的密码
    sni: bing.com
    skip-cert-verify: true
    up: "60 Mbps"
    down: "180 Mbps"
```

3. 提交后，流水线会把它放在 `AUTO` 组**最前面**（优先使用），命名带 `SelfHost-` 前缀。

## 八、成本

| 项目 | 费用 |
|---|---|
| GitHub Actions（公开仓库） | 0 |
| 每次运行时长 | 约 8–12 分钟 |
| 每月流量 | 约 200MB（拉订阅 + 测速） |
| 你的设备 | 只拉一个 yaml，几 KB |
