# qBittorrent 自动反吸血系统（Windows 原生）

面向 qBittorrent **5.3.0**（WebUI API v2，兼容 4.6+）的自动反吸血守护进程。
纯 Python 实现，不修改 qBittorrent 本体，不依赖 Docker，可直接跑在 Windows 上。

- 屏蔽目标：迅雷系、吸血客户端、只下载不上传、异常高流量、伪装客户端
- 策略：自动识别 → 打分 → 自动封禁 → 到期自动解除 → qB 重启后自动补封
- 网络：IPv4 + IPv6
- 三层封禁：SQLite 记录 → qB「手动屏蔽 IP」列表 `banned_IPs`（持久、重启仍生效）→ `transfer/banPeers`（立即断开现有连接）→ 可选 Windows 防火墙

---

## 一、核心设计

```
                 ┌──────────────────────────────────────────┐
                 │            qBittorrent 5.3.0             │
                 │  /sync/maindata  /sync/torrentPeers      │
                 └───────────────┬──────────────────────────┘
                                 │ WebUI API v2
                 ┌───────────────▼──────────────────────────┐
                 │  antileech 守护进程（每 15s 一轮）        │
                 │                                          │
  采集 Peer ──▶ 白名单过滤 ──▶ 行为评分 R1~R7 ──▶ 聚合到 IP  │
                 │                                    │     │
                 │        ┌───────────────────────────┘     │
                 │        ▼                                 │
                 │  分数≥60 或命中硬指纹 → 封禁              │
                 │        │                                 │
                 │        ├─▶ SQLite（bans / events）        │
                 │        ├─▶ banned_IPs（手动屏蔽，重启仍生效）│
                 │        ├─▶ banPeers（立即断开现有连接）    │
                 │        └─▶ 防火墙规则（可选，最硬）        │
                 └──────────────────────────────────────────┘
```

### 为什么不用"客户端名字"作为主判据

qBittorrent 会把 PeerID 解析成客户端名称，但**名称可以伪造**：改个 PeerID 前缀就能自称
qBittorrent。真正难以伪造的是流量行为——`uploaded`（我们上传给它的字节）与
`downloaded`（它回报给我们的字节）由 libtorrent 按连接统计，伪装客户端无法让计数器说谎。

所以系统的主判据是：

> **在同一个种子上，我们给了它很多数据，它的下载进度却长期停在原地，而且几乎不回报任何数据。**

这条特征对"迅雷式只吸不回"极其稳定，同时对正常下载者、做种者、以及"从我们这下、也给我们传"
的互惠 Peer 都不会误伤。

---

## 二、判定规则（R1–R7）

| 编号 | 规则 | 默认阈值 | 分值 | 说明 |
|---|---|---|---|---|
| R1 | 吸血客户端硬指纹 | `xunlei / thunder / 迅雷 / -XL0012- / -SD0100- / qq旋风 / xfplay` | +100（直接封） | 名称或 PeerID 前缀命中即封，不参与打分 |
| R2 | **进度停滞 + 只收不回**（核心） | 连接≥10min，上传≥256MB，进度≤1%，回报率≤2% | +45 | 最主要的判据 |
| R3 | 窗口突发吸血 | 10 分钟内被吸≥256MB 且回报为 0、进度仍停滞 | +30/窗口 | 抓短时间疯狂吸量的 |
| R4 | 伪报完成 | 进度≥99.9% 却仍被持续上传≥128MB | +25 | 逻辑上矛盾的客户端 |
| R5 | 长时间单向吸血 | 连接≥60min，上传≥512MB，下载=0，进度<50% | +40 | 慢速长期吸血 |
| R6 | 客户端伪装 | PeerID 前缀与自称客户端不符 / 版本超过已知上限 / 指纹为空却持续吸量 | +35 / +20 | 需 API 返回 `peer_id`，缺失时自动跳过 |

<del>| R7 | PeerID 农场 | 同一 PeerID 24h 内出现在 ≥3 个不同 IP | +35 | 抓批量伪装 |</del>#qBitAPI获取到的peer_id只有前缀取消R7规则

- 分数会**随时间衰减**（默认 8 分/小时），避免一次瞬时异常被永久记账。
- 同一 IP 在多个种子上的行为会聚合：`总分 = 最高分 + 5 × (种子数-1)`。
- 达到 `ban_threshold`（默认 60）即封禁；R1 无条件立即封禁。
- 正常互惠（`downloaded ≥ uploaded × 50%`）每轮 **-10 分**，用来抵消偶发波动。
### 关闭"版本超出上限"识别（R6 误报）

按影响范围从小到大，三选一。

**1）只放宽某个客户端的上限（推荐，最不容易误伤）**

```json
"detection": {
  "client_version_ceiling": { "qbittorrent": "9.9.9" }
}
```

**2）关掉"版本不可能"这一条，PeerID 伪装检查仍保留**

```json
"detection": {
  "check_client_version": false
}
```

**3）整条 R6 关闭（PeerID 前缀不符、指纹为空也不再判）**

```json
"detection": {
  "enable_fake_client_check": false
}
```

注意：`client_version_ceiling` 是深合并的，写 `{}` **不会**清空默认值，只会保持原样；
要整体停用请写 `null`（1.1.2 起对 `null` 做了安全处理），或者直接用上面的开关。
改完需要重启守护进程 / 计划任务 `QBT-AntiLeech` 才生效。

### 白名单（默认全部放行）

- 私网 / 回环 / 链路本地 / CGNAT：`10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, ::1, fc00::/7, fe80::/10`
- 可在 `whitelist.cidrs` / `whitelist.ips` 追加自己的种子服务器、公司出口、朋友 IP
- `whitelist.allow_private=false` 可关闭私网放行（不建议）

---

## 三、封禁分层与"自动恢复"

| 层 | 作用 | 生效时机 | 失效条件 |
|---|---|---|---|
| SQLite `bans` 表 | 事实来源，记录分数/原因/到期时间 | 立即 | 到期或被手工解除 |
| **手动屏蔽列表** `banned_IPs` | 写入 qB「工具 → 选项 → 连接 → IP 过滤 → 手动屏蔽 IP 地址」，由 qB 持久化 | 同步后立即（通常与封禁同轮） | 解封/到期时从列表移除 |
| `transfer/banPeers` | 立即断开该 IP 已经建立的连接 | 立即 | qB 重启后丢失（会自动补发） |
| Windows 防火墙（可选） | 系统级阻断，连 TCP 握手都进不来 | 立即 | 解封/到期时删除规则 |

**为什么不再用 `ipfilter.dat`**：写文件本身不会让 qB 主动断开已连接的 Peer；Windows 下
文件监视器又不可靠，必须靠"关闭再开启过滤器"强制重载，还会出现约 200ms 的过滤空窗。
手动屏蔽列表走偏好接口 `app/setPreferences`，qB 自己维护、自己持久化，不需要写文件、
不需要 Reload，重启后依然在。

**为什么仍然要 `banPeers`**：`banned_IPs` 和 ipfilter 一样，主要作用于**新连接**；
已经建立的连接不会因为名单更新而自动断开。所以每次封禁会同时对该 IP 当前的连接下发
`banPeers`；后续每轮扫描到黑名单 IP 仍在线时会补发（5 分钟节流），尽力把连接踢掉。

**同步语义（重要）**：`banned_IPs` 是整表替换。系统每次先读取现有列表，剔除"自己上一轮
写入的条目"，再合并当前封禁写回——你在 GUI 里手工加的 IP 永远不会被冲掉。反过来，
如果你在 GUI 里手工删掉一个由系统封禁的 IP，下一轮同步会把它加回来；要解封请用
`unban` 命令，或把它加入白名单。

自动恢复覆盖四种情况：

1. **qB 重启**：会话级 `banPeers` 丢失 → 手动屏蔽列表仍在；对重新连上的黑名单 IP 自动补发 `banPeers`。
2. **WebUI 会话过期**：收到 403 自动重新登录并重试当前请求。
3. **qB 暂时不可用**：指数退避重连（10s → 300s 封顶），进程不退出。
4. **误封**：分数随时间衰减 + 封禁到期自动从列表移除 + `unban` 手工即时解除。

> ⚠️ 两个必须知道的细节：
> 1. qBittorrent 没有公开的"解除会话级封禁"接口。`unban` 会立刻从手动屏蔽列表和数据库
>    移除，并尽力调用 `transfer/unbanPeers`；但 qB 进程内已经记录的 ban 需要重启 qB
>    才会彻底消失。误封后的最干净做法是 `unban <IP>` 后重启一次 qB。
> 2. 如果你的 qB 版本把"手动屏蔽 IP"也实现成纯 ip_filter（只拦新连接），那么"立刻断开"
>    靠的是同一轮下发的 `banPeers`，而不是名单本身。

---

## 四、目录结构

```
qbt-antileech/
├─ antileech/
│  ├─ __main__.py        # python -m antileech 入口
│  ├─ cli.py             # 命令行：run/status/bans/ban/unban/doctor/export
│  ├─ config.py          # 配置合并、路径解析、环境变量覆盖
│  ├─ qbt.py             # WebUI API v2 客户端（登录/重试/403 重认证）
│  ├─ store.py           # SQLite：Peer 状态、封禁、事件、PeerID 索引
│  ├─ rules.py           # R1~R7 评分引擎
│  ├─ blocklist.py       # 手动屏蔽列表 banned_IPs 读写/合并
│  ├─ ipfilter.py        # 旧文件模式（可选，保留兼容）
│  ├─ firewall.py        # 可选 Windows 防火墙封禁
│  └─ engine.py          # 主循环：采集→评分→封禁→解除→状态
├─ deploy/
│  ├─ install_task.ps1   # 注册开机自启计划任务（SYSTEM，崩溃自动重启）
│  ├─ uninstall_task.ps1
│  └─ start_console.bat  # 前台调试运行
├─ tests/smoke_test.py   # 离线自测（内置假 qB WebUI，无需真机）
├─ config.example.json
├─ requirements.txt
└─ README.md
```

---

## 五、部署（Windows）

### 1. 准备 qBittorrent

1. 打开 **工具 → 选项 → Web UI**，勾选"Web 用户界面"。
2. 端口记下来（默认 `8080`），设置用户名/密码。
3. **只监听 127.0.0.1**，不要暴露到公网。
4. 若开启了"对本地主机上的客户端跳过身份验证"，仍建议保留账号密码，脚本登录更稳。
5. 确认 `工具 → 选项 → 连接` 里 IPv4/IPv6 按你的网络情况开启（系统两者都支持）。

### 2. 安装 Python 依赖

```bat
cd C:\qbt-antileech
python -m pip install -r requirements.txt
```

Python 3.10+ 即可（已在 3.12 验证）；只需 `requests` 一个第三方包。

### 3. 生成配置

```bat
copy config.example.json config.json
notepad config.json
```

至少改这三项：

```json
"qbt": {
  "base_url": "http://127.0.0.1:8080",
  "username": "admin",
  "password": "你的密码"
}
```

> 不想把密码写进文件，可以用环境变量：`QBT_URL` / `QBT_USER` / `QBT_PASS`，
> 优先级高于配置文件。
>
> **qBittorrent 5.2+ 用户**：也可以在 WebUI「设置 → Web UI → API Key」生成密钥，
> 填入 `"api_key": "..."`。API Key 优先级高于用户名/密码，且不受登录接口变化影响。

### 4. 自检

```bat
python -m antileech -c config.json doctor
```

正常输出类似：

```
登录      : OK
版本      : 5.3.0
连接状态  : connected
封禁方式  : manual
手动屏蔽  : 3 条（IP过滤 → 手动屏蔽IP地址）
生效封禁  : 0
防火墙层  : 关闭
```

### 5. 先观察，不封禁

```bat
python -m antileech -c config.json run --dry-run
```

观察 30–60 分钟，看日志里 `[封禁]` 的 IP 是否符合预期（迅雷、明显只吸不回）。
确认无误后 Ctrl+C，去掉 `--dry-run` 正式运行。

### 6. 正式运行

前台：

```bat
deploy\start_console.bat
```

开机自启（推荐，管理员 PowerShell）：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\install_task.ps1 `
  -ProjectDir "C:\qbt-antileech" `
  -Config "C:\qbt-antileech\config.json"
```

脚本会注册计划任务 `QBT-AntiLeech`：开机启动、SYSTEM 权限、无执行时限、崩溃后 1 分钟重启。
卸载：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\uninstall_task.ps1
```

> 若坚持用"服务"而不是计划任务，可用 NSSM 包装 `python.exe -m antileech run -c config.json`，
> 工作目录设为项目根目录即可；本项目不依赖 NSSM。

### 7. （可选）防火墙硬封禁

```json
"firewall": { "enabled": true }
```

需要管理员权限运行。开启后每个被封 IP 会生成一对入/出站规则（`QBT-AntiLeech-<IP>`）。
**风险**：若对方是 NAT/机房共享出口，会连带阻断同 IP 的其他用户，所以默认关闭。

### 8. （可选）继续使用文件过滤器

默认 `blocklist.mode = "manual"`，完全不碰 `ipfilter.dat`，你原有的过滤规则文件可以继续
在 GUI 里保留使用，互不干扰。只有需要本系统额外维护一份文件名单时才改成：

```json
"blocklist": { "mode": "both" },
"ip_filter": { "base_file": "D:\\blocklist\\ipfilter.dat" }
```

`base_file` 用于把已有 blocklist 合并进本系统生成的文件（qB 只支持一个 `ip_filter_path`）。

---

## 六、日常运维

```bat
:: 运行状态（最近封禁、错误、Peer 数）
python -m antileech -c config.json status

:: 当前封禁列表
python -m antileech -c config.json bans --limit 100

:: 手工封禁 24 小时（--hours 0 为永久）
python -m antileech -c config.json ban 1.2.3.4 --reason "朋友反馈" --hours 24

:: 误封解除
python -m antileech -c config.json unban 1.2.3.4

:: 手工重写并强制 qB 重载过滤器（改完名单/排查不生效时用）
python -m antileech -c config.json sync-blocklist

:: 全部解除
python -m antileech -c config.json unban --all

:: 导出 CSV（Excel 可直接打开）
python -m antileech -c config.json export -o D:\bans.csv
```

日志：`data\antileech.log`（10MB × 5 轮转），同时输出到控制台。
数据库：`data\antileech.db`（可用任意 SQLite 工具查看 `bans` / `events`）。

### 关键配置项

| 配置 | 默认 | 说明 |
|---|---|---|
| `runtime.interval_seconds` | 15 | 扫描周期；Peer 多时建议 20–30，避免 API 压力 |
| `runtime.max_torrents_per_cycle` | 40 | 每轮最多检查的种子数（按上传速度排序） |
| `detection.min_connected_seconds` | 600 | 观察期，太短易误判新连接 |
| `detection.min_uploaded_bytes` | 256MB | 触发 R2 的最低上传量 |
| `detection.max_return_ratio` | 0.02 | 允许的最低回报率 |
| `detection.ban_threshold` | 60 | 封禁分数线 |
| `ban.duration_seconds` | 86400 | 普通封禁时长 |
| `ban.hard_duration_seconds` | 604800 | R1 硬封禁时长（7 天） |
| `blocklist.mode` | manual | `manual` 用 qB 手动屏蔽列表；`file` 用 ipfilter.dat；`both` 两者都写 |
| `blocklist.max_entries` | 5000 | 手动屏蔽列表最多下发多少条 |
| `blocklist.sync_interval_seconds` | 60 | 名单周期复核间隔（有变更时立即同步） |
| `ip_filter.enabled` | true | 仅 `file`/`both` 模式有效 |
| `ip_filter.reload_mode` | toggle | `toggle` 关闭再开启强制重载；`none` 只写路径、依赖文件监视器 |
| `detection.check_client_version` | true | 是否识别"版本超过已知上限"；关掉后 R6 其余项仍生效 |
| `detection.enable_fake_client_check` | true | 关闭整条 R6（客户端伪装检测） |
| `logging.level` | INFO | 排查时改 DEBUG |

### 调参建议

- **误封偏多**（例如把做种者封了）：把 `min_connected_seconds` 提到 1200，
  `min_uploaded_bytes` 提到 512MB，`zero_progress_max` 保持 0.01。
- **漏封明显吸血**：把 `ban_threshold` 降到 45，或把 `score_zero_progress` 提到 60。
- **小水管/低带宽**：把 `min_uploaded_bytes` 降到 64MB，避免长时间达不到阈值。
- **只封迅雷**：把 `ban_threshold` 设成 1000，仅保留 R1 硬指纹生效。

---

## 七、兼容性与已知限制

1. **API 版本**：基于 WebUI API v2（qB 4.1+）。5.3.0 的 `/sync/torrentPeers`、
   `/transfer/banPeers`、`/app/setPreferences` 均按官方行为调用；若某版本缺少
   `/sync/torrentPeers`，会自动回退到 `/torrents/peers`。
   登录同时兼容 4.x~5.1 的 `200 "Ok."` 与 5.2+ 的 `204 No Content`，并支持 5.2+ API Key。
2. **`peer_id` 字段**：部分 qB 版本不在 Peer 列表中返回 `peer_id`，此时 R6/R7 自动跳过，
   R1 仍可通过客户端名称命中，R2/R3/R5 完全不依赖 `peer_id`。
3. **IPv6**：手动屏蔽列表按纯 IP 字符串写入（`banned_IPs` 为换行分隔文本，不是数组），
   IPv4/IPv6 都支持；若你的 qB 版本拒绝 IPv6 条目，该 IP 仍由 `banPeers`（自动补发）与
   可选防火墙层保证。
4. **会话级解封**：见第三节的 ⚠️ 说明，qB 无公开 unban 接口。
5. **性能**：每轮请求数 ≈ 1（maindata）+ 活跃种子数（≤40）。全部走 127.0.0.1，开销可忽略。
6. **安全**：WebUI 只监听 127.0.0.1；配置文件含密码，建议 NTFS 权限限制为
   运行账户可读；也可改用环境变量。

---

## 八、自测

无需真实 qBittorrent：

```bat
python tests\smoke_test.py
python tests\test_login_compat.py
python tests\test_filter_reload.py
python tests\test_manual_ban.py
python tests\test_fake_client_toggle.py
python tests\test_mapped_ipv6.py
```

内置一个假 WebUI，模拟三类 Peer（迅雷 / IPv6 零进度吸血 / 正常互惠），验证：

- 迅雷命中 R1 立即封禁
- IPv6 吸血命中 R2 被封禁，且写入 qB 手动屏蔽列表
- 正常互惠用户不被封，用户原有手工条目不被覆盖
- `banPeers` 被正确调用、manual 模式不再写 ipfilter.dat
- 手工解封即时同步列表
- 封禁到期自动从列表移除
- qB 5.2+ 的 204 登录、旧版 200 登录、错误密码三种响应
- 过滤器写入后确实执行了"关闭→开启"强制重载（而不是只写文件）
- 过滤器重载的调用顺序、路径纠错、去重与 IPv6 合并

预期最后一行：`全部自测通过。`

---

## 九、风险提示

- 本系统基于行为启发式判断，**不存在 100% 无误封的规则**。首次部署请务必先跑
  `--dry-run` 观察，并从保守阈值开始。
- 不要同时运行多个实例（会重复写入 ipfilter 与数据库）。
- 封禁是"本机视角"，不改变 BT 网络整体生态；请同时保持做种比例，别把自己变成只下载的人。
