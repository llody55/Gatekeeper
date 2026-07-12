# Gatekeeper

> 在线 Linux 账户救援控制台 —— 当 SSH 因密码过期/账户锁定被挡在门外时，无需重启进单用户模式即可远程救活账户。

`Your account has expired; please contact your system administrator.`
经历过这句话、经历过半夜为了改一个 root 密码跑机房进单用户救援的人，会明白这个工具存在的意义。

Gatekeeper 让你在拿到服务器装机时就装一个常驻 **agent**；agent 主动反向连回 **server**，运维通过 Web 控制台下指令，把过期/锁死的账户在线救回。落地场景典型是等保要求每账户设过期天数，到期突然登不上的混合云主机群——不依赖云平台，也能像云平台一样"在线重置密码"。

---

## 为什么需要它

| 传统做法 | Gatekeeper |
|---|---|
| 密码过期/账户锁死 → 进机房接 KVM / 走单用户 grub 救援 | 浏览器点几下，账户在线救活 |
| 改密需逐台 SSH（一台登不上就卡死） | agent 反向长连，server 主动下发，不依赖能 SSH 进去 |
| 混合云/DMZ/防火墙后的机器难触达 | agent 出站 443/8443，几乎在任何网络都能连出 |
| 改谁了什么、什么时候改的无记录 | 全量审计日志 + 指令历史 + 创建者留痕 |

## 特性

- **单二进制 + SQLite**：server / agent 各一静态二进制，零外部依赖，`modernc.org/sqlite` 纯 Go 驱动，交叉编译友好。
- **反向长连突破防火墙**：agent 主动 WebSocket 连接 server，不要求 server 到 agent 的入站可达；只复用几乎都开放的出站 443/8443。
- **预共享 Token 鉴权**：每个 agent 一个 token，server 在数据库登记；登录 Web 控制台用独立 admin 口令，会话 12h。
- **5 个原子救援动作 + 一键组合救援 + 通用 shell**：`chage_status` / `expire_extend` / `unlock` / `clear_fail` / `reset_password` / `combo` / `shell`（自定义命令，受黑白名单管控）。
- **批量与分组**：主机标签、备注、按标签过滤、批量下发、批量打标签。
- **实时推送**：浏览器 WebSocket 订阅上/下线、回执事件，回执到表里就刷新。
- **完整审计**：注册/登录/下发/批量下发/token 创建/撤销/标签变更/agent 删除全部入审计表，留 actor、目标、来源 IP。
- **指令超时回收**：超时未回执的指令后台扫描器自动标记 `timeout`，避免 UI 假挂起。
- **配置外提**：YAML 配置文件 + 环境变量 + 命令行 flag 三级覆盖，无任何硬编码地址/口令/超时。
- **通用 shell 下发**：自定义命令通过 `bash -c` 远程执行，glob 黑白名单策略管控（黑名单优先），默认关闭需管理员显式启用。
- **Agent 断线秒级重连**：指数退避重连 + 读超时存活检测（heartbeat × 3），网络静默中断后 90s 内自动恢复，不会卡死。
- **TLS 可选**：内网 `/tls` 关闭明文 ws/http；公网/混合云用 `-tls-cert/-tls-key` 升级到 wss/https。

## 架构一图流

```
┌────────────────────────────────────────────────────────────────┐
│              运维浏览器 (Web 控制台)                            │
│   登录 → 拿 session token → REST + /ui/events 实时推送          │
└────────────────────────────────────────────────────────────────┘
                          │ HTTPS / WSS
                          ▼
┌────────────────────────────────────────────────────────────────┐
│  Gatekeeper Server  (单二进制 + SQLite)                         │
│  ├─ /api/login, /api/agents, /api/dispatch[_batch]              │
│  ├─ /api/shell/policy, /api/shell/rules (shell 策略管理)         │
│  ├─ /agent   WebSocket 接入 (鉴权 X-Agent-Token)                │
│  ├─ /ui/events  浏览器订阅事件流                                │
│  ├─ 会话池 agent_id -> Session                                  │
│  ├─ Store: agents / tokens / commands / audit_log / settings / shell_rules │
│  └─ 超时扫描器 (15s 周期)                                       │
└────────────────────────────────────────────────────────────────┘
            ▲ agent 主动反向出站                   ▲ agent
            │ ws/wss://server:8443/agent           │
   ┌────────┴───────┐  ┌────────────────┐  ┌──────┴─────────┐
   │ host-A (prod)  │  │ host-B (dmz)   │  │ host-C (cloud)│
   │ gatekeeper-agent│ │ gatekeeper-agent│ │ gatekeeper-agent│
   │  root 常驻      │  │  root 常驻      │  │  root 常驻     │
   └────────────────┘  └────────────────┘  └────────────────┘
     agent 在每台主机执行 chage / passwd / usermod / faillock / pam_tally2
     或 bash -c 执行自定义命令 (受黑白名单管控)
```

## 快速开始

```bash
# 1. 构建(需 Go 1.24+)
make build
# 产物: bin/gatekeeper-server, bin/gatekeeper-agent

# 2. 启动 server (默认 :8443, 自动生成 admin 口令并打印)
cp examples/server.yaml gatekeeper.yaml   # 按需调整
sudo mkdir -p /var/lib/gatekeeper
./bin/gatekeeper-server -config ./gatekeeper.yaml
# 日志里会看到: [security] 首次启动，已自动生成管理员口令(请妥善保存)
# 浏览器打开 http://<server-ip>:8443/, 输入上面那个口令登录

# 3. 在 Web 控制台 Token 页生成一个 agent token (或用启动时登记的 bootstrap token)

# 4. 在被保护主机装 agent (root 身份)
cp examples/agent.yaml /etc/gatekeeper/agent.yaml
# 编辑 /etc/gatekeeper/agent.yaml: 填 server_url + token
./bin/gatekeeper-agent -config /etc/gatekeeper/agent.yaml

# 5. 回到控制台 -> 主机页应看到新进程在线 -> 救援页下发动作
```

更多部署方式(systemd unit、TLS、Provenance)见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 与 [docs/CONFIG.md](docs/CONFIG.md)。

## 项目结构

```
.
├── cmd/
│   ├── server/main.go        # server 入口
│   └── agent/main.go         # agent 入口
├── internal/
│   ├── proto/protocol.go     # WebSocket JSON 消息协议 (共享)
│   ├── config/               # YAML + env + flag 三级配置加载
│   ├── agent/{agent,actions}.go  # 反连会话 + 5 个救援动作实现
│   └── server/               # store + WebSocket 接入 + REST API + UI Hub + 内嵌 Web
├── examples/                 # server.yaml / agent.yaml 配置范例
├── docs/                     # 架构与配置文档
└── bin/                      # 构建产物(gitignore)
```

## 安全说明

- **Agent 即 root 后门**：本工具本质是"被授权的远程特权执行"，务必只在你能信任治理边界的主机群内使用。
- **最小动作面 + 可控 shell**：默认只暴露账户救援 6 类动作；通用 shell 默认关闭，需管理员显式启用，且受黑白名单策略管控（黑名单优先）。
- **Token 管理**：用 Web 控制台按机器/批次发 token，离职/下线立刻撤销；撤销后关联 agent 下次重连即被拒。
- **传输**：混合云/跨网络部署强烈建议开 TLS (wss/https)，并配置独立 admin 口令。
- **审计**：所有写动作(dispatch/token/agent/标签/shell 策略变更)落 `audit_log` 表，含操作者和来源 IP，便于等保取证。
- **数据库**：SQLite + WAL，定期 `VACUUM` 或拷贝主文件备份即可；如需多 server 共享，下一步会支持外接 MySQL/PostgreSQL。

## 配置速查

详见 [docs/CONFIG.md](docs/CONFIG.md)。要点：

| 类别 | server 关键字段 | agent 关键字段 |
|---|---|---|
| 监听/连接 | `listen`, `tls` | `server_url`, `insecure_tls` |
| 存储/ID | `db_path` | `agent_id` |
| 鉴权 | `ui.admin_password`, `agent.bootstrap_token` | `token` |
| 时序 | `defaults.cmd_timeout`, `agent.heartbeat_timeout` | `heartbeat`, `reconnect_min/max` |
| 优先级 | flag > env `GATEKEEPER_SERVER_*` > YAML > 默认 | flag > env `GATEKEEPER_AGENT_*` > YAML > 默认 |

## 路线图

已实现：登录会话、agent 注册、5 动作救援 + 通用 shell、批量/标签、审计、实时推送、超时回收、TLS、配置外提、黑白名单策略、断线秒级重连。
近期：
- [ ] 基于标签/批次的定时巡检(提前发现将过期账户并告警)
- [ ] 指令审批工作流(双人复核改密)
- [ ] 外接 MySQL/PostgreSQL 后端(替代 SQLite)
- [ ] 指令输出可下载、命令重放
- [ ] 监控指标 Prometheus exporter
长期：对接 LDAP/OIDC 单点登录，运维动作与工单系统联动。

## 许可证

[MIT](LICENSE)。欢迎提 issue / PR。