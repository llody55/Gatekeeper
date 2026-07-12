# Gatekeeper 架构设计

本文面向二次开发者与安全评审者，讲清协议、模块边界、并发模型、决策权衡。

## 1. 设计目标

1. **免接触在线救援**：被救主机不需要运维 SSH 进去，也不需要进单用户模式；agent 主动反连 server，server 推指令。
2. **穿透防火墙**：混合云/DMZ 主机的入站端口通常封死，但出站 443/8443 几乎都开。架构利用"agent 反向长连 + server 主动推"绕过入站限制。
3. **最小爆破半径**：默认只暴露账户救援相关的 6 个动作，避免变成万能后门；通用 shell 需管理员显式启用且受黑白名单管控。
4. **最小部署成本**：单二进制 + SQLite + YAML 配置；纯 Go SQLite 驱动，无 CGO，交叉编译友好。
5. **可审计**：所有写动作留痕，便于等保取证。

## 2. 模块

```
                  ┌────────── 运维浏览器 ──────────┐
                  │  REST(/api/*) + 实时(/ui/events) │
                  └──────────────┬───────────────────┘
                                 │ HTTPS/WS
       ┌─────────────────────────▼─────────────────────────────┐
       │                    Server (单进程)                     │
       │  ┌─────────────┐  ┌──────────┐  ┌──────────────────┐  │
       │  │ HTTP Mux    │→ │ API      │→ │ Store (SQLite WAL)│  │
       │  │ /agent /api │  │ handlers │  │ agents/tokens/   │  │
       │  │ /ui/events  │  │          │  │ commands/audit/  │  │
       │  │ /           │  │          │  │ settings         │  │
       │  └──────┬──────┘  └────┬─────┘  └──────────────────┘  │
       │         │              │                              │
       │    ┌────▼────┐   ┌──────▼──────┐  ┌─────────────────┐  │
       │    │ AgentWS │   │ SessionPool │  │ TimeoutSweeper  │  │
       │    │ upgrader│   │ agentID→Sess │  │ 15s 周期        │  │
       │    └────┬────┘   └─────────────┘  └─────────────────┘  │
       └─────────┼─────────────────────────────────────────────┘
                  │ ws/wss (agent 反向出站)
       ┌──────────▼─────────┐
       │      Agent        │
       │  connectAndServe  │
       │  ┌──────────┐     │   ┌──────────┐
       │  │readLoop  │← cmd │   │Execute() │ chage/passwd/usermod
       │  │→handleCmd│      │   │ per action│ faillock/pam_tally2
       │  └────┬─────┘     │   └──────────┘
       │       │ result     │
       │       ▼            │
       │  writeJSON          │
       └────────────────────┘
```

## 3. 通信协议

所有 WebSocket 帧（无论方向）都是同一 JSON 信封 `proto.Envelope`（见 [internal/proto/protocol.go](../internal/proto/protocol.go)）：

| Kind | 方向 | 用途 |
|---|---|---|
| `register` | agent → server | 注册，带 token/agent_id/hostname/os |
| `ok` / `error` | server → agent | 注册回执 |
| `ping` / `pong` | 互发 | 心跳，agent 每 `heartbeat` 发 ping |
| `cmd` | server → agent | 下发救援指令 `proto.Cmd{ID,Action,User,Params}` |
| `result` | agent → server | 执行回执 `proto.Result{CmdID,OK,Output,Err}` |

**shell 动作**：`Action=shell` 时 `Params` 包含 `command`（命令文本）、`timeout`（超时秒数）、`max_output`（输出截断字节数）。agent 通过 `bash -c` 执行，输出超截断后返回。server 端在 `handleDispatch` / `handleDispatchBatch` 中校验：shell 是否启用 → 黑名单拦截 → 白名单放行（黑名单优先）。

**鉴权流程**（`/agent` 端点）：
1. 升级 WebSocket 前先读 HTTP 头 `X-Agent-Token` / `X-Agent-Id`。
2. 读不到或不匹配 → 401。
3. server 校验 token 在 `tokens` 表且未 revoke。
4. 升级后第一帧必须 `register`，server 写 `agents` 行 + 审计。

**会话池**：`map[agent_id]*Session`，`Session.send` 是 64 容量缓冲 channel。同 agent_id 重连时旧 Session 被 close 并断开，保证唯一。

## 4. 救援动作实现

`internal/agent/actions.go::Execute` 按 `Action` 派发到对应命令链，全部以 root 静默执行：

| 动作 | 命令 | 备注 |
|---|---|---|
| `chage_status` | `chage -l <user>` | 只读，先排查过没过期 |
| `expire_extend` | `chage -E -1 -M -1 -I -1 -W 0 <user>` | 永不过期 + 不锁定不活动 + 0 警告 |
| `unlock` | `usermod -U` + `passwd -u` | 账户锁 + 密码锁都解 |
| `clear_fail` | `faillock --reset` → 失败回退 `pam_tally2 --reset` | RHEL8+/CentOS Stream 用 faillock；老系统用 pam_tally2 |
| `reset_password` | `chpasswd` 非交互 stdin，可选 `chage -d 0` | 避免 TTY 交互 |
| `combo` | 上述按 checkbox 顺序组合 | UI 默认勾三个清场项 + 改密 |
| `shell` | `bash -c <command>` | 自定义命令，受黑白名单管控，默认关闭 |

执行用 `exec.Command` + `Stdin = 空字符串` 避免 TTY 等待；`Setpgid` 避免被父进程信号串扰。

## 5. 数据模型

| 表 | 关键列 | 用途 |
|---|---|---|
| `agents` | agent_id(PK), token, hostname, ip, tags, notes, online, last_seen | 在册主机 |
| `tokens` | token(PK), note, revoked | agent 接入凭证 |
| `commands` | id(PK), agent_id, action, user, params, status, output, err, created_by, created_at, finished_at | 指令与回执 |
| `audit_log` | id, ts, actor, action, target, detail, ip | 操作审计 |
| `settings` | k, v | admin_password、会话 token、shell 策略等 |
| `shell_rules` | id, type, pattern, note, enabled, created_at, updated_at | shell 黑白名单规则（type=whitelist/blacklist） |

`modernc.org/sqlite` 是纯 Go 实现，避免 CGO；`SetMaxOpenConns(1)` + 短互斥锁规避 SQLite 写并发冲突。

## 6. 并发与一致性

- Store 用一把 `sync.Mutex` 串行所有写；YAGNI，规模足够大前不必优化。
- SessionPool 用 `sync.RWMutex`：读多(下发时找 Session)用 RLock，写(增删)用 Lock。
- 超时扫描器 15s 周期：`SweepTimeouts` 一次扫描 + 批量 UPDATE，避免条目级并发。
- UIHub 用 `sync.RWMutex` 维护订阅 channel 集合，`Broadcast` 非阻塞投递(满缓冲即丢，保护 server)。

## 7. UI 实时推送

浏览器登录后维持一条 `/ui/events?t=<session>` 的 WebSocket。Session `readPump` 收到 agent 回执、上/下线时调用 `uiHub.Broadcast`，所有 UI 连接收到 JSON 事件并自行决定刷新哪些列表。丢包/慢连不影响 server。

## 8. 配置加载

见 [CONFIG.md](CONFIG.md)。三级覆盖：flag > 环境变量(`GATEKEEPER_SERVER_*` / `GATEKEEPER_AGENT_*`) > YAML > 默认值。YAML 路径按 `./`, `~/.gatekeeper/`, `/etc/gatekeeper/` 顺序查找。

## 9. 安全边界与权衡

- **通用 shell 默认关闭**：`shell.enabled` 默认 `false`，管理员需在 UI 或 YAML 显式启用。即便启用，所有命令受黑白名单策略管控：
  - **黑名单优先**：即使白名单匹配，黑名单命中则拒绝。
  - **glob 模式匹配**：`systemctl *` 匹配 `systemctl restart nginx`，`rm -rf /*` 拦截危险删除。
  - **策略变更审计**：启用/禁用 shell、增删改规则全部写入 `audit_log`。
  - **策略即时生效**：API 修改策略后同时持久化 DB + 刷新内存，无需重启。
- **不是 Ansible**：shell 是受限的运维工具，不是通用配置管理；批量执行仍建议走专业工具。
- **Token 物理等同 agent 上线权**：泄露即等于该机器远程改密权，必须按机器发放、离职立即撤销。
- admin 口令目前是单管理员；多用户/RBAC/SSO 见路线图，必要时落地 `users` 表与 `sessions` 表分离。
- 改密的明文会经过 server 临时内存 + 日志审计 detail 字段。本版为便于排查，combo/reset 的密码不出现在 audit detail；但 commands.params 列是 JSON 明文存库。若合规要求不可留存密码，下一步会加 `Defaults.KeepPasswordInHistory` 开关，默认关闭即可。

## 10. 演进钩子

- `Store` 接口已在内部抽稳定，未来外接 MySQL/PG 时只需替换底层实现。
- `Execute` 的 action 是常量集，新增动作只需在 proto + actions.go + validAction + UI 选项里四处同步。
- `ShellAllowed` 的黑白名单引擎独立于 action 派发，未来可扩展为正则匹配或审批流。
- agent 的 `connectAndServe` + 指数退避重连 + 读超时存活检测是通用的 WebSocket 会话管理模式，未来支持多 server 时可复用。
- `Web 控制台` 是内嵌单页；若需要复杂，可外挂 React/Vue 单独构建到 `web/dist/` 再 `embed`。