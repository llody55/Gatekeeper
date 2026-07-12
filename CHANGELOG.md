# Gatekeeper 更新日志

本文件记录每个发行版的关键变更。版本号与仓库根目录 `VERSION` 文件一致。
发版流程: 改 `VERSION` → `make build`（Makefile 通过 `-ldflags -X` 自动注入到二进制）→ 更新本文件。

## v0.6.0 (2026-07-12)

本版聚焦"通用 shell 下发 + agent 连接健壮性 + 多项 UI/功能修复", 是面向日常运维场景的关键更新。

### 新增

- **通用 shell 命令下发**：
  - 新增 `shell` 动作，通过 `bash -c` 执行自定义命令，弥补仅有 6 个原子救援动作的不足。
  - **黑白名单策略引擎**：glob 模式匹配，黑名单优先级高于白名单，规则存储在 `shell_rules` 表。
  - 启动时种子默认规则（白名单：`systemctl *`/`journalctl *`/`cat *`/`ls *`/`df *`/`free *`/`ping *`/`docker ps *`/`docker logs *`；黑名单：`rm -rf /*`/`mkfs *`/`dd if=*`/`shutdown *`/`reboot *`/`init 0`/`>: *`）。
  - **Shell 策略管理页**：UI 新增 Shell tab（仅 admin 可见），支持启用/禁用 shell、调整超时与输出截断、CRUD 黑白名单规则。
  - 6 个管理 API：`GET/POST /api/shell/policy`、`GET /api/shell/rules`、`POST /api/shell/rules`、`POST /api/shell/rules/update`、`POST /api/shell/rules/delete`。
  - 默认关闭（`shell.enabled: false`），需管理员显式启用，策略变更持久化到 DB 并即时生效。
  - Agent 本地执行日志 `agent-exec.log`，记录命令/超时/输出截断等。
- **指令历史按动作类型筛选**：UI 指令历史页新增类型下拉（全部/自定义命令/组合救援/查看过期/...），API `/api/commands` 支持 `?action=` 参数过滤。
- **救援页自定义命令输入**：动作下拉新增"自定义命令"选项，选中后显示命令输入框。

### 修复

- **SessionTTL 配置未生效**：`handleLogin` 硬编码 `12 * time.Hour`，改为读取 `s.sessionTTL`，YAML `session_ttl` 配置现在正确生效。
- **Shell 下发返回非 JSON 响应**：`http.Error()` 返回纯文本导致前端 `api().json()` 解析失败（`"shell acti"... is not valid JSON`），全部改为 JSON 错误响应。
- **批量下发缺少 shell 校验**：`handleDispatchBatch` 完全缺失 shell 启用/黑白名单检查，已补齐。
- **Shell 策略管理页无响应**：6 个 handler 函数（`handleShellPolicyGet/Set`、`handleShellRulesList`、`handleShellRuleAdd/Update/Delete`）从未实现，路由注册后函数不存在，导致所有 shell 管理操作无响应。已补全实现，含输入校验、审计日志、策略持久化与内存刷新。
- **默认黑白名单为空**：`SeedShellRules()` 用 `_, _ =` 静默吞掉 INSERT 错误，新建 DB 打开规则页为空白。改为 mutex + 事务 + 错误返回。
- **前端操作无提示**：shell 管理页所有 API 调用（保存策略/新增规则/删除规则/切换启用）缺少 `.catch()` 错误处理，失败时用户无感知。已添加 `toast()` 提示。
- **Agent 断线后卡死不重连**：agent 的 `readLoop` 无 `SetReadDeadline`，server 异常退出（kill -9/OOM/宕机/网络中断）不发 FIN 时 `ReadJSON` 永久阻塞，只能等 TCP 重传超时（~15min）或 keepalive（~2h）。已加入读超时（heartbeat × 3，默认 90s），每收到消息刷新 deadline。
- **JS `const` 重复赋值**：救援页 `const params=buildParams()` 后 `params={command:...}` 重赋值报错，改为 `let`。
- **CSS 宽度语法错误**：`width:100%%`（Go 字符串中 `%` 无需转义）改为 `width:100%`。
- **保存按钮颜色不匹配**：shell 策略保存按钮缺少 `primary` CSS 类。

### 优化

- **Agent 重连退避重置**：上次连接存活时间超过 `reconnect_max`（说明是稳定连接断开），下次退避重置为 `reconnect_min`，快速恢复而非从翻倍后的值开始。
- **Agent ping goroutine 泄漏修复**：`readLoop` 退出后 ticker 被 Stop 但 ping goroutine 永远阻塞在 stopped channel，每次重连泄漏一个 goroutine。改为 `context.WithCancel` 驱动退出。
- **Shell 策略变更即时生效**：`handleShellPolicySet` 不仅持久化到 DB，还调用 `SetShellConfig()` 刷新 server 内存状态，无需重启。
- **`badRequest` 辅助函数**：新增 JSON 格式的 400 错误响应，替代之前 `respond` 一律返回 500 "internal error"，前端能看到具体校验失败原因。
- **Shell 规则仅切换 enabled 保留原值**：UI 的 checkbox 切换发送 `pattern:''`，handler 在 pattern 为空时从 DB 查原值保留，不会误清空。

### 安全

- **Shell 默认关闭**：`shell.enabled` 默认 `false`，管理员需在 UI 或 YAML 显式开启。
- **黑白名单双重防护**：即使白名单放行，黑名单仍可阻止危险命令；黑名单优先。
- **Shell 策略变更审计**：所有策略/规则变更写入 `audit_log`（`shell_policy_set`/`shell_rule_add`/`shell_rule_update`/`shell_rule_delete`）。
- **Agent 存活检测**：读超时机制确保 agent 在网络静默中断后 90s 内触发重连，避免"假在线"死连。

### 配置

- 新增 `shell:` 段（`enabled` / `timeout` / `max_output`），支持 YAML + `GATEKEEPER_SERVER_SHELL_*` 环境变量覆盖。
- `examples/server.yaml` 同步更新 shell 配置段及注释。

---

## v0.5.0 (2026-07-07)

本版聚焦"等保可用性 + 多管理员 + 健康告警", 是面向生产部署的第一个推荐版本。

### 新增

- **多账号与 RBAC 三角色** (`admin` / `operator` / `auditor`)：
  - admin 全权；operator 仅能下发救援+看审计；auditor 只读审计。
  - 不能删除/禁用最后一个 admin、不能删除自己（护栏）。
  - 老库自动从 `settings.admin_password` 迁移到 `users` 表的 `admin` 用户。
  - UI 新增用户管理页（仅 admin 可见）+ 中文角色徽章。
  - `/api/me`、登录响应返回 `role`。
- **agent 健康告警**：
  - 超过 `alerts.offline_after` 未心跳 → POST `agent_offline` 到 `webhook_url`。
  - 恢复心跳 → POST `agent_recovered`。同一状态去重，不重复发送。
  - `POST /api/alerts/test`（仅 admin）手动触发一次，用于验证 webhook 配置。
  - 可选 `webhook_token` 写入 `X-Gatekeeper-Token` 头校验来源。
- **数据清理 worker**：每日按 `audit_retention_days` 清理旧 audit_log/commands。
  - 双层锁定：YAML `history_retention` 为下限（默认 180 天），DB settings 可调高但不得低于下限。
  - `GET/POST /api/settings/retention` 查看/调整。
- **agent / token 删除功能**：
  - `DELETE /api/agents?id=xxx` 硬删除（前置：online=0）。
  - `POST /api/tokens/delete` 硬删除（前置：revoked=1）。
- **列表分页**：`/api/agents`、`/api/commands`、`/api/tokens`、`/api/audit` 全部 `[page,page_size,q]` 化，统一响应 `{items,total,page,page_size,pages}`。默认每页 **10** 条。

### 优化

- **撤销 token 立即踢活会话**：revoke 通过 token 哈希反查 bound_agent_id 后 `KickSession`，agent 即时断连，不再能继续接命令。
- **`/api/agents` 叠加实时在线真值**：API 序列化前用 server 内存 live session map 校验 DB 的 `online` 列，修正 sweeper 15s 滞差，UI 立即反映真实状态。
- **审计/索引**：audit_log 新增 `idx_audit_actor_action_ts`、`idx_audit_target`，1000 规模下模糊查询走索引。
- **`/api/audit/actions` 用 DISTINCT** 取代内存去重；`/api/command/<id>` 改 `GetCmd` 直查。
- **server/agent 启动日志打印版本号**，`/api/me` 与 UI 头部展示版本。

### 安全

- **在线状态假 + 死信下发**：
  - `SweepStaleAgents` 每 15s 扫描 `last_seen` 超时仍 `online=1` 的 agent，置离线。
  - `/api/dispatch` 下发前校验 `IsOnline`，离线直接返回 **409** `agent offline`，命令不再入库成死信。
- **Token 与 agent_id 绑定**：
  - `tokens` 表新增 `bound_agent_id` 列。`bind_bootstrap_token: true`（默认）开启后 bootstrap token 首次注册即自动锁定到该 agent_id。
  - 即便 bootstrap token 泄露，攻击者无法在另一台机器冒名注册别的 agent_id。
  - WS 升级前做绑定校验，不符直接 **403** + `agent_register_denied` 审计。
  - 新增 `POST /api/tokens/bind`、`POST /api/tokens`（接 `bind_agent_id`）。
- **X-Forwarded-For 绕过防御**：
  - `clientIP` 改为解析 `RemoteAddr`，仅当直连 IP 命中 `trusted_proxies` CIDR 列表时才解析 XFF。**默认 `trusted_proxies: []`**。
  - 新增全局账号兜底：跨 IP 累计 `admin` 失败 30 次/5min → 10 分钟冷却。

### 配置

- `defaults.history_retention`: 30天 → **180天**（等保 6 个月下限）。
- 新增 `alerts:` 段（`enabled / offline_after / webhook_url / webhook_token / check_interval`），全部支持 YAML + `GATEKEEPER_SERVER_ALERTS_*` 环境变量覆盖。
- `examples/server.yaml` 同步更新所有新增字段及等保场景注释。

### 构建

- 新增 `internal/version` 包集中管理版本号。
- `Makefile` 读 `VERSION` 文件并通过 `-ldflags -X` 注入二进制；新增 `make version` 查看当前版本。
- `VERSION` 文件作为单一版本真相源，发版只需改一个文件。

---

(更早版本未单独维护; 0.5.0 起开始记录)