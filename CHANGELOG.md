# Gatekeeper 更新日志

本文件记录每个发行版的关键变更。版本号与仓库根目录 `VERSION` 文件一致。
发版流程: 改 `VERSION` → `make build`（Makefile 通过 `-ldflags -X` 自动注入到二进制）→ 更新本文件。

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