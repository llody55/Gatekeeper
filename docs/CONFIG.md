# Gatekeeper 配置参考

Gatekeeper 不在源码里硬编码任何地址、口令或超时。所有运行参数走三级覆盖：

**flag > 环境变量 > 配置文件 > 内置默认值**

## 配置文件查找顺序

启动时若未用 `-config` 显式指定，按以下顺序找第一个存在的可读文件：

1. `./gatekeeper.yaml`
2. `./gatekeeper.yml`
3. `./config/gatekeeper.yaml` (agent 也会再找 `./gatekeeper-agent.yaml`)
4. `~/.gatekeeper/gatekeeper.yaml`
5. `/etc/gatekeeper/gatekeeper.yaml`

环境变量前缀：server 为 `GATEKEEPER_SERVER_`，agent 为 `GATEKEEPER_AGENT_`，键名由 YAML tag 推导（忽略大小写、下划线连接嵌套）。

---

## Server 配置

完整示例见 [`examples/server.yaml`](../examples/server.yaml)。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `listen` | string | `:8443` | 监听地址，`:443` 需 root/能力 |
| `db_path` | string | `gatekeeper.db` | SQLite 文件，自动开 WAL |
| `log_level` | string | `info` | debug/info/warn/error |
| `tls.cert` | string | `""` | TLS 证书；与 key 同时非空才启用 |
| `tls.key` | string | `""` | TLS 私钥 |
| `ui.admin_password` | string | `""` | 管理员口令；留空则首启自动生成并写入 settings |
| `ui.session_ttl` | duration | `12h` | 会话 token 有效期 |
| `ui.allow_query_token` | bool | `false` | 是否允许 `?t=<password>` 直接访问，生产置 false |
| `agent.bootstrap_token` | string | `""` | 启动自动登记的 agent token |
| `agent.heartbeat_timeout` | duration | `90s` | 超过判定离线 |
| `agent.write_timeout` | duration | `10s` | 写超时 |
| `defaults.cmd_timeout` | duration | `60s` | 单条指令回执超时；扫描器据此标记 timeout |
| `defaults.history_retention` | duration | `720h` | 指令历史保留（留空=永久，自动清理待落地） |
| `shell.enabled` | bool | `false` | 是否启用通用 shell 下发；需显式开启 |
| `shell.timeout` | duration | `60s` | shell 命令执行超时 |
| `shell.max_output` | int | `65536` | shell 输出截断字节数 (1024~1048576) |

### 环境变量示例

```bash
# 覆盖 listen
GATEKEEPER_SERVER_LISTEN=:9443 ./gatekeeper-server

# 显式设管理员口令
GATEKEEPER_SERVER_UI_ADMIN_PASSWORD='my strong pass' ./gatekeeper-server

# 用命令登记一个 agent token
GATEKEEPER_SERVER_AGENT_BOOTSTRAP_TOKEN=abc123xyz ./gatekeeper-server
```

### Flags

```
-config FILE   指定配置文件路径
-addr ADDR     覆盖 listen（最高优先级）
```

---

## Agent 配置

完整示例见 [`examples/agent.yaml`](../examples/agent.yaml)。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `server_url` | string | `ws://127.0.0.1:8443/agent` | server WebSocket 地址，可 `ws://` 或 `wss://` |
| `token` | string | `""` | 预共享 token；也可用 env `GATEKEEPER_AGENT_TOKEN` 注入 |
| `agent_id` | string | `""` | 留空则 `hostname+随机` 生成 |
| `heartbeat` | duration | `30s` | 心跳间隔 |
| `reconnect_min` | duration | `2s` | 重连退避起始 |
| `reconnect_max` | duration | `60s` | 重连退避上限（指数翻倍） |
| `insecure_tls` | bool | `false` | wss 时是否跳过证书校验 |
| `log_level` | string | `info` | 日志级别 |

### 环境变量示例

最稳的 token 注入方式，避免写文件：

```bash
# systemd 单元里
[Service]
Environment="GATEKEEPER_AGENT_TOKEN=SUPER_SECRET_TOKEN"
EnvironmentFile=-/etc/gatekeeper/agent.env
ExecStart=/usr/local/bin/gatekeeper-agent -config /etc/gatekeeper/agent.yaml
```

### Flags

```
-config FILE   指定配置文件路径
-server URL    覆盖 server_url
-token TOKEN   覆盖 token（也可用 GATEKEEPER_AGENT_TOKEN）
-id ID         覆盖 agent_id
```

---

## systemd 部署范例

### server

`/etc/systemd/system/gatekeeper-server.service`:

```ini
[Unit]
Description=Gatekeeper Server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/gatekeeper-server -config /etc/gatekeeper/server.yaml
Restart=on-failure
RestartSec=3
StateDirectory=gatekeeper
WorkingDirectory=/var/lib/gatekeeper
User=root

[Install]
WantedBy=multi-user.target
```

`/etc/gatekeeper/server.yaml`:

```yaml
listen: ":8443"
db_path: "/var/lib/gatekeeper/gatekeeper.db"
tls:
  cert: "/etc/gatekeeper/server.crt"
  key:  "/etc/gatekeeper/server.key"
ui:
  admin_password: "REPLACE-ME"
```

### agent

`/etc/systemd/system/gatekeeper-agent.service`:

```ini
[Unit]
Description=Gatekeeper Agent
After=network-online.target

[Service]
EnvironmentFile=-/etc/gatekeeper/agent.env
ExecStart=/usr/local/bin/gatekeeper-agent -config /etc/gatekeeper/agent.yaml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

`/etc/gatekeeper/agent.env` (chmod 600):

```
GATEKEEPER_AGENT_TOKEN=YOUR_TOKEN_HERE
```

`/etc/gatekeeper/agent.yaml`:

```yaml
server_url: "wss://gatekeeper.internal:8443/agent"
heartbeat: "30s"
```

---

## 自签 TLS 一行命令（内网可用）

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /etc/gatekeeper/server.key -out /etc/gatekeeper/server.crt \
  -subj "/CN=gatekeeper.internal" -addext "subjectAltName=DNS:gatekeeper.internal"
```

agent 端若用自签且不放进信任库，需 `insecure_tls: true`；公网强烈推荐用正式证书/Let's Encrypt。

---

## 忘记管理员口令怎么办

admin 口令存在 `settings` 表 `admin_password` 行。两个补救办法：

1. 备份数据库后用 sqlite3 清空该行，重启时随机再生成：

   ```sh
   sqlite3 /var/lib/gatekeeper/gatekeeper.db "DELETE FROM settings WHERE k='admin_password'"
   systemctl restart gatekeeper-server
   # 看日志拿到新口令
   ```

2. 在配置文件里显式写 `ui.admin_password`，启动时会覆盖回数据库。