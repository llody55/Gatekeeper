# Contributing to Gatekeeper

感谢你对 Gatekeeper 的关注！本文档说明如何参与开发、构建与测试。

## 项目简介

Gatekeeper 是一个 Go 语言实现的在线账户救援管理平台，提供：

- 主机账户状态巡检（过期/锁定/即将过期）
- 在线救援动作下发（改密/解锁/禁用/启用 等）
- 通用 shell 命令下发（黑白名单策略）
- agent 健康告警 + 账户过期告警（webhook / 邮件）
- 操作审计日志与留存策略

## 开发环境

| 工具 | 版本要求 |
|------|---------|
| Go   | 1.24+   |
| Git  | 2.x     |

```bash
# 克隆仓库
git clone git@github.com:llody55/Gatekeeper.git
cd Gatekeeper

# 验证环境
go version
go env GOPATH
```

## 构建

```bash
# 构建 server + agent（版本号从 VERSION 文件读取）
make build

# 交叉编译到 linux/amd64 + linux/arm64
make cross

# 手动指定版本构建
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X gatekeeper/internal/version.VERSION=0.8.0" \
  -o bin/gatekeeper-server ./cmd/server
```

## 测试与质量检查

```bash
# 运行全部测试
make test
# 或
go test ./... -count=1

# 静态检查
make vet
# 或
go vet ./...

# 依赖校验
go mod verify
```

### 覆盖率

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## 目录结构

```
Gatekeeper/
├── cmd/
│   ├── server/          # server 入口 (main.go)
│   └── agent/           # agent 入口 (main.go)
├── internal/
│   ├── server/          # server 核心: store/web/alert/server/ui
│   ├── agent/           # agent 核心: actions/client
│   ├── config/          # 配置加载与默认值
│   ├── proto/           # agent 通信协议
│   └── version/         # 版本号集中管理
├── examples/            # 配置示例 (server.yaml / agent.yaml)
├── deploy/systemd/      # systemd unit 文件
├── .github/workflows/   # CI / Release 工作流
├── VERSION              # 版本号 (与 internal/version 默认值一致)
├── CHANGELOG.md         # 更新日志
└── Makefile
```

## 版本号管理

版本号集中在两处，必须保持一致：

1. `VERSION` 文件（仓库根目录）
2. `internal/version/version.go` 中的 `VERSION` 变量

发版流程：

```bash
# 1. 修改 VERSION 文件
echo "0.9.0" > VERSION

# 2. 同步修改 internal/version/version.go

# 3. 更新 CHANGELOG.md

# 4. 本地验证
make build && make vet && make test

# 5. 提交并打 tag
git add -A
git commit -m "release: v0.9.0"
git tag -a v0.9.0 -m "v0.9.0"
git push origin master --tags
```

推送 `v*` tag 会触发 `.github/workflows/release.yml`，自动交叉编译并发布 GitHub Release 工件。

## 配置分层原则

Gatekeeper 采用"配置文件 + DB settings 表"双层配置：

| 类型 | 存储 | 变更方式 | 示例 |
|------|------|---------|------|
| 基础设施 | `gatekeeper.yaml` | 改配置 + 重启 | SMTP host、DB 连接、调度间隔 |
| 运行时可变 | DB `settings` 表 | Web 端保存，热更 | 告警开关、收件人、预警阈值 |

新增配置项时，请判断其归属：需要重启才能生效的放配置文件，可热更的放 settings 表。

## 提交规范

Commit message 采用简洁的前缀格式：

```
<type>: <subject>

type 可选:
  feat:     新功能
  fix:      修复
  docs:     文档
  refactor: 重构
  perf:     性能
  test:     测试
  chore:    构建/工程化
```

示例：

```
feat(alert): 用户邮箱绑定自动成为告警收件人
fix(store): SettingSet 兼容 MySQL ON DUPLICATE KEY UPDATE
perf(store): Mutex 升级为 RWMutex, 纯读方法改用 RLock
```

## 安全注意事项

- **SQL 注入**: 所有 SQL 必须使用参数化查询（`?` 占位符 + `db.Exec/Query`），禁止字符串拼接。
- **输入校验**: 用户输入（username/agent_id/pattern 等）需通过正则白名单校验。
- **权限控制**: API 入口检查角色，admin/operator/auditor 权限分明。
- **凭证处理**: 密码用 bcrypt 哈希，token 不明文入库（存 hash+前缀）。
- **审计日志**: 所有写操作（创建/修改/删除/下发）必须写入 audit 表。

## 提交流程

1. Fork 仓库或创建 feature 分支
2. 完成开发，确保 `make vet && make test` 通过
3. 提交 PR，描述变更内容与测试方式
4. CI 通过后等待维护者 Review

## 问题反馈

- Bug / 功能建议: [GitHub Issues](https://github.com/llody55/Gatekeeper/issues)
