// Package config 负责 Gatekeeper server / agent 的配置加载、默认值与环境变量覆盖。
//
// 配置优先级：命令行 flag > 环境变量 > 配置文件 > 默认值。
// 配置文件采用 YAML 格式，路径通过 -c/--config 指定；未指定时按顺序查找：
//
//	./gatekeeper.yaml, ~/.gatekeeper/gatekeeper.yaml, /etc/gatekeeper/gatekeeper.yaml
package config

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Path 候选配置文件路径，按顺序查找。
var SearchPaths = []string{
	"./gatekeeper.yaml",
	"./gatekeeper.yml",
	"./config/gatekeeper.yaml",
	filepath.Join(homeDir(), ".gatekeeper", "gatekeeper.yaml"),
	"/etc/gatekeeper/gatekeeper.yaml",
}

// ServerConfig 是 server 端配置。
type ServerConfig struct {
	Listen         string        `yaml:"listen"`    // 监听地址，默认 :8443
	DBPath         string        `yaml:"db_path"`   // SQLite 路径，默认 gatekeeper.db（db.type=sqlite 时生效）
	DB             DatabaseConfig `yaml:"db"`       // 数据库配置(支持 sqlite/mysql/postgres)
	LogLevel       string        `yaml:"log_level"` // debug/info/warn/error
	TLS            TLSConfig     `yaml:"tls"`
	UI             UIConfig      `yaml:"ui"`
	Agent          AgentPolicy   `yaml:"agent"`
	Defaults       DefaultPolicy `yaml:"defaults"`
	TrustedProxies []string      `yaml:"trusted_proxies"` // 信任的前置代理 CIDR 列表；仅当直连对端 IP 命中此列表时方解析 X-Forwarded-For。默认空=不信任任何 XFF，公网部署必须留空
	Alerts         AlertConfig   `yaml:"alerts"`          // agent 健康告警配置
	Shell          ShellConfig   `yaml:"shell"`           // 通用 shell 下发配置
	Metrics        MetricsConfig `yaml:"metrics"`         // 观测性指标端点配置
}

// DatabaseConfig 数据库连接配置。
// type 可选: sqlite(默认, 纯 Go 驱动, 零依赖) / mysql / postgres。
// sqlite 时 dsn 可为空, 使用 db_path; mysql/postgres 时必须填 dsn。
type DatabaseConfig struct {
	Type string `yaml:"type"` // sqlite / mysql / postgres, 默认 sqlite
	DSN  string `yaml:"dsn"`  // 连接串, 如 "user:pass@tcp(127.0.0.1:3306)/gk" 或 "postgres://user:pass@localhost/gk?sslmode=disable"
}

// MetricsConfig 控制 /metrics 与 /healthz 端点的暴露。
// /healthz 始终暴露(供负载均衡探活); /metrics 由 enabled 控制, 默认启用。
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"` // 是否暴露 /metrics (Prometheus text format), 默认 true
}

// ShellConfig 通用 shell 命令下发策略。
// 黑白名单存储在数据库 shell_rules 表中, 此处仅为初次启动种子与策略开关。
// enabled 默认 false, 用户需显式开启才允许 shell action。
type ShellConfig struct {
	Enabled   bool          `yaml:"enabled"`    // 是否启用 shell action
	Timeout   time.Duration `yaml:"timeout"`    // 执行超时, 默认 60s
	MaxOutput int           `yaml:"max_output"` // 输出截断字节数, 默认 65536
}

// AlertConfig agent 健康告警 + 账户巡检过期告警配置。
// 通知通道: webhook(HTTP POST JSON) 与 邮件(SMTP), 可同时启用。
// agent 离线: 超过 OfflineAfter 未心跳 -> 发告警; 恢复后发恢复事件。
// 账户过期: 巡检发现 status=expired/password_expired, 或距过期 <= WarnDays -> 发告警。
type AlertConfig struct {
	Enabled        bool          `yaml:"enabled"`         // 是否启用告警
	OfflineAfter   time.Duration `yaml:"offline_after"`   // agent 多久未心跳触发告警, 默认 10 分钟
	CheckInterval  time.Duration `yaml:"check_interval"`  // 检查周期, 默认 60s
	WebhookURL     string        `yaml:"webhook_url"`     // webhook 目标 URL, POST JSON
	WebhookToken   string        `yaml:"webhook_token"`   // 可选, 写入 X-Gatekeeper-Token 头
	Email          EmailConfig   `yaml:"email"`           // SMTP 邮件通知(可选)
	AccountExpired AccountAlert  `yaml:"account_expired"` // 账户过期告警(可选)
}

// EmailConfig SMTP 邮件通知配置。
type EmailConfig struct {
	Enabled   bool   `yaml:"enabled"`    // 是否启用邮件
	Host      string `yaml:"host"`       // SMTP 服务器地址, 如 smtp.example.com:587
	Username  string `yaml:"username"`   // SMTP 用户名
	Password  string `yaml:"password"`   // SMTP 密码/授权码
	From      string `yaml:"from"`       // 发件人地址
	To        string `yaml:"to"`         // 收件人地址(多个用逗号分隔)
	UseTLS    bool   `yaml:"use_tls"`    // 是否使用 TLS(端口 465)
	UseStartTLS bool `yaml:"use_starttls"` // 是否使用 STARTTLS(端口 587, 默认 true)
}

// AccountAlert 账户巡检过期告警配置。
type AccountAlert struct {
	Enabled  bool `yaml:"enabled"`   // 是否启用账户过期告警
	WarnDays int  `yaml:"warn_days"` // 距过期多少天内开始预警, 默认 7
}

// TLSConfig TLS 配置。
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// UIConfig 管理界面配置。
type UIConfig struct {
	// 管理员登录口令；留空则在首次启动时自动生成并写入数据库，随后通过 /api/login 登录
	AdminPassword string `yaml:"admin_password"`
	// 会话 token 有效期；默认 12h
	SessionTTL time.Duration `yaml:"session_ttl"`
	// 是否允许通过 query ?t= 直接访问（生产建议关闭）
	AllowQueryToken bool `yaml:"allow_query_token"`
}

// AgentPolicy 控制与 agent 的连接行为。
type AgentPolicy struct {
	// 注册时 token 必须先在 server 登记；若该字段非空，则首次启动自动登记此 token
	BootstrapToken string `yaml:"bootstrap_token"`
	// 心跳超时：超过该时长无心跳则判定离线
	HeartbeatTimeout time.Duration `yaml:"heartbeat_timeout"`
	// 写超时
	WriteTimeout time.Duration `yaml:"write_timeout"`
	// 是否在 bootstrap token 首次被某 agent 注册成功后, 自动把它绑定到该 agent_id。
	// 开启后可避免拿到 bootstrap token 的攻击者冒名顶替别的 agent。默认 true（等保环境推荐保持）。
	BindBootstrapToken bool `yaml:"bind_bootstrap_token"`
}

// DefaultPolicy 默认下发策略。
type DefaultPolicy struct {
	// 单条指令未回执的超时时间，超时则自动标记 timeout
	CmdTimeout time.Duration `yaml:"cmd_timeout"`
	// 历史指令保留时长，超过则清理
	HistoryRetention time.Duration `yaml:"history_retention"`
}

// AgentConfig 是 agent 端配置。
type AgentConfig struct {
	ServerURL            string        `yaml:"server_url"`    // ws:// 或 wss://
	Token                string        `yaml:"token"`         // 预共享 token
	AgentID              string        `yaml:"agent_id"`      // 显式指定；留空走持久化文件
	AgentIDFile          string        `yaml:"agent_id_file"` // 持久化文件；留空则 ~/.gatekeeper/agent_id
	Heartbeat            time.Duration `yaml:"heartbeat"`
	ReconnectMin         time.Duration `yaml:"reconnect_min"`
	ReconnectMax         time.Duration `yaml:"reconnect_max"`
	LogLevel             string        `yaml:"log_level"`
	InsecureTLS          bool          `yaml:"insecure_tls"`           // wss 时是否跳过证书校验
	TrustedCAFingerprint string        `yaml:"trusted_ca_fingerprint"` // sha256(DER) hex; 留空走系统信任
}

// DefaultServer 返回带合理默认值的 server 配置骨架。
func DefaultServer() ServerConfig {
	return ServerConfig{
		Listen:   ":8443",
		DBPath:   "gatekeeper.db",
		LogLevel: "info",
		UI: UIConfig{
			SessionTTL: 12 * time.Hour,
		},
		Agent: AgentPolicy{
			HeartbeatTimeout:   90 * time.Second,
			WriteTimeout:       10 * time.Second,
			BindBootstrapToken: true,
		},
		Defaults: DefaultPolicy{
			CmdTimeout:       60 * time.Second,
			HistoryRetention: 180 * 24 * time.Hour, // 等保常见要求日志留存 >=6 个月, 此为下限, DB 设置不得低于此值
		},
		Alerts: AlertConfig{
			OfflineAfter:  10 * time.Minute,
			CheckInterval: 60 * time.Second,
			AccountExpired: AccountAlert{
				WarnDays: 7,
			},
			Email: EmailConfig{
				UseStartTLS: true,
			},
		},
		Shell: ShellConfig{
			Enabled:   false,
			Timeout:   60 * time.Second,
			MaxOutput: 65536,
		},
		Metrics: MetricsConfig{
			Enabled: true,
		},
	}
}

// DefaultAgent 返回带合理默认值的 agent 配置骨架。
func DefaultAgent() AgentConfig {
	return AgentConfig{
		ServerURL:    "ws://127.0.0.1:8443/agent",
		Heartbeat:    30 * time.Second,
		ReconnectMin: 2 * time.Second,
		ReconnectMax: 60 * time.Second,
		LogLevel:     "info",
	}
}

// LoadServer 从 path 加载 server 配置；path 为空则按 SearchPaths 顺序查找。
// envPrefix=GATEKEEPER_SERVER_ 的环境变量会覆盖对应字段。
func LoadServer(path string) (ServerConfig, error) {
	cfg := DefaultServer()
	if path == "" {
		for _, p := range SearchPaths {
			if fileExists(p) {
				path = p
				break
			}
		}
	}
	if path != "" && fileExists(path) {
		if err := applyYAML(path, &cfg); err != nil {
			return cfg, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	applyEnv("GATEKEEPER_SERVER_", &cfg)
	return cfg, nil
}

// LoadAgent 同 LoadServer，envPrefix=GATEKEEPER_AGENT_。
func LoadAgent(path string) (AgentConfig, error) {
	cfg := DefaultAgent()
	if path == "" {
		for _, p := range SearchPaths {
			if fileExists(p) {
				path = p
				break
			}
		}
	}
	if path != "" && fileExists(path) {
		if err := applyYAML(path, &cfg); err != nil {
			return cfg, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	applyEnv("GATEKEEPER_AGENT_", &cfg)
	return cfg, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	if info.Mode().Perm()&0400 == 0 {
		return false
	}
	return true
}

// applyYAML 解析 YAML 文件并反序列化到目标。对未设置字段保留默认值。
func applyYAML(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, out)
}

// applyEnv 通过反射将形如 GATEKEEPER_SERVER_LISTEN 的环境变量覆盖到结构体。
// 仅支持常见标量类型：string / int / bool / time.Duration。
func applyEnv(prefix string, out interface{}) {
	walkEnv(prefix, out)
}

// walkEnv 递归遍历结构体，匹配环境变量后写入字段。实现保持简单，避免引入 reflect 大段。
func walkEnv(prefix string, out interface{}) {
	// 反射实现见 env_reflect.go
	envReflect(prefix, out)
}

// homeDir 返回当前用户的 HOME，失败返回空字符串。
func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// ParseDuration 宽松解析 duration，允许纯数字视为秒。
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid duration %q", s)
}

// IsValidMode 仅供校验 LogLevel 字段。
func IsValidMode(s string) bool {
	switch strings.ToLower(s) {
	case "debug", "info", "warn", "error", "":
		return true
	}
	return false
}

// ApplyLogLevel 根据配置的 log_level 设置标准库 log 的输出行为。
// debug 级别：显示文件:行号与微秒，便于排查；其余级别使用标准格式。
// 标准库 log 无级别的概念，所有日志统一输出；debug 通过更详细的格式区分。
func ApplyLogLevel(level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		slog.SetLogLoggerLevel(slog.LevelDebug)
		log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	default:
		slog.SetLogLoggerLevel(slog.LevelInfo)
		log.SetFlags(log.LstdFlags)
	}
}
