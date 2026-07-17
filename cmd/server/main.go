// Command gatekeeper-server 是 Gatekeeper 管理端：接收 agent 反向长连，下发账户救援指令。
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/server"
	"gatekeeper/internal/version"
)

func main() {
	var (
		cfgPath = flag.String("config", "", "配置文件路径，留空则按以下顺序查找: ./gatekeeper.yaml, ~/.gatekeeper/gatekeeper.yaml, /etc/gatekeeper/gatekeeper.yaml")
		addr    = flag.String("addr", "", "覆盖配置中的 listen 地址")
	)
	flag.Parse()

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if *addr != "" {
		cfg.Listen = *addr
	}
	log.Printf("[gatekeeper-server] v%s 配置加载完成: listen=%s db=%s", version.String(), cfg.Listen, cfg.DBPath)

	store, err := server.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer store.Close()

	// 初始化 admin 用户(多账号体系): 迁移老 settings.admin_password 到 users 表。
	adminHash, _ := store.SettingGet("admin_password")
	if cfg.UI.AdminPassword != "" {
		// 配置文件显式给了明文 -> 给 admin 用户覆盖口令哈希。
		if h, err := server.HashPassword(cfg.UI.AdminPassword); err == nil {
			adminHash = h
			_ = store.SettingSet("admin_password", h) // 保留旧 settings 行做兼容
			log.Printf("[security] 已用配置中的 admin_password 重新哈希落库")
		}
	}
	// 若 users 表无 admin 用户, 则创建一个(role=admin)。
	if u, _, _ := store.GetUser("admin"); u == nil {
		if adminHash == "" {
			// 首次启动且未配置: 生成随机明文, 哈希落库, 明文仅打印一次。
			plain := randomHex(8)
			if h, err := server.HashPassword(plain); err == nil {
				adminHash = h
				_ = store.SettingSet("admin_password", h)
				log.Printf("[security] 首次启动，已自动生成 admin 口令(请妥善保存, 仅显示一次): %s", plain)
			}
		} else {
			log.Printf("[security] 已从老 settings.admin_password 迁移到 users 表")
		}
		if err := store.CreateUser("admin", adminHash, "admin"); err != nil {
			log.Printf("[security] 创建 admin 用户失败: %v", err)
		}
	} else if cfg.UI.AdminPassword != "" {
		// admin 已存在但配置给了新明文: 同步覆盖口令
		_ = store.SetUserPassword("admin", adminHash)
		log.Printf("[security] 已用配置中的 admin_password 更新 admin 用户口令")
	} else {
		log.Printf("[security] 使用 users 表中已有 admin 账号; 若需重置请登录后到用户管理页或修改 server.yaml")
	}

	// 处理 agent token: 仅登记配置文件中显式指定的 bootstrap token, 不再自动生成。
	// 首次部署请通过 UI「Token 管理」或 API 手动创建 token。
	if cfg.Agent.BootstrapToken != "" {
		_ = store.EnsureToken(cfg.Agent.BootstrapToken, "bootstrap", "")
		log.Printf("[bootstrap] 已登记 agent token (来自配置): %s...", server.TokenPrefix(cfg.Agent.BootstrapToken))
	} else if n, _ := store.TokenCount(); n == 0 {
		log.Printf("[bootstrap] 当前无任何 agent token，请通过 UI「Token 管理」或 API 手动创建")
	}

	// agent 健康告警检查器: 可配置 webhook, 超时未心跳触发
	alertCh := make(chan struct{})
	alertChecker := server.NewAlertChecker(store, cfg.Alerts)
	go alertChecker.Run(alertCh)

	srv := server.New(store, cfg.TrustedProxies, cfg.Agent.BindBootstrapToken,
		int(cfg.Defaults.HistoryRetention/(24*time.Hour)), cfg.UI.SessionTTL, cfg.Agent.HeartbeatTimeout)
	srv.SetAlerter(alertChecker)

	// 初始化 shell 策略: 种子默认黑白名单 + 加载配置到内存
	if err := store.SeedShellRules(); err != nil {
		log.Printf("[shell] 种子默认规则失败: %v", err)
	}
	// 配置文件为首次启动提供初始值; 后续以 DB settings 为准(用户可通过 API 修改)
	shellEnabled := cfg.Shell.Enabled
	if v, _ := store.SettingGet("shell_enabled"); v != "" {
		shellEnabled = v == "1"
	} else {
		shellStr := "0"
		if shellEnabled {
			shellStr = "1"
		}
		_ = store.SettingSet("shell_enabled", shellStr)
	}
	shellTimeout := cfg.Shell.Timeout
	if shellTimeout <= 0 {
		shellTimeout = 60 * time.Second
	}
	if v, _ := store.SettingGet("shell_timeout"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			shellTimeout = time.Duration(n) * time.Second
		}
	} else {
		_ = store.SettingSet("shell_timeout", strconv.Itoa(int(shellTimeout/time.Second)))
	}
	shellMaxOutput := cfg.Shell.MaxOutput
	if shellMaxOutput <= 0 {
		shellMaxOutput = 65536
	}
	if v, _ := store.SettingGet("shell_max_output"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			shellMaxOutput = n
		}
	} else {
		_ = store.SettingSet("shell_max_output", strconv.Itoa(shellMaxOutput))
	}
	// 匹配模式: strict_glob(默认) / legacy / permissive / strict_chars
	shellMatchMode := "strict_glob"
	if v, _ := store.SettingGet("shell_match_mode"); v != "" {
		shellMatchMode = v
	} else {
		_ = store.SettingSet("shell_match_mode", shellMatchMode)
	}
	srv.SetShellConfig(shellEnabled, shellTimeout, shellMaxOutput, shellMatchMode)
	if shellEnabled {
		log.Printf("[shell] 通用 shell 下发已启用: timeout=%s max_output=%d match_mode=%s", shellTimeout, shellMaxOutput, shellMatchMode)
	} else {
		log.Printf("[shell] 通用 shell 下发未启用 (配置 shell.enabled=false)")
	}
	if len(cfg.TrustedProxies) == 0 {
		log.Printf("[security] 未配置 trusted_proxies, 将忽略所有 X-Forwarded-For, 使用直连 IP 做登录限速(公网部署推荐)")
	} else {
		log.Printf("[security] 已信任前置代理 CIDR: %v (仅这些来源的 XFF 才会被采信)", cfg.TrustedProxies)
	}
	if cfg.Agent.BindBootstrapToken {
		log.Printf("[security] bootstrap token 将在首次被某 agent 注册时自动绑定到该 agent_id")
	}

	// 超时扫描器：每 15s 清理一次 pending 超时的指令
	go runTimeoutSweeper(srv, store, cfg.Defaults.CmdTimeout)
	// 在线状态扫描器：心跳超时则判定离线，弥补 agent 没有 TCP FIN 就掉线的假在线
	go runHeartbeatSweeper(store, cfg.Agent.HeartbeatTimeout)
	// 数据留存清理器：每日跑一次, 按 DB settings 与 YAML 下限取较大值(更严格)
	go runRetentionWorker(store, cfg.Defaults.HistoryRetention)
	// 账户巡检调度器 (默认每 6 小时扫描一次)
	go srv.StartAccountScanScheduler(resolveScanInterval(store), make(chan struct{}))

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Mux(cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("[gatekeeper-server] 监听 %s (登录口令已在启动日志中显示)", cfg.Listen)
	fmt.Println("→ 浏览器打开 http://<server-ip>:<port>/ 输入管理员口令登录。Agent 接入命令参考 README。")

	// 优雅关闭: 监听 SIGTERM/SIGINT, 安全关闭 HTTP server 和 DB。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
			if err := hs.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key); err != nil && err != http.ErrServerClosed {
				log.Fatalf("TLS 服务启动失败: %v", err)
			}
		} else {
			log.Printf("[warn] 未启用 TLS，使用明文 ws/http —— 仅建议内网/测试环境使用")
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("服务启动失败: %v", err)
			}
		}
	}()

	sig := <-sigCh
	log.Printf("[gatekeeper-server] 收到信号 %v, 开始优雅关闭...", sig)

	// 通知后台 goroutine 停止
	close(alertCh)

	// 给 HTTP 服务 15 秒完成正在处理的请求和 WebSocket 关闭
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		log.Printf("[gatekeeper-server] HTTP 关闭超时: %v", err)
	}

	if err := store.Close(); err != nil {
		log.Printf("[gatekeeper-server] DB 关闭失败: %v", err)
	}
	log.Printf("[gatekeeper-server] 已安全退出")
}

// runTimeoutSweeper 定期把超过 timeout 仍 pending 的指令标记为 timeout。
func runTimeoutSweeper(srv *server.Server, store *server.Store, timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for range t.C {
		ids, _ := store.SweepTimeouts(timeout)
		for range ids {
			// 可在此广播 UI 通知；目前仅写库
		}
	}
}

// runHeartbeatSweeper 定期检查 last_seen, 把超时未心跳的 agent 标记为离线。
func runHeartbeatSweeper(store *server.Store, hbTimeout time.Duration) {
	if hbTimeout <= 0 {
		hbTimeout = 90 * time.Second
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for range t.C {
		if ids, _ := store.SweepStaleAgents(hbTimeout); len(ids) > 0 {
			log.Printf("[sweeper] %d 个 agent 心跳超时置离线: %v", len(ids), ids)
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// runRetentionWorker 每日按"DB settings -> YAML 下限"取较严格(较大)保留天数清理旧数据。
// DB setting 缺省回落到 YAML history_retention; DB 设置不得低于 YAML 下限(否则按下限执行)。
func runRetentionWorker(store *server.Store, yamlMin time.Duration) {
	minDays := int(yamlMin / (24 * time.Hour))
	if minDays < 1 {
		minDays = 180
	}
	// 启动后等 30s 再跑第一次, 避免与启动初始化抢锁
	time.Sleep(30 * time.Second)
	run := func() {
		days := resolveRetentionDays(store, minDays)
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		a, c, err := store.PurgeOlderThan(cutoff)
		if err != nil {
			log.Printf("[retention] 清理失败: %v", err)
			return
		}
		if a > 0 || c > 0 {
			log.Printf("[retention] 已清理 audit=%d commands=%d (保留 %d 天, 下限 %d 天)", a, c, days, minDays)
		}
	}
	run()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for range t.C {
		run()
	}
}

// resolveRetentionDays 解析 DB settings 中的 audit_retention_days,
// 若未设或小于下限则按下限返回。
func resolveRetentionDays(store *server.Store, minDays int) int {
	v, _ := store.SettingGet("audit_retention_days")
	if v == "" {
		return minDays
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minDays {
		return minDays
	}
	return n
}

// resolveScanInterval 解析 DB settings 中的 account_scan_interval_hours,
// 缺省 6 小时, 最少 1 小时。
func resolveScanInterval(store *server.Store) time.Duration {
	v, _ := store.SettingGet("account_scan_interval_hours")
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return time.Duration(n) * time.Hour
		}
	}
	return 6 * time.Hour
}
