// Command gatekeeper-server 是 Gatekeeper 管理端：接收 agent 反向长连，下发账户救援指令。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/server"
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
	log.Printf("[gatekeeper-server] 配置加载完成: listen=%s db=%s", cfg.Listen, cfg.DBPath)

	store, err := server.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer store.Close()

	// 初始化 admin_password：以 bcrypt 哈希存入 DB，明文绝不入库。
	storedHash, _ := store.SettingGet("admin_password")
	if cfg.UI.AdminPassword != "" {
		// 配置文件显式给了明文 -> 哈希后覆盖入库。明文不回写 cfg 用于鉴权。
		if h, err := server.HashPassword(cfg.UI.AdminPassword); err == nil {
			_ = store.SettingSet("admin_password", h)
			log.Printf("[security] 已用配置中的 admin_password 重新哈希落库")
		}
		// 配置明文同时可以用于 AllowQueryToken 路径(默认关闭, 仅内网便捷)
	} else if storedHash == "" {
		// 首次启动且未配置: 生成随机明文, 哈希落库, 明文仅打印一次。
		plain := randomHex(8)
		if h, err := server.HashPassword(plain); err == nil {
			_ = store.SettingSet("admin_password", h)
			log.Printf("[security] 首次启动，已自动生成管理员口令(请妥善保存, 仅显示一次): %s", plain)
		}
		// 不将明文写回 cfg；用户后续登录靠该明文，遗失需按 CONFIG.md 流程重置。
	} else {
		log.Printf("[security] 使用数据库中已有 admin 口令哈希; 若需重置请按 CONFIG.md 操作")
	}

	// 处理 agent token
	if cfg.Agent.BootstrapToken != "" {
		_ = store.EnsureToken(cfg.Agent.BootstrapToken, "bootstrap", "")
		log.Printf("[bootstrap] 已登记 agent token (来自配置): %s", cfg.Agent.BootstrapToken)
	} else if n, _ := store.TokenCount(); n == 0 {
		t := randomHex(10)
		_ = store.EnsureToken(t, "auto-bootstrap", "")
		store.Audit("system", "token_bootstrap", t, "auto generated on first run", "127.0.0.1")
		log.Printf("[bootstrap] 首次启动无任何 agent token，已自动生成: %s", t)
	}

	srv := server.New(store, cfg.TrustedProxies, cfg.Agent.BindBootstrapToken)
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

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Mux(cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("[gatekeeper-server] 监听 %s (登录口令已在启动日志中显示)", cfg.Listen)
	fmt.Println("→ 浏览器打开 http://<server-ip>:<port>/ 输入管理员口令登录。Agent 接入命令参考 README。")

	if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
		log.Fatal(hs.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key))
	} else {
		log.Printf("[warn] 未启用 TLS，使用明文 ws/http —— 仅建议内网/测试环境使用")
		log.Fatal(hs.ListenAndServe())
	}
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
