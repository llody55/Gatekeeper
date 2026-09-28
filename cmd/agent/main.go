// Command gatekeeper-agent 是常驻主机端的 agent，反连 server 等待账户救援指令。
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gatekeeper/internal/agent"
	"gatekeeper/internal/config"
)

func main() {
	var (
		cfgPath = flag.String("config", "", "配置文件路径，留空则按以下顺序查找: ./gatekeeper.yaml, ./gatekeeper-agent.yaml, ~/.gatekeeper/gatekeeper.yaml, /etc/gatekeeper/gatekeeper.yaml")
		server  = flag.String("server", "", "覆盖配置中的 server_url")
		token   = flag.String("token", "", "覆盖配置中的 token (也可用环境变量 GATEKEEPER_AGENT_TOKEN)")
		agentID = flag.String("id", "", "覆盖配置中的 agent_id")
	)
	flag.Parse()

	cfg, err := config.LoadAgent(*cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	config.ApplyLogLevel(cfg.LogLevel)

	if *server != "" {
		cfg.ServerURL = *server
	}
	if *token != "" {
		cfg.Token = *token
	} else if cfg.Token == "" {
		cfg.Token = os.Getenv("GATEKEEPER_AGENT_TOKEN")
	}
	if *agentID != "" {
		cfg.AgentID = *agentID
	}
	if cfg.Token == "" {
		log.Fatal("必须在配置文件、-token 或环境变量 GATEKEEPER_AGENT_TOKEN 中提供 token")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	agent.Run(ctx, agent.Options{
		ServerURL:            cfg.ServerURL,
		Token:                cfg.Token,
		AgentID:              cfg.AgentID,
		AgentIDFile:          cfg.AgentIDFile,
		Heartbeat:            cfg.Heartbeat,
		ReconnectMin:         cfg.ReconnectMin,
		ReconnectMax:         cfg.ReconnectMax,
		InsecureTLS:          cfg.InsecureTLS,
		TrustedCAFingerprint: cfg.TrustedCAFingerprint,
	})
}
