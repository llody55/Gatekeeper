package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"gatekeeper/internal/proto"
	"gatekeeper/internal/version"

	"github.com/gorilla/websocket"
)

// Options 是 agent 运行参数。
type Options struct {
	ServerURL            string // 如 wss://server:8443/agent
	Token                string // 注册 token
	AgentID              string // 显式指定则优先；留空走持久化文件
	AgentIDFile          string // 持久化文件路径；留空则 ~/.gatekeeper/agent_id
	Heartbeat            time.Duration
	ReconnectMin         time.Duration
	ReconnectMax         time.Duration
	InsecureTLS          bool
	TrustedCAFingerprint string // wss 时校验证书指纹(sha256 hex)；留空走系统信任
}

// Run 启动 agent：反连 server，断线指数退避重连。AgentID 在多次重启间保持稳定。
func Run(ctx context.Context, opts Options) {
	if opts.AgentID == "" {
		id, err := loadOrCreateAgentID(opts.AgentIDFile)
		if err != nil {
			log.Printf("[agent] 加载/生成 agent_id 失败: %v", err)
			// 退化为内存生成
			id, _ = generateAgentID()
		}
		opts.AgentID = id
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = 30 * time.Second
	}
	if opts.ReconnectMin <= 0 {
		opts.ReconnectMin = 2 * time.Second
	}
	if opts.ReconnectMax <= 0 {
		opts.ReconnectMax = 60 * time.Second
	}
	hostname, _ := os.Hostname()
	log.Printf("[gatekeeper-agent] v%s id=%s hostname=%s 开始反连 %s", version.String(), opts.AgentID, hostname, opts.ServerURL)

	backoff := opts.ReconnectMin
	for {
		if ctx.Err() != nil {
			return
		}
		err := connectAndServe(ctx, opts)
		if err != nil {
			log.Printf("[agent] 连接断开: %v", err)
		}
		if backoff > opts.ReconnectMax {
			backoff = opts.ReconnectMax
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

// connectAndServe 建立一次 WebSocket 会话：注册 -> 收 cmd 执行 -> 回执。
func connectAndServe(ctx context.Context, opts Options) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	if opts.InsecureTLS {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	} else if opts.TrustedCAFingerprint != "" {
		// 只信任指纹匹配的自签证书，绕开系统 CA。
		fp := strings.ToLower(strings.TrimSpace(opts.TrustedCAFingerprint))
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // 我们自己在校验回调里比对指纹
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				for _, c := range rawCerts {
					sum := sha256.Sum256(c)
					if hex.EncodeToString(sum[:]) == fp {
						return nil
					}
				}
				return fmt.Errorf("server cert fingerprint does not match trusted_ca_fingerprint")
			},
		}
	}
	hdr := http.Header{}
	hdr.Set("X-Agent-Token", opts.Token)
	hdr.Set("X-Agent-Id", opts.AgentID)

	conn, _, err := dialer.DialContext(ctx, opts.ServerURL, hdr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	hostname, _ := os.Hostname()
	reg := proto.Envelope{
		Kind:     proto.KindRegister,
		Token:    opts.Token,
		AgentID:  opts.AgentID,
		Hostname: hostname,
		OS:       runtime.GOOS,
	}
	if err := writeJSON(conn, reg); err != nil {
		return err
	}

	pingC := time.NewTicker(opts.Heartbeat)
	defer pingC.Stop()

	done := make(chan error, 2)
	go func() { done <- readLoop(conn, opts) }()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-pingC.C:
				if err := writeJSON(conn, proto.Envelope{Kind: proto.KindPing, AgentID: opts.AgentID, Payload: "ping"}); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func readLoop(conn *websocket.Conn, opts Options) error {
	for {
		var env proto.Envelope
		if err := conn.ReadJSON(&env); err != nil {
			return err
		}
		switch env.Kind {
		case proto.KindOK:
			log.Printf("[agent] 注册成功，已纳入管理")
		case proto.KindErr:
			log.Printf("[agent] server 报错: %s", env.Payload)
		case proto.KindPong:
			// 心跳回执
		case proto.KindCmd:
			go handleCmd(conn, env.Cmd, opts)
		}
	}
}

func handleCmd(conn *websocket.Conn, c *proto.Cmd, opts Options) {
	if c == nil {
		return
	}
	log.Printf("[agent] 收到指令 %s action=%s user=%s", c.ID, c.Action, c.User)
	res := Execute(c)
	out, _ := json.Marshal(proto.Envelope{Kind: proto.KindResult, AgentID: opts.AgentID, Result: res})
	_ = conn.WriteMessage(websocket.TextMessage, out)
}

func writeJSON(conn *websocket.Conn, env proto.Envelope) error {
	b, _ := json.Marshal(env)
	return conn.WriteMessage(websocket.TextMessage, b)
}

// OSInfo 返回系统信息，用于注册补充。
func OSInfo() string {
	out, err := exec.Command("uname", "-a").Output()
	if err != nil {
		return runtime.GOOS
	}
	return string(out)
}
