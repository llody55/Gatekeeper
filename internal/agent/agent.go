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
	"sync"
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
		start := time.Now()
		err := connectAndServe(ctx, opts)
		if err != nil {
			log.Printf("[agent] 连接断开: %v", err)
		}
		// 上次连接存活时间超过 ReconnectMax 说明之前的连接是稳定的(非拨号即败),
		// 下次重连不必再走完整指数退避, 重置到最小值以快速恢复。
		if time.Since(start) > opts.ReconnectMax {
			backoff = opts.ReconnectMin
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

	// 读超时: 若在 readDeadline 内未收到任何消息(含 pong), 判定连接已死,
	// ReadJSON 返回超时错误, 触发上层重连。取心跳的 3 倍, 容忍网络抖动。
	// 这解决了 server 被 kill -9 / OOM / 宿主机宕机 / 网络静默中断时不发 FIN 导致
	// ReadJSON 永久阻塞(卡死)的问题——否则只能等 TCP 重传超时(~15min)或 keepalive(~2h)。
	readDeadline := opts.Heartbeat * 3
	if readDeadline < 30*time.Second {
		readDeadline = 30 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))

	// 写锁: gorilla/websocket 不允许一连接并发写, 否则帧交错/数据竞争/panic。
	// 心跳 goroutine 和每条 handleCmd goroutine 的写操作都通过此锁串行化。
	var writeMu sync.Mutex
	safeWrite := func(env proto.Envelope) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeJSON(conn, env)
	}

	hostname, _ := os.Hostname()
	reg := proto.Envelope{
		Kind:     proto.KindRegister,
		Token:    opts.Token,
		AgentID:  opts.AgentID,
		Hostname: hostname,
		OS:       runtime.GOOS,
	}
	if err := safeWrite(reg); err != nil {
		return err
	}

	pingC := time.NewTicker(opts.Heartbeat)
	defer pingC.Stop()
	// connCtx 在 connectAndServe 返回时被 cancel, 用于唤醒可能仍阻塞在 select 上的
	// ping goroutine, 避免 ticker 已 Stop 但 goroutine 无法退出导致的泄漏。
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 2)
	go func() { done <- readLoop(conn, opts, safeWrite, readDeadline) }()
	go func() {
		for {
			select {
			case <-connCtx.Done():
				return
			case <-pingC.C:
				if err := safeWrite(proto.Envelope{Kind: proto.KindPing, AgentID: opts.AgentID, Payload: "ping"}); err != nil {
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

func readLoop(conn *websocket.Conn, opts Options, safeWrite func(proto.Envelope) error, readDeadline time.Duration) error {
	for {
		var env proto.Envelope
		if err := conn.ReadJSON(&env); err != nil {
			return err
		}
		// 收到任何消息(pong/ok/cmd)都说明连接活着, 刷新读超时。
		// server 异常退出不发 FIN 时, 下次 pong 不会到达, readDeadline 到期即触发重连。
		_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
		switch env.Kind {
		case proto.KindOK:
			log.Printf("[agent] 注册成功，已纳入管理")
		case proto.KindErr:
			log.Printf("[agent] server 报错: %s", env.Payload)
		case proto.KindPong:
			// 心跳回执
		case proto.KindCmd:
			go handleCmd(conn, env.Cmd, opts, safeWrite)
		}
	}
}

func handleCmd(conn *websocket.Conn, c *proto.Cmd, opts Options, safeWrite func(proto.Envelope) error) {
	if c == nil {
		return
	}
	log.Printf("[agent] 收到指令 %s action=%s user=%s", c.ID, c.Action, c.User)
	res := Execute(c)
	_ = safeWrite(proto.Envelope{Kind: proto.KindResult, AgentID: opts.AgentID, Result: res})
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
