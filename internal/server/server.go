package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/proto"

	"github.com/gorilla/websocket"
)

// Server 持有 WebSocket 会话、store、UI 实时事件总线。
type Server struct {
	Store              *Store
	mu                 sync.RWMutex
	sessions           map[string]*Session // agent_id -> 会话
	uiHub              *UIHub
	trustedProxies     []*net.IPNet  // 解析后的可信代理 CIDR；为空表示不信任任何 XFF
	bindBootstrapToken bool          // 是否把首次被注册的 bootstrap token 自动绑定到该 agent_id
	retentionMinDays   int           // YAML 配置的留存下限天数, UI/DB 不得低于此值
	alert              *AlertChecker // agent 健康告警检查器; 可能为 nil
}

// New 构造 Server；trustedProxies 为 CIDR 字符串列表，"any" 表示信任所有。
func New(s *Store, trustedProxies []string, bindBootstrapToken bool, retentionMinDays int) *Server {
	srv := &Server{Store: s, sessions: map[string]*Session{}, uiHub: newUIHub(),
		bindBootstrapToken: bindBootstrapToken, retentionMinDays: retentionMinDays}
	for _, c := range trustedProxies {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.EqualFold(c, "any") {
			_, n, _ := net.ParseCIDR("0.0.0.0/0")
			srv.trustedProxies = append(srv.trustedProxies, n)
			continue
		}
		if !strings.Contains(c, "/") {
			c += "/32"
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			srv.trustedProxies = append(srv.trustedProxies, n)
		} else {
			log.Printf("[server] 忽略无法解析的 trusted_proxies 条目: %q", c)
		}
	}
	return srv
}

// SetAlerter 注入告警检查器, 供 /api/alerts/test 等路由调用。
func (s *Server) SetAlerter(a *AlertChecker) { s.alert = a }

type Session struct {
	AgentID string
	Conn    *websocket.Conn
	send    chan proto.Envelope
	srv     *Server
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// AgentWS 处理 agent 的 WebSocket 反向连接。
func (s *Server) AgentWS(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Agent-Token")
	agentID := r.Header.Get("X-Agent-Id")
	if token == "" || agentID == "" {
		http.Error(w, "missing token/id", http.StatusUnauthorized)
		return
	}
	// 绑定校验: token 必须存在且未撤销; 若已绑定到别的 agent_id 则拒绝(防冒名)。
	bound, unbound, boundTo, err := s.Store.CheckTokenBindAgent(token, agentID)
	if err != nil {
		http.Error(w, "token check error", http.StatusInternalServerError)
		return
	}
	if !bound {
		ipHint := s.clientIP(r)
		s.Store.Audit("anonymous", "agent_register_denied", agentID, ".reason=token_bound_to:"+boundTo, ipHint)
		http.Error(w, "agent_id does not match token binding", http.StatusForbidden)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	sess := &Session{AgentID: agentID, Conn: conn, send: make(chan proto.Envelope, 64), srv: s}

	// 等待 register 帧
	var reg proto.Envelope
	if err := conn.ReadJSON(&reg); err != nil {
		conn.Close()
		return
	}
	if reg.Kind != proto.KindRegister {
		conn.Close()
		return
	}
	ip := s.clientIP(r)
	if unbound && s.bindBootstrapToken {
		// bootstrap token 首次被该 agent 使用: 自动绑定, 后续他人即便拿到此 token 也无法冒名。
		_ = s.Store.BindToken(token, agentID)
		s.Store.Audit("agent", "token_first_bind", token, "agent_id="+agentID, ip)
	}
	if first, err := s.Store.TouchAgent(agentID, token, reg.Hostname, reg.OS, ip); err != nil {
		log.Printf("[server] TouchAgent err: %v", err)
	} else if first {
		s.Store.Audit("agent", "register", agentID, "agent_id="+agentID+" hostname="+reg.Hostname, ip)
	}
	s.addSession(sess)
	defer s.removeSession(agentID, sess)
	defer s.Store.OfflineAgent(agentID)

	log.Printf("[server] agent 上线: %s (%s) @ %s", agentID, reg.Hostname, ip)
	_ = sess.Send(proto.Envelope{Kind: proto.KindOK, Payload: "registered"})

	go sess.writePump()
	sess.readPump()
}

// IsOnline 返回 agent 当前是否有活 WebSocket 会话（live 检测，DB online 列只是兜底）。
func (s *Server) IsOnline(agentID string) bool {
	s.mu.RLock()
	_, ok := s.sessions[agentID]
	s.mu.RUnlock()
	return ok
}

// KickSession 强制关闭某 agent 的活 WebSocket 会话。用于 token 撤销后立即断开,
// 避免 agent 在已撤销后仍能接收下发指令。
func (s *Server) KickSession(agentID string) bool {
	s.mu.Lock()
	sess, ok := s.sessions[agentID]
	if ok {
		close(sess.send)
		sess.Conn.Close()
		delete(s.sessions, agentID)
	}
	s.mu.Unlock()
	if ok {
		s.uiHub.Broadcast(map[string]any{"type": "agent_offline", "agent_id": agentID})
	}
	return ok
}

func (s *Server) addSession(sess *Session) {
	s.mu.Lock()
	if old := s.sessions[sess.AgentID]; old != nil {
		close(old.send)
		old.Conn.Close()
	}
	s.sessions[sess.AgentID] = sess
	s.mu.Unlock()
	s.uiHub.Broadcast(map[string]any{"type": "agent_online", "agent_id": sess.AgentID})
}

func (s *Server) removeSession(agentID string, sess *Session) {
	s.mu.Lock()
	if cur := s.sessions[agentID]; cur == sess {
		delete(s.sessions, agentID)
	}
	s.mu.Unlock()
	s.uiHub.Broadcast(map[string]any{"type": "agent_offline", "agent_id": agentID})
}

func (s *Server) Send(agentID string, env proto.Envelope) bool {
	s.mu.RLock()
	sess := s.sessions[agentID]
	s.mu.RUnlock()
	if sess == nil {
		return false
	}
	return sess.Send(env)
}

// ---- Session ----

func (s *Session) Send(env proto.Envelope) bool {
	select {
	case s.send <- env:
		return true
	default:
		return false
	}
}

func (s *Session) writePump() {
	for env := range s.send {
		if err := s.Conn.WriteJSON(env); err != nil {
			return
		}
	}
}

func (s *Session) readPump() {
	defer s.Conn.Close()
	for {
		var env proto.Envelope
		if err := s.Conn.ReadJSON(&env); err != nil {
			return
		}
		switch env.Kind {
		case proto.KindPing:
			_ = s.Send(proto.Envelope{Kind: proto.KindPong, AgentID: s.AgentID})
			_ = s.srv.Store.MarkSeen(s.AgentID)
		case proto.KindResult:
			if env.Result != nil {
				_ = s.srv.Store.FinishCmd(env.Result.CmdID, &ResultBody{
					Output: env.Result.Output,
					Err:    env.Result.Err,
					OK:     env.Result.OK,
				})
				s.srv.uiHub.Broadcast(map[string]any{
					"type":     "result",
					"cmd_id":   env.Result.CmdID,
					"ok":       env.Result.OK,
					"agent_id": s.AgentID,
				})
			}
		}
	}
}

// BuildCmd 构造一个指令 envelope。
func BuildCmd(c *StoredCmd) proto.Envelope {
	return proto.Envelope{
		Kind: proto.KindCmd,
		Cmd: &proto.Cmd{
			ID:     c.ID,
			Action: c.Action,
			User:   c.User,
			Params: c.Params,
		},
	}
}

// UIHub 维护浏览器订阅的事件流。每个 UI 连接可订阅 agent 上线/下线/结果事件。
type UIHub struct {
	mu    sync.RWMutex
	conns map[chan map[string]any]struct{}
}

func newUIHub() *UIHub {
	return &UIHub{conns: map[chan map[string]any]struct{}{}}
}

func (h *UIHub) Subscribe() chan map[string]any {
	ch := make(chan map[string]any, 32)
	h.mu.Lock()
	h.conns[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *UIHub) Unsubscribe(ch chan map[string]any) {
	h.mu.Lock()
	delete(h.conns, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *UIHub) Broadcast(msg map[string]any) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.conns {
		select {
		case ch <- msg:
		default:
			// 缓冲满则丢弃，避免阻塞 server
		}
	}
}

// EventsWS 供浏览器订阅的 WebSocket。
func (s *Server) EventsWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ch := s.uiHub.Subscribe()
	defer s.uiHub.Unsubscribe(ch)
	defer conn.Close()

	// 收消息忽略（浏览器不会主动发，但需消费 ping frame）
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	for msg := range ch {
		if err := conn.WriteJSON(msg); err != nil {
			return
		}
	}
}

// clientIP 从 request 中取出对端 IP。只有当直连对端 IP 命中 s.trustedProxies 时才解析 X-Forwarded-For，
// 否则一律用 RemoteAddr，避免攻击者通过伪造 XFF 绕过登录限速。
func (s *Server) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if h, _, err := net.SplitHostPort(remote); err == nil {
		remote = h
	}
	if len(s.trustedProxies) > 0 {
		ip := net.ParseIP(remote)
		trusted := false
		for _, n := range s.trustedProxies {
			if ip != nil && n.Contains(ip) {
				trusted = true
				break
			}
		}
		if trusted {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if i := indexOfByte(xff, ','); i > 0 {
					return trim(xff[:i])
				}
				return trim(xff)
			}
		}
	}
	return remote
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// keep imports used
var _ = json.Marshal
var _ = time.Second
var _ = rand.Read
var _ = hex.EncodeToString
