package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
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
	sessionTTL         time.Duration // 管理端会话有效期; 默认 12h
	heartbeatTimeout   time.Duration // agent 心跳超时; 用于 readPump 读超时兜底
	shellEnabled       bool          // shell action 是否启用
	shellTimeout       time.Duration // shell 执行超时
	shellMaxOutput     int           // shell 输出截断字节数
	shellMatchMode     string        // shell 命令匹配模式: legacy / permissive / strict_chars / strict_glob
	alert              *AlertChecker // agent 健康告警检查器; 可能为 nil
	dispatchSem        chan struct{} // 指令并发信号量: 限制同时下发未回执的指令数量, 防止突发下发耗尽资源
	pendingCmds        map[string]*StoredCmd // 内存中保留未脱敏的 pending 指令, 供 agent 重连后重发（DB 中 password 已脱敏无法重发）
	pendingMu          sync.Mutex
	shellRuleCache     struct { // shell 黑白名单内存缓存, 避免每次下发都查 DB
		black []ShellRule
		white []ShellRule
		mu    sync.RWMutex
		valid bool
	}
}

// Shell 匹配模式常量。
const (
	ShellMatchLegacy      = "legacy"       // 老模式: * 匹配任意字符(含元字符), 不安全, 仅兼容
	ShellMatchPermissive  = "permissive"   // 允许所有: 跳过黑白名单检查
	ShellMatchStrictChars = "strict_chars" // 拒元字符: 命令含 ;|& 等直接拒绝
	ShellMatchStrictGlob  = "strict_glob"  // 严格通配: * 不匹配元字符, 精确规则允许元字符 [默认推荐]
)

// SetShellConfig 注入 shell 策略配置。
func (s *Server) SetShellConfig(enabled bool, timeout time.Duration, maxOutput int, matchMode string) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if maxOutput <= 0 {
		maxOutput = 65536
	}
	s.shellEnabled = enabled
	s.shellTimeout = timeout
	s.shellMaxOutput = maxOutput
	s.shellMatchMode = validShellMatchMode(matchMode)
}

// IsShellEnabled 返回 shell action 是否已启用。
func (s *Server) IsShellEnabled() bool { return s.shellEnabled }

// ShellTimeout 返回 shell 执行超时时长。
func (s *Server) ShellTimeout() time.Duration { return s.shellTimeout }

// ShellMaxOutput 返回 shell 输出截断字节数。
func (s *Server) ShellMaxOutput() int { return s.shellMaxOutput }

// ShellMatchModeStr 返回当前匹配模式名称。
func (s *Server) ShellMatchModeStr() string { return s.shellMatchMode }

// validShellMatchMode 校验并归一化匹配模式值，无效则回落到 legacy。
func validShellMatchMode(m string) string {
	switch m {
	case ShellMatchLegacy, ShellMatchPermissive, ShellMatchStrictChars, ShellMatchStrictGlob:
		return m
	default:
		return ShellMatchStrictGlob
	}
}

// containsShellMetachars 检测命令是否含 shell 元字符(;|&$\`等)。
// 这些字符在 bash -c 下有命令分隔/替换语义，可被利用绕过白名单。
// 空格不是元字符——它只是参数分隔符，不影响 bash 的命令解析边界。
func containsShellMetachars(s string) bool {
	return strings.ContainsAny(s, ";&|`$\n\r()<>") || strings.Contains(s, "\\")
}

// shellRules 从缓存返回启用的黑白名单规则；缓存未命中时查 DB 并填充。
func (s *Server) shellRules() (black, white []ShellRule) {
	s.shellRuleCache.mu.RLock()
	if s.shellRuleCache.valid {
		black, white = s.shellRuleCache.black, s.shellRuleCache.white
		s.shellRuleCache.mu.RUnlock()
		return
	}
	s.shellRuleCache.mu.RUnlock()

	s.shellRuleCache.mu.Lock()
	defer s.shellRuleCache.mu.Unlock()
	// double-check: 可能其他 goroutine 已填充
	if s.shellRuleCache.valid {
		return s.shellRuleCache.black, s.shellRuleCache.white
	}
	b, _ := s.Store.ListShellRules("blacklist", true)
	w, _ := s.Store.ListShellRules("whitelist", true)
	s.shellRuleCache.black = b
	s.shellRuleCache.white = w
	s.shellRuleCache.valid = true
	return b, w
}

// InvalidateShellRules 使 shell 规则缓存失效，在规则增删改后调用。
func (s *Server) InvalidateShellRules() {
	s.shellRuleCache.mu.Lock()
	s.shellRuleCache.valid = false
	s.shellRuleCache.mu.Unlock()
}

// ShellAllowed 判断命令是否被策略允许执行。
// 返回 (allowed, reason)。
// 判定优先级: 黑名单 > 白名单 > 放行。
// 匹配模式影响过滤行为:
//   - legacy:        * 匹配任意字符(含元字符)，当前行为
//   - permissive:    跳过黑白名单，直接放行
//   - strict_chars:  命令含元字符直接拒，否则走正常黑白名单
//   - strict_glob:   * 不匹配元字符，精确规则(无*)允许元字符
func (s *Server) ShellAllowed(command string) (bool, string) {
	// permissive 模式: 跳过所有检查
	if s.shellMatchMode == ShellMatchPermissive {
		return true, ""
	}

	// strict_chars 模式: 先拒元字符，再走正常匹配
	if s.shellMatchMode == ShellMatchStrictChars {
		if containsShellMetachars(command) {
			return false, "command contains shell metacharacters (;|& etc), blocked by strict_chars mode"
		}
	}

	// 选择匹配函数
	matchFn := globMatch
	if s.shellMatchMode == ShellMatchStrictGlob {
		matchFn = globMatchStrict
	}

	blackRules, whiteRules := s.shellRules()
	// 1. 黑名单优先
	for _, r := range blackRules {
		if matchFn(r.Pattern, command) {
			return false, "blocked by blacklist: " + r.Pattern
		}
	}
	// 2. 白名单非空则命令必须命中至少一条
	if len(whiteRules) == 0 {
		return true, ""
	}
	for _, r := range whiteRules {
		if matchFn(r.Pattern, command) {
			return true, ""
		}
	}
	return false, "not in whitelist"
}

// globMatch 简单 glob 匹配: * 匹配任意字符(含空格/斜杠), 其余字符精确匹配。
// 例如 "systemctl *" 匹配 "systemctl restart nginx"
//
//	"cat /etc/*"   匹配 "cat /etc/nginx/nginx.conf"
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	// 检查前缀
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	// 检查中间各段
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue // ** 等价于 *
		}
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}
	// 检查后缀
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// globMatchStrict 与 globMatch 类似，但 * 不匹配 shell 元字符。
// 精确规则（不含 *）允许元字符（如 "ps aux | grep nginx" 作为完整白名单）。
// 含 * 的规则中，* 只匹配不含元字符的字符序列，防止 "systemctl restart *"
// 被 "systemctl restart x; rm -rf /" 绕过。
func globMatchStrict(pattern, s string) bool {
	// 精确匹配(无 *)：允许元字符，用于白名单写死完整管道命令
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	rest := s[len(parts[0]):]

	if len(parts) == 2 {
		// 单 * 模式 (最常见): "prefix*" → rest 是 * 匹配的部分
		return !containsShellMetachars(rest)
	}

	// 多 * 模式: 逐段匹配，每段 * 匹配部分不得含元字符
	// 先用普通 globMatch 检查能否匹配
	if !globMatch(pattern, s) {
		return false
	}
	// 能匹配 → 追踪各 * 段并校验元字符
	s2 := s[len(parts[0]):] // 重新从头开始追踪
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(s2, parts[i])
		if idx < 0 {
			return false
		}
		// s2[:idx] 是当前 * 匹配的段
		if containsShellMetachars(s2[:idx]) {
			return false
		}
		s2 = s2[idx+len(parts[i]):]
	}
	// 尾部 * 匹配的段
	suffix := parts[len(parts)-1]
	if suffix != "" {
		if !strings.HasSuffix(s2, suffix) {
			return false
		}
		if containsShellMetachars(s2[:len(s2)-len(suffix)]) {
			return false
		}
	} else {
		if containsShellMetachars(s2) {
			return false
		}
	}
	return true
}

// New 构造 Server；trustedProxies 为 CIDR 字符串列表，"any" 表示信任所有。
func New(s *Store, trustedProxies []string, bindBootstrapToken bool, retentionMinDays int, sessionTTL time.Duration, heartbeatTimeout time.Duration) *Server {
	if sessionTTL <= 0 {
		sessionTTL = 12 * time.Hour
	}
	srv := &Server{Store: s, sessions: map[string]*Session{}, uiHub: newUIHub(),
		bindBootstrapToken: bindBootstrapToken, retentionMinDays: retentionMinDays, sessionTTL: sessionTTL, heartbeatTimeout: heartbeatTimeout,
		dispatchSem: make(chan struct{}, 256), pendingCmds: map[string]*StoredCmd{}}
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
	CheckOrigin:     checkOrigin,
}

// checkOrigin 校验 WebSocket 请求来源: 允许同源浏览器请求和非浏览器客户端(无 Origin 头)。
// 阻止跨站 WebSocket 劫持(CSWSH): 恶意网页无法从不同 origin 连接 /ui/events 窃取事件流。
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	// 非浏览器客户端(如 agent 的 Go websocket dialer)不发送 Origin 头, 允许通过。
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := u.Hostname()
	originPort := u.Port()
	if originPort == "" {
		// 浏览器对默认端口省略端口号
		if u.Scheme == "https" || u.Scheme == "wss" {
			originPort = "443"
		} else {
			originPort = "80"
		}
	}
	reqHost := r.Host
	if h, p, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h + ":" + p
	} else {
		// 请求 Host 无端口, 补默认端口用于比较
		if strings.HasPrefix(r.URL.Scheme, "https") || r.TLS != nil {
			reqHost = reqHost + ":443"
		} else {
			reqHost = reqHost + ":80"
		}
	}
	return originHost+":"+originPort == reqHost
}

// AgentWS 处理 agent 的 WebSocket 反向连接。
func (s *Server) AgentWS(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Agent-Token")
	agentID := r.Header.Get("X-Agent-Id")
	if token == "" || agentID == "" {
		http.Error(w, "missing token/id", http.StatusUnauthorized)
		return
	}
	// agent_id 格式校验: 防止超长或含特殊字符的 ID 写入 DB/内存 map 造成滥用。
	if ok, msg := validAgentID(agentID); !ok {
		http.Error(w, msg, http.StatusBadRequest)
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

	// 等待 register 帧 (设 30s 超时防止恶意连接不发帧导致 goroutine 泄漏)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
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
		s.Store.Audit("agent", "token_first_bind", TokenPrefix(token), "agent_id="+agentID, ip)
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
	// 重连后重发该 agent 未完成的 pending 指令，修复下发后断线导致的指令丢失
	s.ResendPending(agentID, sess)

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

// ---- 账户巡检扫描 ----

// handleScanResult 解析 scan_accounts 的 JSON 输出, 写入 account_scans 表。
func (s *Server) handleScanResult(agentID, output string) {
	var accounts []AccountScanRow
	if err := json.Unmarshal([]byte(output), &accounts); err != nil {
		log.Printf("[server] 解析 %s 的 scan_accounts 结果失败: %v", agentID, err)
		return
	}
	if err := s.Store.UpsertAccountScan(agentID, accounts); err != nil {
		log.Printf("[server] 存储 %s 的账户扫描结果失败: %v", agentID, err)
		return
	}
	// 账户过期告警: 检查过期/即将过期账户并通知
	if s.alert != nil {
		hostname := s.Store.HostnameOf(agentID)
		s.alert.NotifyAccountExpired(agentID, hostname, accounts)
	}
	// 向 UI 推送巡检更新事件
	s.uiHub.Broadcast(map[string]any{
		"type":     "account_scan_updated",
		"agent_id": agentID,
		"count":    len(accounts),
	})
	log.Printf("[server] 已接收 %s 的账户巡检结果: %d 个账户", agentID, len(accounts))
}

// TriggerAccountScan 触发对指定 agent 或全部在线 agent 的账户巡检。
// 返回成功接受的 agent 数量。
func (s *Server) TriggerAccountScan(targetAgentID string) int {
	cmdID := "scan-" + time.Now().Format("20060102150405") + randomHex(4)
	accepted := 0
	if targetAgentID != "" {
		// 单个 agent
		c := &StoredCmd{
			ID: cmdID, AgentID: targetAgentID, Action: proto.ActionScanAccounts,
			Params: map[string]string{"min_uid": "0"}, CreatedBy: "system",
		}
		_ = s.Store.SaveCmd(c)
		if s.Send(targetAgentID, proto.Envelope{
			Kind: proto.KindCmd,
			Cmd:  &proto.Cmd{ID: cmdID, Action: proto.ActionScanAccounts, Params: map[string]string{"min_uid": "0"}},
		}) {
			accepted = 1
		}
	} else {
		// 全部在线 agent
		s.mu.RLock()
		ids := make([]string, 0, len(s.sessions))
		for id := range s.sessions {
			ids = append(ids, id)
		}
		s.mu.RUnlock()
		for _, id := range ids {
			subCmdID := cmdID + "-" + id
			c := &StoredCmd{
				ID: subCmdID, AgentID: id, Action: proto.ActionScanAccounts,
				Params: map[string]string{"min_uid": "0"}, CreatedBy: "system",
			}
			_ = s.Store.SaveCmd(c)
			if s.Send(id, proto.Envelope{
				Kind: proto.KindCmd,
				Cmd:  &proto.Cmd{ID: subCmdID, Action: proto.ActionScanAccounts, Params: map[string]string{"min_uid": "0"}},
			}) {
				accepted++
			}
		}
	}
	return accepted
}

// StartAccountScanScheduler 启动定时账户巡检 goroutine, 需在独立 goroutine 中调用。
// stopCh 关闭时退出。
func (s *Server) StartAccountScanScheduler(interval time.Duration, stopCh <-chan struct{}) {
	log.Printf("[server] 账户巡检调度器已启动, 间隔 %v", interval)
	// 启动后延迟 30s 首次扫描, 给所有 agent 重连时间
	select {
	case <-stopCh:
		return
	case <-time.After(30 * time.Second):
	}
	for {
		log.Printf("[server] 账户巡检: 开始扫描 %d 个在线 agent", len(s.SessionsIDs()))
		s.TriggerAccountScan("")
		select {
		case <-stopCh:
			log.Printf("[server] 账户巡检调度器已停止")
			return
		case <-time.After(interval):
		}
	}
}

// SessionsIDs 返回当前所有在线 agent 的 id 列表。
func (s *Server) SessionsIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}

// OnlineAgentCount 返回当前在线(已建立 WebSocket 会话)的 agent 数量。
func (s *Server) OnlineAgentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// PendingCmdCount 返回内存中待回执指令数量。
func (s *Server) PendingCmdCount() int {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return len(s.pendingCmds)
}

// randomHex 生成 n 字节随机数的 hex 编码。
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
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
	// 指令下发占用并发信号量；ping/pong 等控制消息不占用。
	if env.Kind == proto.KindCmd {
		select {
		case s.dispatchSem <- struct{}{}:
		default:
			return false // 并发上限，拒绝本次下发
		}
		if !sess.Send(env) {
			<-s.dispatchSem // 发送失败，立即释放信号量
			return false
		}
		return true
	}
	return sess.Send(env)
}

// ReleaseDispatch 释放一个指令并发信号量槽位（收到 agent 回执或指令超时时调用）。
func (s *Server) ReleaseDispatch() {
	select {
	case <-s.dispatchSem:
	default:
	}
}

// SavePendingCmd 在内存中保留未脱敏的指令副本，供 agent 重连后重发。
// DB 落库时 password 已脱敏，重发必须用内存中的原始副本。
func (s *Server) SavePendingCmd(c *StoredCmd) {
	s.pendingMu.Lock()
	s.pendingCmds[c.ID] = c
	s.pendingMu.Unlock()
}

// PopPendingCmd 取出并删除内存中的 pending 指令副本（回执或超时时调用）。
func (s *Server) PopPendingCmd(id string) *StoredCmd {
	s.pendingMu.Lock()
	c := s.pendingCmds[id]
	delete(s.pendingCmds, id)
	s.pendingMu.Unlock()
	return c
}

// ResendPending 把该 agent 所有 pending 指令重新下发到新会话。
// agent 断线重连后调用，修复"下发后断线导致指令丢失"的问题。
func (s *Server) ResendPending(agentID string, sess *Session) {
	ids, err := s.Store.PendingCmdIDs(agentID)
	if err != nil || len(ids) == 0 {
		return
	}
	s.pendingMu.Lock()
	for _, id := range ids {
		c, ok := s.pendingCmds[id]
		if !ok {
			continue // server 重启后内存无副本，跳过（需用户重新下发）
		}
		// 直接投递到会话 channel，不经过 Server.Send（避免重复占用信号量）
		sess.Send(BuildCmd(c))
	}
	s.pendingMu.Unlock()
	log.Printf("[server] agent %s 重连后重发 %d 条 pending 指令", agentID, len(ids))
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

	// 计算读超时: agent 心跳超时 * 3, 容忍间歇网络抖动的同时保证静默断连能被及时检测。
	// 默认 heartbeatTimeout=90s → deadline=270s, 与 agent 端 readDeadline 设计对称。
	hb := s.srv.heartbeatTimeout
	if hb <= 0 {
		hb = 90 * time.Second
	}
	deadline := hb * 3

	for {
		_ = s.Conn.SetReadDeadline(time.Now().Add(deadline))
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
				s.srv.ReleaseDispatch()
				s.srv.PopPendingCmd(env.Result.CmdID)
				_ = s.srv.Store.FinishCmd(env.Result.CmdID, &ResultBody{
					Output: env.Result.Output,
					Err:    env.Result.Err,
					OK:     env.Result.OK,
				})
				// 特殊处理: scan_accounts 的返回结果存入 account_scans 表
				if cmd, _ := s.srv.Store.GetCmd(env.Result.CmdID); cmd != nil && cmd.Action == proto.ActionScanAccounts {
					if env.Result.OK && env.Result.Output != "" {
						s.srv.handleScanResult(s.AgentID, env.Result.Output)
					}
				}
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
