package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/proto"
	"gatekeeper/internal/version"
)

// ---- 输入校验常量与函数 ----
// 这些校验防止特殊字符破坏 session 解析（session 值以 | 分隔），
// 同时防止 LIKE 通配符注入、超长输入存储滥用等问题。

const (
	maxUsernameLen  = 64  // 用户名最大长度
	maxAgentIDLen   = 128 // agent_id 最大长度
	maxShellPatLen  = 500 // shell 规则 pattern 最大长度
	maxTokenNoteLen = 256 // token 备注/绑定 agent_id 最大长度
	maxDispatchUser = 64  // dispatch user 字段最大长度
)

// reUsername 用户名白名单: 字母/数字/下划线/连字符，1~maxUsernameLen 位。
// 不允许 | % _ 等特殊字符，防止破坏 session 解析 (session 格式 "username|role|expires")
// 和 LIKE 通配符注入。
var reUsername = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// validUsername 校验用户名是否合法，不合法返回错误描述。
func validUsername(name string) (bool, string) {
	if name == "" {
		return false, "username required"
	}
	if len(name) > maxUsernameLen {
		return false, "username too long (max 64 characters)"
	}
	if !reUsername.MatchString(name) {
		return false, "username contains invalid characters (only a-z A-Z 0-9 _ - allowed)"
	}
	return true, ""
}

// reEmail 邮箱格式校验(宽松匹配, 允许本地名含 ._-+)。
var reEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// validEmail 校验邮箱格式, 空字符串视为合法(允许不绑定)。
func validEmail(email string) bool {
	if email == "" {
		return true
	}
	return len(email) <= 254 && reEmail.MatchString(email)
}

// reAgentID agent_id 白名单: 字母/数字/点/下划线/连字符，1~maxAgentIDLen 位。
var reAgentID = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// validAgentID 校验 agent_id 格式。
func validAgentID(id string) (bool, string) {
	if id == "" {
		return false, "agent_id required"
	}
	if len(id) > maxAgentIDLen {
		return false, "agent_id too long (max 128 characters)"
	}
	if !reAgentID.MatchString(id) {
		return false, "agent_id contains invalid characters (only a-z A-Z 0-9 . _ - allowed)"
	}
	return true, ""
}

// ---- 登录限速 ----
// 两层防护：
//  1. 按 IP 局部计数：5 次/60s 内失败 -> 5 分钟冷却(防单 IP 爆破)
//  2. 按 actor 全局计数：30 次/5min 内失败 -> 10 分钟冷却(防 XFF 绕过后分布式爆破)
//
// 即便攻击者伪造 XFF 让每个请求看似来自不同 IP，全局计数仍会捕获并锁定 admin 账号。
const (
	loginWindow     = 60 * time.Second
	loginMaxFails   = 5
	loginCooldown   = 5 * time.Minute
	loginGlobalMax  = 30
	loginGlobalCool = 10 * time.Minute
	loginGlobalWin  = 5 * time.Minute
)

type loginState struct {
	fails       int
	windowStart time.Time
	cooldownEnd time.Time
}

var (
	loginMu     sync.Mutex
	loginStats  = map[string]*loginState{} // key = IP
	loginGlobal = loginState{}             // 跨 IP 的全局计数，固定针对 admin(actor)
)

// loginAllowed 返回是否允许尝试登录(false 表示处于冷却)。
func loginAllowed(ip string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	st, ok := loginStats[ip]
	if ok && !st.cooldownEnd.IsZero() && time.Now().Before(st.cooldownEnd) {
		return false
	}
	// 全局冷却（即使换 IP 也锁死）
	if !loginGlobal.cooldownEnd.IsZero() && time.Now().Before(loginGlobal.cooldownEnd) {
		return false
	}
	return true
}

// loginFail 记录一次失败尝试，触发冷却则返回剩余秒数（取局部与全局较大者）。
func loginFail(ip string) int {
	loginMu.Lock()
	defer loginMu.Unlock()
	// 局部
	st := loginStats[ip]
	if st == nil || time.Since(st.windowStart) > loginWindow {
		st = &loginState{windowStart: time.Now()}
		loginStats[ip] = st
	}
	st.fails++
	if st.fails >= loginMaxFails {
		st.cooldownEnd = time.Now().Add(loginCooldown)
	}
	// 全局（窗口期>=局部，所以失败时全局窗口多半在生效；过期则重置）
	if time.Since(loginGlobal.windowStart) > loginGlobalWin {
		loginGlobal = loginState{windowStart: time.Now()}
	}
	loginGlobal.fails++
	if loginGlobal.fails >= loginGlobalMax {
		loginGlobal.cooldownEnd = time.Now().Add(loginGlobalCool)
	}
	// 返回较大的冷却剩余秒数
	maxCool := 0
	if !st.cooldownEnd.IsZero() {
		if r := int(time.Until(st.cooldownEnd).Seconds()); r > maxCool {
			maxCool = r
		}
	}
	if !loginGlobal.cooldownEnd.IsZero() {
		if r := int(time.Until(loginGlobal.cooldownEnd).Seconds()); r > maxCool {
			maxCool = r
		}
	}
	return maxCool
}

// loginOK 清空当前 IP 的失败计数。
// 不重置全局计数器: 防止攻击者用自己账号正常登录来重置全局限速,
// 然后利用重置窗口对 admin 账号发起暴力破解。
func loginOK(ip string) {
	loginMu.Lock()
	delete(loginStats, ip)
	loginMu.Unlock()
}

// loginSweep 清理 loginStats 中已过期且不在冷却期的条目, 防止 map 无限增长。
// 应由定时器周期调用。
func loginSweep() {
	loginMu.Lock()
	defer loginMu.Unlock()
	now := time.Now()
	for ip, st := range loginStats {
		// 窗口已过 且 不在冷却期(或冷却已到期) -> 清除
		if now.Sub(st.windowStart) > loginWindow {
			if st.cooldownEnd.IsZero() || now.After(st.cooldownEnd) {
				delete(loginStats, ip)
			}
		}
	}
}

// initLoginSweeper 启动后台 goroutine 周期清理 loginStats 过期条目。
func initLoginSweeper() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			loginSweep()
		}
	}()
}

// AuthCtx 保存已通过鉴权的管理上下文。
type AuthCtx struct {
	Actor string
	IP    string
	Role  string // admin / operator / auditor; 旧 session 无 role 时默认 admin 以兼容
}

// HasRole 返回当前用户是否拥有任一指定角色。
func (ac AuthCtx) HasRole(roles ...string) bool {
	for _, r := range roles {
		if ac.Role == r {
			return true
		}
	}
	return false
}

var loginSweeperOnce sync.Once

// Mux 返回带 API + Web UI 的 mux。允许 query token 访问受 ui.AllowQueryToken 控制。
func (s *Server) Mux(cfg config.ServerConfig) http.Handler {
	loginSweeperOnce.Do(initLoginSweeper)
	m := http.NewServeMux()
	m.HandleFunc("/agent", s.AgentWS)
	m.HandleFunc("/ui/events", s.UIEventsGuard(cfg))
	m.Handle("/static/", staticHandler())
	m.HandleFunc("/healthz", s.handleHealthz)
	if cfg.Metrics.Enabled {
		m.HandleFunc("/metrics", s.handleMetrics)
	}
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		serveUI(w, r)
	})
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		s.apiGuard(cfg)(http.HandlerFunc(s.apiMux)).ServeHTTP(w, r)
	})
	return securityHeaders(m, cfg)
}

// securityHeaders 给所有响应追加安全头，降低点击劫持/MIME 嗅探/XSS 等风险。
// HSTS 仅在启用 TLS 时下发。
func securityHeaders(next http.Handler, cfg config.ServerConfig) http.Handler {
	csp := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; " +
		"frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-XSS-Protection", "0")
		if cfg.TLS.Cert != "" && cfg.TLS.Key != "" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// healthzStatus 是 /healthz 响应结构。
type healthzStatus struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	AgentsOnline     int    `json:"agents_online"`
	AgentsRegistered int    `json:"agents_registered"`
	DBOK             bool   `json:"db_ok"`
}

// handleHealthz 返回服务健康状态, 供负载均衡/容器编排探活。
// 始终返回 200 (即使 DB 异常也返回 200 但 db_ok=false),
// 避免探活失败导致误重启; 监控系统可依据 db_ok 字段告警。
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	st := healthzStatus{
		Status:       "ok",
		Version:      version.String(),
		AgentsOnline: s.OnlineAgentCount(),
		DBOK:         true,
	}
	if n, err := s.Store.CountAgents(); err == nil {
		st.AgentsRegistered = n
	}
	if err := s.Store.Ping(); err != nil {
		st.Status = "degraded"
		st.DBOK = false
		log.Printf("[healthz] DB ping 失败: %v", err)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(st)
}

// handleMetrics 以 Prometheus text exposition format 输出观测指标。
// 不引入 prometheus client 依赖, 手动拼装文本, 便于 Prometheus / VictoriaMetrics 直接抓取。
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	emit := func(help, name, typ, val string, labels ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, typ)
		if len(labels) > 0 {
			fmt.Fprintf(&b, "%s{%s} %s\n", name, strings.Join(labels, ","), val)
		} else {
			fmt.Fprintf(&b, "%s %s\n", name, val)
		}
	}

	emit("Gatekeeper build information.", "gatekeeper_build_info", "gauge", "1",
		`version="`+version.String()+`"`)

	emit("Number of agents currently connected via WebSocket.", "gatekeeper_agents_online", "gauge", strconv.Itoa(s.OnlineAgentCount()))

	if n, err := s.Store.CountAgents(); err == nil {
		emit("Total number of registered agents.", "gatekeeper_agents_registered", "gauge", strconv.Itoa(n))
	}
	emit("Number of commands pending agent acknowledgment.", "gatekeeper_cmds_pending", "gauge", strconv.Itoa(s.PendingCmdCount()))

	if n, err := s.Store.CountCmds(); err == nil {
		emit("Total number of commands historically dispatched.", "gatekeeper_cmds_total", "gauge", strconv.Itoa(n))
	}
	if n, err := s.Store.CountAudit(); err == nil {
		emit("Total number of audit log entries.", "gatekeeper_audit_events_total", "gauge", strconv.Itoa(n))
	}
	if n, err := s.Store.CountShellRules(); err == nil {
		emit("Total number of shell allow/deny rules.", "gatekeeper_shell_rules_total", "gauge", strconv.Itoa(n))
	}
	if n, err := s.Store.CountUsers(); err == nil {
		emit("Total number of UI users.", "gatekeeper_users_total", "gauge", strconv.Itoa(n))
	}
	if n, err := s.Store.CountAdmins(); err == nil {
		emit("Total number of admin users.", "gatekeeper_admins_total", "gauge", strconv.Itoa(n))
	}
	if n, err := s.Store.TokenCount(); err == nil {
		emit("Total number of agent registration tokens.", "gatekeeper_tokens_total", "gauge", strconv.Itoa(n))
	}
	if n, err := s.Store.CountAccountScans(); err == nil {
		emit("Total number of account scan records.", "gatekeeper_account_scans_total", "gauge", strconv.Itoa(n))
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(b.String()))
}

// apiGuard 包装 API 处理器，校验管理会话；同时解析 actor/ip 并注入 context。
func (s *Server) apiGuard(cfg config.ServerConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 限制请求体大小为 1MB，防止大请求耗尽内存
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			ac, ok := s.authCheck(w, r, cfg)
			if !ok {
				return
			}
			r = withActor(r, ac)
			next.ServeHTTP(w, r)
		})
	}
}

// UIEventsGuard 给 /ui/events 做鉴权（WS 升级前无法带 Authorization 头时支持 query）。
func (s *Server) UIEventsGuard(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.authCheck(w, r, cfg); !ok {
			return
		}
		s.EventsWS(w, r)
	}
}

// authCheck 校验会话 token，返回 actor 信息。兼容旧 query token。
// query ?t=<token> 仅对 /ui/events (WebSocket 端点) 开放, 因为浏览器 WebSocket API 无法设置 Authorization 头。
// 对 /api/* REST 端点只接受 Authorization 头, 避免 token 出现在 URL/日志/Referer 中泄露。
func (s *Server) authCheck(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) (AuthCtx, bool) {
	get := func(name string) string { return r.Header.Get(name) }
	// 1) Authorization: Bearer <session>
	if a := get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		tok := strings.TrimPrefix(a, "Bearer ")
		if actor, role, ok := s.checkSession(tok); ok {
			return AuthCtx{Actor: actor, Role: role, IP: s.clientIP(r)}, true
		}
	}
	// 2) query ?t=<token> 仅限 WebSocket 端点 /ui/events
	if r.URL.Path == "/ui/events" {
		if q := r.URL.Query().Get("t"); q != "" {
			if actor, role, ok := s.checkSession(q); ok {
				return AuthCtx{Actor: actor, Role: role, IP: s.clientIP(r)}, true
			}
			if cfg.UI.AllowQueryToken && q == cfg.UI.AdminPassword {
				return AuthCtx{Actor: "admin", Role: "admin", IP: s.clientIP(r)}, true
			}
		}
	}
	// 3) 特例：登录接口必须放行
	if r.URL.Path == "/api/login" {
		return AuthCtx{Actor: "anonymous", Role: "anonymous", IP: s.clientIP(r)}, true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="gatekeeper"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return AuthCtx{}, false
}

// checkSession 校验会话 token 是否有效, 返回 (username, role, ok)。
// session 值格式: username|role|expiresUnix
// token 在入库前已做 sha256 哈希, 此处用哈希值查库, 数据库中不留 token 原文。
// 校验通过后额外检查用户当前状态: 若用户已被禁用或删除, 会话立即失效。
func (s *Server) checkSession(tok string) (string, string, bool) {
	h := HashSession(tok)
	v, err := s.Store.SettingGet("session:" + h)
	if err != nil || v == "" {
		return "", "", false
	}
	parts := strings.SplitN(v, "|", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	role := "admin" // 兼容老 session "actor|expires" 两段格式
	if len(parts) == 3 {
		role = parts[1]
	}
	ts, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return "", "", false
	}
	if time.Now().Unix() > ts {
		_ = s.Store.SettingSet("session:"+h, "")
		return "", "", false
	}
	// 检查用户当前状态: 被禁用或已删除则会话失效
	if u, _, _ := s.Store.GetUser(parts[0]); u == nil || u.Disabled {
		_ = s.Store.SettingSet("session:"+h, "")
		return "", "", false
	}
	return parts[0], role, true
}

func withActor(r *http.Request, ac AuthCtx) *http.Request {
	return r.WithContext(setCtx(r.Context(), ac))
}

func actorOf(r *http.Request) AuthCtx {
	if v, ok := getCtx(r.Context()); ok {
		return v
	}
	return AuthCtx{Actor: "anonymous", IP: remoteAddrIP(r)}
}

// remoteAddrIP 直接从 RemoteAddr 取 IP，不解析任何 XFF（fallback 用，安全默认）。
func remoteAddrIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := indexOfByte(host, ':'); i > 0 {
		return host[:i]
	}
	return host
}

// ---- API 路由 ----

func (s *Server) apiMux(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/login" && r.Method == http.MethodPost:
		s.handleLogin(w, r)
	case path == "/api/logout" && r.Method == http.MethodPost:
		s.handleLogout(w, r)
	case path == "/api/me" && r.Method == http.MethodGet:
		ac := actorOf(r)
		respond(w, map[string]string{"actor": ac.Actor, "role": ac.Role, "version": version.String()}, nil)
	case path == "/api/agents" && r.Method == http.MethodGet:
		page := atoiDefault(r.URL.Query().Get("page"), 1)
		pageSize := atoiDefault(r.URL.Query().Get("page_size"), 10)
		q := r.URL.Query().Get("q")
		agents, total, err := s.Store.ListAgentsPaged(page, pageSize, q)
		// 叠加 live session 在线真值: DB online 列由 sweeper 维护(15s 滞后),
		// 此处以 server 内存中的活跃会话为准, 给前端最实时的在线状态。
		if err == nil {
			for i := range agents {
				if agents[i].Online {
					// DB 标在线但 live session 不在 -> 实际已失联, 修正为 false
					if !s.IsOnline(agents[i].AgentID) {
						agents[i].Online = false
					}
				}
				// live session 在 -> 一定在线, 不论 DB 怎么标
				if s.IsOnline(agents[i].AgentID) {
					agents[i].Online = true
				}
			}
		}
		respond(w, pagedResult(agents, total, page, pageSize), err)
	case path == "/api/agents" && r.Method == http.MethodPost:
		s.handleAgentUpdate(w, r)
	case path == "/api/agents" && r.Method == http.MethodDelete:
		// 删除 agent：?id=xxx  (硬删除, 仅允许离线 agent; 仅 admin)
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleAgentDelete(w, r)
	case strings.HasPrefix(path, "/api/agent/") && r.Method == http.MethodGet:
		s.handleAgentGet(w, r)
	case strings.HasPrefix(path, "/api/agent/") && r.Method == http.MethodPost:
		s.handleAgentUpdateID(w, r)
	case path == "/api/commands" && r.Method == http.MethodGet:
		agentID := r.URL.Query().Get("agent_id")
		actionFilter := r.URL.Query().Get("action")
		page := atoiDefault(r.URL.Query().Get("page"), 1)
		pageSize := atoiDefault(r.URL.Query().Get("page_size"), 10)
		cmds, total, err := s.Store.ListCmdsPaged(page, pageSize, agentID, actionFilter)
		respond(w, pagedResult(cmds, total, page, pageSize), err)
	case path == "/api/tokens" && r.Method == http.MethodGet:
		page := atoiDefault(r.URL.Query().Get("page"), 1)
		pageSize := atoiDefault(r.URL.Query().Get("page_size"), 10)
		toks, total, err := s.Store.ListTokensPaged(page, pageSize)
		// 用 agent_id 反查 hostname, 供 UI 直接显示绑定主机名
		for i := range toks {
			if toks[i].BoundAgentID != "" {
				toks[i].BoundHostname = s.Store.HostnameOf(toks[i].BoundAgentID)
			}
		}
		respond(w, pagedResult(toks, total, page, pageSize), err)
	case path == "/api/tokens" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleTokenCreate(w, r)
	case path == "/api/tokens/revoke" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleTokenRevoke(w, r)
	case path == "/api/tokens/delete" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleTokenDelete(w, r)
	case path == "/api/tokens/bind" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleTokenBind(w, r)
	case path == "/api/dispatch" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin", "operator") {
			forbidden(w, r)
			return
		}
		s.handleDispatch(w, r)
	case path == "/api/dispatch_batch" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin", "operator") {
			forbidden(w, r)
			return
		}
		s.handleDispatchBatch(w, r)
	case path == "/api/audit" && r.Method == http.MethodGet:
		f := AuditFilter{
			Page:     atoiDefault(r.URL.Query().Get("page"), 1),
			PageSize: atoiDefault(r.URL.Query().Get("page_size"), 10),
		}
		f.Actor = r.URL.Query().Get("actor")
		f.Action = r.URL.Query().Get("action")
		f.Target = r.URL.Query().Get("target")
		f.Q = r.URL.Query().Get("q")
		f.From = int64(atoiDefault(r.URL.Query().Get("from"), 0))
		f.To = int64(atoiDefault(r.URL.Query().Get("to"), 0))
		audit, total, err := s.Store.ListAuditPaged(f)
		respond(w, pagedResult(audit, total, f.Page, f.PageSize), err)
	case path == "/api/audit/actions" && r.Method == http.MethodGet:
		actions, err := s.Store.AuditActions()
		respond(w, actions, err)
	case strings.HasPrefix(path, "/api/command/"):
		s.handleCmdStatus(w, r)
	case path == "/api/settings" && r.Method == http.MethodGet:
		// 运行时配置: 告警开关、webhook、邮件收件人、预警阈值等, 存 settings 表, 可 Web 端热更。
		getStr := func(k, def string) string {
			v, _ := s.Store.SettingGet(k)
			if v == "" {
				return def
			}
			return v
		}
		getInt := func(k string, def int) int {
			v, _ := s.Store.SettingGet(k)
			if v == "" {
				return def
			}
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
			return def
		}
		adminEmails, _ := s.Store.ListAdminEmails()
		respond(w, map[string]any{
			"allow_query_token": false,
			"alerts": map[string]any{
				"enabled":               getStr("alert_enabled", "false") == "true",
				"webhook_url":           getStr("alert_webhook_url", ""),
				"email_to":              getStr("alert_email_to", ""),
				"account_expired_enabled": getStr("alert_account_expired_enabled", "false") == "true",
				"warn_days":             getInt("alert_warn_days", 7),
				"admin_emails":          adminEmails,
			},
		}, nil)
	case path == "/api/settings" && r.Method == http.MethodPost:
		ac := actorOf(r)
		if !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		var body struct {
			Alerts struct {
				Enabled                 bool   `json:"enabled"`
				WebhookURL              string `json:"webhook_url"`
				EmailTo                 string `json:"email_to"`
				AccountExpiredEnabled   bool   `json:"account_expired_enabled"`
				WarnDays                int    `json:"warn_days"`
			} `json:"alerts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			badRequest(w, "invalid json")
			return
		}
		boolStr := func(b bool) string {
			if b {
				return "true"
			}
			return "false"
		}
		_ = s.Store.SettingSet("alert_enabled", boolStr(body.Alerts.Enabled))
		_ = s.Store.SettingSet("alert_webhook_url", body.Alerts.WebhookURL)
		_ = s.Store.SettingSet("alert_email_to", body.Alerts.EmailTo)
		_ = s.Store.SettingSet("alert_account_expired_enabled", boolStr(body.Alerts.AccountExpiredEnabled))
		_ = s.Store.SettingSet("alert_warn_days", strconv.Itoa(body.Alerts.WarnDays))
		s.Store.Audit(ac.Actor, "settings_update", "alerts",
			fmt.Sprintf("enabled=%v warn_days=%d email_to=%s", body.Alerts.Enabled, body.Alerts.WarnDays, body.Alerts.EmailTo), ac.IP)
		respond(w, map[string]string{"status": "ok"}, nil)
	case path == "/api/settings/retention" && r.Method == http.MethodGet:
		min := s.retentionMinDays
		v, _ := s.Store.SettingGet("audit_retention_days")
		days := min
		if v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= min {
				days = n
			}
		}
		respond(w, map[string]any{
			"min_days":     min, // YAML 下限, UI 不允许低于
			"current_days": days,
		}, nil)
	case path == "/api/settings/retention" && r.Method == http.MethodPost:
		ac := actorOf(r)
		if !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		var body struct {
			Days int `json:"days"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		min := s.retentionMinDays
		if body.Days < min {
			jsonError(w, fmt.Sprintf("retention days must >= %d (yaml floor)", min), http.StatusBadRequest)
			return
		}
		_ = s.Store.SettingSet("audit_retention_days", strconv.Itoa(body.Days))
		s.Store.Audit(ac.Actor, "retention_set", "", fmt.Sprintf("days=%d", body.Days), ac.IP)
		respond(w, map[string]int{"days": body.Days}, nil)
	case path == "/api/users" && r.Method == http.MethodGet:
		s.handleUsersList(w, r)
	case path == "/api/users" && r.Method == http.MethodPost:
		s.handleUserCreate(w, r)
	case path == "/api/users/password" && r.Method == http.MethodPost:
		s.handleUserPassword(w, r)
	case path == "/api/users/email" && r.Method == http.MethodPost:
		s.handleUserEmail(w, r)
	case path == "/api/users/disable" && r.Method == http.MethodPost:
		s.handleUserDisable(w, r)
	case path == "/api/users/delete" && r.Method == http.MethodPost:
		s.handleUserDelete(w, r)
	case path == "/api/alerts/test" && r.Method == http.MethodPost:
		s.handleAlertTest(w, r)
	case path == "/api/shell/policy" && r.Method == http.MethodGet:
		s.handleShellPolicyGet(w, r)
	case path == "/api/shell/policy" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleShellPolicySet(w, r)
	case path == "/api/shell/rules" && r.Method == http.MethodGet:
		s.handleShellRulesList(w, r)
	case path == "/api/shell/rules" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleShellRuleAdd(w, r)
	case path == "/api/shell/rules/update" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleShellRuleUpdate(w, r)
	case path == "/api/shell/rules/delete" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin") {
			forbidden(w, r)
			return
		}
		s.handleShellRuleDelete(w, r)

	// ---- 账户巡检 API ----
	case path == "/api/account_scans" && r.Method == http.MethodGet:
		agentID := r.URL.Query().Get("agent_id")
		statusFilter := r.URL.Query().Get("status")
		scans, err := s.Store.ListAccountScans(agentID, statusFilter)
		respond(w, scans, err)
	case path == "/api/account_scans/summary" && r.Method == http.MethodGet:
		sum, err := s.Store.GetAccountScanSummary()
		respond(w, sum, err)
	case path == "/api/account_scans/trigger" && r.Method == http.MethodPost:
		if ac := actorOf(r); !ac.HasRole("admin", "operator") {
			forbidden(w, r)
			return
		}
		s.handleScanTrigger(w, r)

	default:
		http.NotFound(w, r)
	}
}

// pagedResult 包装统一分页响应: {items, total, page, page_size, pages}
func pagedResult(items any, total, page, pageSize int) map[string]any {
	if pageSize <= 0 {
		pageSize = 200
	}
	pages := 0
	if pageSize > 0 {
		pages = (total + pageSize - 1) / pageSize
	}
	return map[string]any{
		"items":     items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"pages":     pages,
	}
}

// forbidden 返回 403 JSON 错误, 用于 RBAC 校验失败。
func forbidden(w http.ResponseWriter, _ *http.Request) {
	jsonError(w, "forbidden: insufficient role", http.StatusForbidden)
}

// ---- 用户管理 handlers ----

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	ac := actorOf(r)
	if !ac.HasRole("admin") {
		forbidden(w, r)
		return
	}
	users, err := s.Store.ListUsers()
	respond(w, users, err)
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	ac := actorOf(r)
	if !ac.HasRole("admin") {
		forbidden(w, r)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Username == "" || body.Password == "" {
		jsonError(w, "username and password required", http.StatusBadRequest)
		return
	}
	if ok, msg := validUsername(body.Username); !ok {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	if ok, msg := ValidatePassword(body.Password); !ok {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	if body.Email != "" && !validEmail(body.Email) {
		jsonError(w, "invalid email format", http.StatusBadRequest)
		return
	}
	if body.Role == "" {
		body.Role = "operator"
	}
	if body.Role != "admin" && body.Role != "operator" && body.Role != "auditor" {
		jsonError(w, "role must be admin/operator/auditor", http.StatusBadRequest)
		return
	}
	h, err := HashPassword(body.Password)
	if err != nil {
		jsonError(w, "hash error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.CreateUser(body.Username, h, body.Role, body.Email); err != nil {
		jsonError(w, "create failed (username may already exist)", http.StatusConflict)
		return
	}
	s.Store.Audit(ac.Actor, "user_create", body.Username, fmt.Sprintf("role=%s email=%s", body.Role, body.Email), ac.IP)
	respond(w, map[string]string{"username": body.Username, "role": body.Role, "email": body.Email}, nil)
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	ac := actorOf(r)
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// 自助改密 OR admin 改任意; 但 auditor 不允许改别人
	if ac.Actor != body.Username && !ac.HasRole("admin") {
		forbidden(w, r)
		return
	}
	if body.Username == "" || body.Password == "" {
		jsonError(w, "username and password required", http.StatusBadRequest)
		return
	}
	if ok, msg := ValidatePassword(body.Password); !ok {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	h, err := HashPassword(body.Password)
	if err != nil {
		jsonError(w, "hash error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.SetUserPassword(body.Username, h); err != nil {
		respond(w, nil, err)
		return
	}
	// 改密后吊销该用户所有既有会话, 强制重新登录
	s.Store.DeleteSessionsByActor(body.Username)
	s.Store.Audit(ac.Actor, "user_password_change", body.Username, "", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleUserEmail 修改用户绑定邮箱。admin 可改任意用户, 其他角色只能改自己。
func (s *Server) handleUserEmail(w http.ResponseWriter, r *http.Request) {
	ac := actorOf(r)
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// 自助改邮箱 OR admin 改任意
	if ac.Actor != body.Username && !ac.HasRole("admin") {
		forbidden(w, r)
		return
	}
	if body.Username == "" {
		jsonError(w, "username required", http.StatusBadRequest)
		return
	}
	if !validEmail(body.Email) {
		jsonError(w, "invalid email format", http.StatusBadRequest)
		return
	}
	if err := s.Store.UpdateUserEmail(body.Username, body.Email); err != nil {
		respond(w, nil, err)
		return
	}
	s.Store.Audit(ac.Actor, "user_email_change", body.Username, "email="+body.Email, ac.IP)
	respond(w, map[string]string{"status": "ok", "email": body.Email}, nil)
}

func (s *Server) handleUserDisable(w http.ResponseWriter, r *http.Request) {
	ac := actorOf(r)
	if !ac.HasRole("admin") {
		forbidden(w, r)
		return
	}
	var body struct {
		Username string `json:"username"`
		Disabled bool   `json:"disabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Username == "" {
		jsonError(w, "username required", http.StatusBadRequest)
		return
	}
	// 防止禁用最后一个 admin
	if body.Disabled && body.Username == ac.Actor {
		if n, _ := s.Store.CountAdmins(); n <= 1 {
			jsonError(w, "refuse: cannot disable the last admin (yourself)", http.StatusConflict)
			return
		}
	}
	if err := s.Store.SetUserDisabled(body.Username, body.Disabled); err != nil {
		respond(w, nil, err)
		return
	}
	// 禁用用户时即时吊销其所有会话; 启用时无需操作
	if body.Disabled {
		s.Store.DeleteSessionsByActor(body.Username)
	}
	s.Store.Audit(ac.Actor, "user_disable", body.Username, fmt.Sprintf("disabled=%v", body.Disabled), ac.IP)
	respond(w, map[string]bool{"disabled": body.Disabled}, nil)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	ac := actorOf(r)
	if !ac.HasRole("admin") {
		forbidden(w, r)
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Username == "" {
		jsonError(w, "username required", http.StatusBadRequest)
		return
	}
	if body.Username == ac.Actor {
		jsonError(w, "refuse: cannot delete yourself", http.StatusConflict)
		return
	}
	u, _, _ := s.Store.GetUser(body.Username)
	if u != nil && u.Role == "admin" {
		if n, _ := s.Store.CountAdmins(); n <= 1 {
			jsonError(w, "refuse: cannot delete the last admin", http.StatusConflict)
			return
		}
	}
	if err := s.Store.DeleteUser(body.Username); err != nil {
		respond(w, nil, err)
		return
	}
	// 删除用户后吊销其所有会话
	s.Store.DeleteSessionsByActor(body.Username)
	s.Store.Audit(ac.Actor, "user_delete", body.Username, "hard delete", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleAlertTest 手动触发一次告警测试, 用于验证 webhook 配置是否生效。
// 仅 admin 可调。请求体: {"agent_id":"xxx"} (可选, 缺省取第一个 agent)。
func (s *Server) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	ac := actorOf(r)
	if !ac.HasRole("admin") {
		forbidden(w, r)
		return
	}
	if s.alert == nil {
		jsonError(w, "告警未启用 (配置 alerts.enabled=false 或 webhook_url 为空)", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		AgentID string `json:"agent_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.AgentID == "" {
		// 取第一个 agent
		ags, _, _ := s.Store.ListAgentsPaged(1, 1, "")
		if len(ags) == 0 {
			jsonError(w, "没有任何已注册 agent, 无法测试", http.StatusBadRequest)
			return
		}
		body.AgentID = ags[0].AgentID
	}
	if err := s.alert.ForceAlert(body.AgentID); err != nil {
		jsonError(w, "告警发送失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.Store.Audit(ac.Actor, "alert_test", body.AgentID, "手动触发 webhook 测试", ac.IP)
	respond(w, map[string]string{"status": "sent", "agent_id": body.AgentID}, nil)
}

// ---- Shell 策略与规则管理 handlers ----

// handleShellPolicyGet 返回当前 shell 策略配置 (启用状态/超时/输出截断/匹配模式)。
func (s *Server) handleShellPolicyGet(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]any{
		"enabled":    s.IsShellEnabled(),
		"timeout":    int(s.ShellTimeout() / time.Second),
		"max_output": s.ShellMaxOutput(),
		"match_mode": s.ShellMatchModeStr(),
	}, nil)
}

// handleShellPolicySet 更新 shell 策略配置, 同时持久化到 DB 并刷新内存。
func (s *Server) handleShellPolicySet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled   bool   `json:"enabled"`
		Timeout   int    `json:"timeout"`
		MaxOutput int    `json:"max_output"`
		MatchMode string `json:"match_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, "请求体格式错误: "+err.Error())
		return
	}
	if body.Timeout < 1 || body.Timeout > 600 {
		badRequest(w, "超时必须在 1~600 秒之间")
		return
	}
	if body.MaxOutput < 1024 || body.MaxOutput > 1048576 {
		badRequest(w, "输出截断必须在 1024~1048576 字节之间")
		return
	}
	matchMode := validShellMatchMode(body.MatchMode)
	// 持久化到 DB settings (重启后仍生效)
	enStr := "0"
	if body.Enabled {
		enStr = "1"
	}
	if err := s.Store.SettingSet("shell_enabled", enStr); err != nil {
		respond(w, nil, fmt.Errorf("persist shell_enabled: %w", err))
		return
	}
	if err := s.Store.SettingSet("shell_timeout", strconv.Itoa(body.Timeout)); err != nil {
		respond(w, nil, fmt.Errorf("persist shell_timeout: %w", err))
		return
	}
	if err := s.Store.SettingSet("shell_max_output", strconv.Itoa(body.MaxOutput)); err != nil {
		respond(w, nil, fmt.Errorf("persist shell_max_output: %w", err))
		return
	}
	if err := s.Store.SettingSet("shell_match_mode", matchMode); err != nil {
		respond(w, nil, fmt.Errorf("persist shell_match_mode: %w", err))
		return
	}
	// 刷新内存中的策略状态
	s.SetShellConfig(body.Enabled, time.Duration(body.Timeout)*time.Second, body.MaxOutput, matchMode)
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "shell_policy_set", "", fmt.Sprintf("enabled=%v timeout=%ds max_output=%d match_mode=%s", body.Enabled, body.Timeout, body.MaxOutput, matchMode), ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleShellRulesList 返回全部 shell 规则 (黑白名单), 供 UI 分组渲染。
func (s *Server) handleShellRulesList(w http.ResponseWriter, r *http.Request) {
	rules, err := s.Store.ListShellRules("", false)
	respond(w, rules, err)
}

// handleShellRuleAdd 新增一条 shell 规则。
func (s *Server) handleShellRuleAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type    string `json:"type"`
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, "请求体格式错误: "+err.Error())
		return
	}
	if body.Type != "whitelist" && body.Type != "blacklist" {
		badRequest(w, "类型必须为 whitelist 或 blacklist")
		return
	}
	if strings.TrimSpace(body.Pattern) == "" {
		badRequest(w, "模式不能为空")
		return
	}
	if len(body.Pattern) > maxShellPatLen {
		badRequest(w, fmt.Sprintf("模式过长 (最多 %d 字符)", maxShellPatLen))
		return
	}
	if len(body.Note) > maxTokenNoteLen {
		badRequest(w, fmt.Sprintf("备注过长 (最多 %d 字符)", maxTokenNoteLen))
		return
	}
	id, err := s.Store.AddShellRule(body.Type, body.Pattern, body.Note)
	if err != nil {
		respond(w, nil, fmt.Errorf("add rule: %w", err))
		return
	}
	s.InvalidateShellRules()
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "shell_rule_add", strconv.FormatInt(id, 10), fmt.Sprintf("type=%s pattern=%s note=%s", body.Type, body.Pattern, body.Note), ac.IP)
	respond(w, map[string]any{"id": id, "status": "ok"}, nil)
}

// handleShellRuleUpdate 更新 shell 规则; pattern 为空时保留原值 (支持仅切换 enabled)。
func (s *Server) handleShellRuleUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      int64  `json:"id"`
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, "请求体格式错误: "+err.Error())
		return
	}
	if body.ID <= 0 {
		badRequest(w, "id 不能为空")
		return
	}
	// 仅切换 enabled 时 (pattern 为空), 保留原 pattern/note
	pattern, note := body.Pattern, body.Note
	if strings.TrimSpace(pattern) == "" {
		all, _ := s.Store.ListShellRules("", false)
		for _, rr := range all {
			if rr.ID == body.ID {
				pattern = rr.Pattern
				note = rr.Note
				break
			}
		}
	}
	if len(pattern) > maxShellPatLen {
		badRequest(w, fmt.Sprintf("模式过长 (最多 %d 字符)", maxShellPatLen))
		return
	}
	if len(note) > maxTokenNoteLen {
		badRequest(w, fmt.Sprintf("备注过长 (最多 %d 字符)", maxTokenNoteLen))
		return
	}
	if err := s.Store.UpdateShellRule(body.ID, pattern, note, body.Enabled); err != nil {
		respond(w, nil, fmt.Errorf("update rule: %w", err))
		return
	}
	s.InvalidateShellRules()
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "shell_rule_update", strconv.FormatInt(body.ID, 10), fmt.Sprintf("enabled=%v pattern=%s", body.Enabled, pattern), ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleShellRuleDelete 硬删除一条 shell 规则。
func (s *Server) handleShellRuleDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, "请求体格式错误: "+err.Error())
		return
	}
	if body.ID <= 0 {
		badRequest(w, "id 不能为空")
		return
	}
	if err := s.Store.DeleteShellRule(body.ID); err != nil {
		respond(w, nil, fmt.Errorf("delete rule: %w", err))
		return
	}
	s.InvalidateShellRules()
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "shell_rule_delete", strconv.FormatInt(body.ID, 10), "", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleScanTrigger 手动触发对指定 agent 的账户巡检扫描。
func (s *Server) handleScanTrigger(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID string `json:"agent_id"` // 空=扫描所有在线 agent
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ac := actorOf(r)
	accepted := s.TriggerAccountScan(body.AgentID)
	s.Store.Audit(ac.Actor, "scan_trigger", body.AgentID, fmt.Sprintf("accepted=%d", accepted), ac.IP)
	respond(w, map[string]int{"accepted": accepted}, nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !loginAllowed(ip) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many failed attempts, try later"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// 兼容旧客户端: 身份缺省时回退为 admin
	if body.Username == "" {
		body.Username = "admin"
	}
	// 用户名格式校验: 防止含 | % 等特殊字符的用户名破坏 session 解析或 LIKE 匹配。
	// 校验失败时返回与用户不存在相同的响应，避免用户名枚举。
	if ok, _ := validUsername(body.Username); !ok {
		cool := loginFail(ip)
		s.Store.Audit(body.Username, "login_failed", "", "reason=invalid_username_format ip="+ip, ip)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if cool > 0 {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials", "cooldown": intToStr(int64(cool))})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		}
		return
	}
	u, hash, err := s.Store.GetUser(body.Username)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if u == nil || hash == "" || u.Disabled {
		cool := loginFail(ip)
		s.Store.Audit(body.Username, "login_failed", "", "reason=user_not_found_or_disabled ip="+ip, ip)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if cool > 0 {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials", "cooldown": intToStr(int64(cool))})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		}
		return
	}
	if !CheckPassword(hash, body.Password) {
		cool := loginFail(ip)
		s.Store.Audit(body.Username, "login_failed", "", "ip="+ip, ip)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if cool > 0 {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials", "cooldown": intToStr(int64(cool))})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		}
		return
	}
	loginOK(ip)
	tok := genSession()
	expires := time.Now().Add(s.sessionTTL).Unix()
	_ = s.Store.SettingSet("session:"+HashSession(tok), body.Username+"|"+u.Role+"|"+intToStr(expires))
	s.Store.Audit(body.Username, "login", "", "ip="+ip, ip)
	respond(w, map[string]string{"token": tok, "actor": body.Username, "role": u.Role, "expires_at": intToStr(expires)}, nil)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	a := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(a, "Bearer ")
	_ = s.Store.SettingSet("session:"+HashSession(tok), "")
	respond(w, map[string]string{"status": "ok"}, nil)
}

func (s *Server) handleAgentGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/agent/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	a, err := s.Store.GetAgent(id)
	respond(w, a, err)
}

func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID string   `json:"agent_id"`
		Tags    []string `json:"tags"`
		Notes   *string  `json:"notes"` // 指针: nil=不改, ""=清空
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.AgentID == "" {
		jsonError(w, "agent_id required", http.StatusBadRequest)
		return
	}
	if len(body.AgentID) > maxAgentIDLen {
		jsonError(w, fmt.Sprintf("agent_id too long (max %d characters)", maxAgentIDLen), http.StatusBadRequest)
		return
	}
	if len(body.Tags) > 20 {
		jsonError(w, "too many tags (max 20)", http.StatusBadRequest)
		return
	}
	notesVal := ""
	if body.Notes != nil {
		notesVal = *body.Notes
		if len(notesVal) > maxTokenNoteLen {
			jsonError(w, fmt.Sprintf("notes too long (max %d characters)", maxTokenNoteLen), http.StatusBadRequest)
			return
		}
	}
	ac := actorOf(r)
	if body.Tags != nil {
		_ = s.Store.SetAgentTags(body.AgentID, body.Tags)
	}
	if body.Notes != nil {
		_ = s.Store.SetAgentNotes(body.AgentID, *body.Notes)
	}
	s.Store.Audit(ac.Actor, "agent_update", body.AgentID, fmt.Sprintf("tags=%v notes=%s", body.Tags, notesVal), ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleAgentUpdateID 处理 /api/agent/<id> POST（同 /api/agents）。
func (s *Server) handleAgentUpdateID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/agent/")
	var body struct {
		Tags  []string `json:"tags"`
		Notes *string  `json:"notes"` // 指针: nil=不改, ""=清空
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if len(body.Tags) > 20 {
		jsonError(w, "too many tags (max 20)", http.StatusBadRequest)
		return
	}
	notesVal := ""
	if body.Notes != nil {
		notesVal = *body.Notes
		if len(notesVal) > maxTokenNoteLen {
			jsonError(w, fmt.Sprintf("notes too long (max %d characters)", maxTokenNoteLen), http.StatusBadRequest)
			return
		}
	}
	ac := actorOf(r)
	if body.Tags != nil {
		_ = s.Store.SetAgentTags(id, body.Tags)
	}
	if body.Notes != nil {
		_ = s.Store.SetAgentNotes(id, *body.Notes)
	}
	s.Store.Audit(ac.Actor, "agent_update", id, fmt.Sprintf("tags=%v notes=%s", body.Tags, notesVal), ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

func (s *Server) handleAgentDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	// 安全: 先踢活会话, 再尝试硬删除(仅允许离线 agent 被删, 防误删活主机)
	s.KickSession(id)
	del, err := s.Store.DeleteAgent(id)
	if err != nil {
		// 多半是 agent 仍标记 online
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	if !del {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "agent_delete", id, "hard delete (commands purged)", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Note        string `json:"note"`
		BindAgentID string `json:"bind_agent_id"` // 可选: 创建即绑定到指定 agent_id
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if len(body.Note) > maxTokenNoteLen {
		jsonError(w, fmt.Sprintf("note too long (max %d characters)", maxTokenNoteLen), http.StatusBadRequest)
		return
	}
	if len(body.BindAgentID) > maxAgentIDLen {
		jsonError(w, fmt.Sprintf("bind_agent_id too long (max %d characters)", maxAgentIDLen), http.StatusBadRequest)
		return
	}
	tok := genToken()
	if err := s.Store.EnsureToken(tok, body.Note, body.BindAgentID); err != nil {
		respond(w, nil, err)
		return
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "token_create", TokenPrefix(tok), "note="+body.Note+" bind="+body.BindAgentID, ac.IP)
	respond(w, map[string]string{"token": tok, "note": body.Note, "bound_agent_id": body.BindAgentID}, nil)
}

// handleTokenBind POST /api/tokens/bind {token, agent_id} 给已存在的 token 设置绑定。
func (s *Server) handleTokenBind(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token   string `json:"token"`
		AgentID string `json:"agent_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Token == "" || body.AgentID == "" {
		jsonError(w, "token and agent_id required", http.StatusBadRequest)
		return
	}
	if len(body.AgentID) > maxAgentIDLen {
		jsonError(w, fmt.Sprintf("agent_id too long (max %d characters)", maxAgentIDLen), http.StatusBadRequest)
		return
	}
	if err := s.Store.BindToken(body.Token, body.AgentID); err != nil {
		respond(w, nil, err)
		return
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "token_bind", TokenPrefix(body.Token), "agent_id="+body.AgentID, ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// 先撤销(DB + agent 置 offline), 再踢活会话: 防止 agent 在已撤销后仍能接收下发指令。
	if err := s.Store.RevokeToken(body.Token); err != nil {
		respond(w, nil, err)
		return
	}
	// 通过 token 哈希反查绑定的 agent_id, 立即关闭其活 WebSocket 会话
	h := body.Token
	if len(h) != 64 {
		h = HashToken(body.Token)
	}
	if bound := s.Store.BoundAgentIDForToken(h); bound != "" {
		s.KickSession(bound)
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "token_revoke", TokenPrefix(body.Token), "", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleTokenDelete 硬删除一个已 revoked 的 token。
func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"` // 原始 token 或哈希都支持
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Token == "" {
		jsonError(w, "token required", http.StatusBadRequest)
		return
	}
	if err := s.Store.DeleteToken(body.Token); err != nil {
		// 多半是 token 未撤销
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "token_delete", TokenPrefix(body.Token), "hard delete", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

type dispatchReq struct {
	AgentID string            `json:"agent_id"`
	Action  string            `json:"action"`
	User    string            `json:"user"`
	Params  map[string]string `json:"params"`
}

type batchReq struct {
	AgentIDs []string          `json:"agent_ids"`
	Action   string            `json:"action"`
	User     string            `json:"user"`
	Params   map[string]string `json:"params"`
}

func (s *Server) handleDispatch(w http.ResponseWriter, r *http.Request) {
	var req dispatchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.Action == "" {
		jsonError(w, "agent_id and action required", http.StatusBadRequest)
		return
	}
	if len(req.AgentID) > maxAgentIDLen {
		jsonError(w, fmt.Sprintf("agent_id too long (max %d characters)", maxAgentIDLen), http.StatusBadRequest)
		return
	}
	if req.User == "" {
		req.User = "root"
	}
	if len(req.User) > maxDispatchUser {
		jsonError(w, fmt.Sprintf("user too long (max %d characters)", maxDispatchUser), http.StatusBadRequest)
		return
	}
	if !validAction(req.Action) {
		jsonError(w, "unknown action", http.StatusBadRequest)
		return
	}
	// shell action 需要额外校验: 是否启用 + 黑白名单策略
	if req.Action == proto.ActionShell {
		if !s.shellEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "shell action not enabled"})
			return
		}
		command := req.Params["command"]
		if command == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "command required for shell action"})
			return
		}
		allowed, reason := s.ShellAllowed(command)
		if !allowed {
			ac := actorOf(r)
			s.Store.Audit(ac.Actor, "shell_blocked", req.AgentID, "cmd="+command+" reason="+reason, ac.IP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "command blocked: " + reason})
			return
		}
	}
	// 在线下发：agent 反连会话不存在直接拒绝，避免命令变成无人接收的死信
	if !s.IsOnline(req.AgentID) {
		ac := actorOf(r)
		s.Store.Audit(ac.Actor, "dispatch_rejected", req.AgentID, "reason=agent_offline action="+req.Action, ac.IP)
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "agent offline", "agent_id": req.AgentID})
		return
	}
	ac := actorOf(r)
	c := &StoredCmd{
		ID: genID(), AgentID: req.AgentID, Action: req.Action, User: req.User,
		Params: req.Params, CreatedBy: ac.Actor,
	}
	if err := s.Store.SaveCmd(c); err != nil {
		respond(w, nil, err)
		return
	}
	s.SavePendingCmd(c) // 内存保留未脱敏副本，供重连后重发
	sent := s.Send(c.AgentID, BuildCmd(c))
	status := "sent"
	if !sent {
		status = "pending_offline"
	}
	s.Store.Audit(ac.Actor, "dispatch", c.AgentID, fmt.Sprintf("action=%s user=%s cmd=%s", c.Action, c.User, c.ID), ac.IP)
	respond(w, map[string]string{"id": c.ID, "status": status}, nil)
}

func (s *Server) handleDispatchBatch(w http.ResponseWriter, r *http.Request) {
	var req batchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 || req.Action == "" {
		jsonError(w, "agent_ids and action required", http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) > 100 {
		jsonError(w, "too many agent_ids (max 100)", http.StatusBadRequest)
		return
	}
	if req.User == "" {
		req.User = "root"
	}
	if len(req.User) > maxDispatchUser {
		jsonError(w, fmt.Sprintf("user too long (max %d characters)", maxDispatchUser), http.StatusBadRequest)
		return
	}
	if !validAction(req.Action) {
		jsonError(w, "unknown action", http.StatusBadRequest)
		return
	}
	// shell action 需要额外校验: 是否启用 + 黑白名单策略 (与单发保持一致)
	if req.Action == proto.ActionShell {
		if !s.shellEnabled {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "shell action not enabled"})
			return
		}
		command := req.Params["command"]
		if command == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "command required for shell action"})
			return
		}
		allowed, reason := s.ShellAllowed(command)
		if !allowed {
			ac := actorOf(r)
			s.Store.Audit(ac.Actor, "shell_blocked", strings.Join(req.AgentIDs, ","), "cmd="+command+" reason="+reason, ac.IP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "command blocked: " + reason})
			return
		}
	}
	ac := actorOf(r)
	type oneRes struct {
		AgentID string `json:"agent_id"`
		ID      string `json:"id"`
		Sent    bool   `json:"sent"`
		Reason  string `json:"reason,omitempty"`
	}
	var results []oneRes
	for _, aid := range req.AgentIDs {
		if !s.IsOnline(aid) {
			results = append(results, oneRes{aid, "", false, "agent_offline"})
			continue
		}
		c := &StoredCmd{
			ID: genID(), AgentID: aid, Action: req.Action, User: req.User,
			Params: req.Params, CreatedBy: ac.Actor,
		}
		_ = s.Store.SaveCmd(c)
		s.SavePendingCmd(c)
		sent := s.Send(aid, BuildCmd(c))
		results = append(results, oneRes{aid, c.ID, sent, ""})
	}
	s.Store.Audit(ac.Actor, "dispatch_batch", strings.Join(req.AgentIDs, ","), fmt.Sprintf("action=%s user=%s n=%d", req.Action, req.User, len(req.AgentIDs)), ac.IP)
	respond(w, results, nil)
}

func (s *Server) handleCmdStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/command/")
	c, err := s.Store.GetCmd(id)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if c == nil {
		http.NotFound(w, r)
		return
	}
	respond(w, c, nil)
}

func validAction(a string) bool {
	switch a {
	case proto.ActionChageStatus, proto.ActionExpireExtend, proto.ActionUnlock,
		proto.ActionClearFail, proto.ActionResetPassword, proto.ActionCombo:
		return true
	case proto.ActionShell:
		return true // shell 是否放行由 ShellAllowed 进一步校验
	}
	return false
}

func respond(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("[api] internal error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// badRequest 返回 400 JSON 错误, 用于客户端输入校验失败。
func badRequest(w http.ResponseWriter, msg string) {
	jsonError(w, msg, http.StatusBadRequest)
}

// jsonError 返回 JSON 格式的错误响应，确保前端 r.json() 能正确解析。
// 所有 API handler 应使用此函数替代 http.Error()，以保持前端错误提示一致性。
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func genToken() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func genSession() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func genID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%d", hex.EncodeToString(b), time.Now().UnixNano())
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return def
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<30 {
			return def
		}
	}
	return n
}

func intToStr(n int64) string {
	return fmt.Sprintf("%d", n)
}
