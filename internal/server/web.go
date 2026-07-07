package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/config"
	"gatekeeper/internal/proto"
	"gatekeeper/internal/version"
)

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

// loginOK 清空失败计数。
func loginOK(ip string) {
	loginMu.Lock()
	delete(loginStats, ip)
	loginGlobal = loginState{}
	loginMu.Unlock()
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

// Mux 返回带 API + Web UI 的 mux。允许 query token 访问受 ui.AllowQueryToken 控制。
func (s *Server) Mux(cfg config.ServerConfig) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/agent", s.AgentWS)
	m.HandleFunc("/ui/events", s.UIEventsGuard(cfg))
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
	return m
}

// apiGuard 包装 API 处理器，校验管理会话；同时解析 actor/ip 并注入 context。
func (s *Server) apiGuard(cfg config.ServerConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) authCheck(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) (AuthCtx, bool) {
	get := func(name string) string { return r.Header.Get(name) }
	// 1) Authorization: Bearer <session>
	if a := get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		tok := strings.TrimPrefix(a, "Bearer ")
		if actor, role, ok := s.checkSession(tok); ok {
			return AuthCtx{Actor: actor, Role: role, IP: s.clientIP(r)}, true
		}
	}
	// 2) query ?t=<token>  (AllowQueryToken)
	if q := r.URL.Query().Get("t"); q != "" {
		if actor, role, ok := s.checkSession(q); ok {
			return AuthCtx{Actor: actor, Role: role, IP: s.clientIP(r)}, true
		}
		if cfg.UI.AllowQueryToken && q == cfg.UI.AdminPassword {
			return AuthCtx{Actor: "admin", Role: "admin", IP: s.clientIP(r)}, true
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
func (s *Server) checkSession(tok string) (string, string, bool) {
	v, err := s.Store.SettingGet("session:" + tok)
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
		_ = s.Store.SettingSet("session:"+tok, "")
		return "", "", false
	}
	return parts[0], role, true
}

// 便捷别名
var _ = fmt.Sprintf

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
		page := atoiDefault(r.URL.Query().Get("page"), 1)
		pageSize := atoiDefault(r.URL.Query().Get("page_size"), 10)
		cmds, total, err := s.Store.ListCmdsPaged(page, pageSize, agentID)
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
		respond(w, map[string]any{"allow_query_token": false}, nil)
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
			http.Error(w, fmt.Sprintf("retention days must >= %d (yaml floor)", min), http.StatusBadRequest)
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
	case path == "/api/users/disable" && r.Method == http.MethodPost:
		s.handleUserDisable(w, r)
	case path == "/api/users/delete" && r.Method == http.MethodPost:
		s.handleUserDelete(w, r)
	case path == "/api/alerts/test" && r.Method == http.MethodPost:
		s.handleAlertTest(w, r)
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

// forbidden 返回 403, 用于 RBAC 校验失败。
func forbidden(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "forbidden: insufficient role", http.StatusForbidden)
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
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Username == "" || body.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	if body.Role == "" {
		body.Role = "operator"
	}
	if body.Role != "admin" && body.Role != "operator" && body.Role != "auditor" {
		http.Error(w, "role must be admin/operator/auditor", http.StatusBadRequest)
		return
	}
	h, err := HashPassword(body.Password)
	if err != nil {
		http.Error(w, "hash error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.CreateUser(body.Username, h, body.Role); err != nil {
		http.Error(w, "create failed (username may already exist)", http.StatusConflict)
		return
	}
	s.Store.Audit(ac.Actor, "user_create", body.Username, "role="+body.Role, ac.IP)
	respond(w, map[string]string{"username": body.Username, "role": body.Role}, nil)
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
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	h, err := HashPassword(body.Password)
	if err != nil {
		http.Error(w, "hash error", http.StatusInternalServerError)
		return
	}
	if err := s.Store.SetUserPassword(body.Username, h); err != nil {
		respond(w, nil, err)
		return
	}
	s.Store.Audit(ac.Actor, "user_password_change", body.Username, "", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
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
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	// 防止禁用最后一个 admin
	if body.Disabled && body.Username == ac.Actor {
		if n, _ := s.Store.CountAdmins(); n <= 1 {
			http.Error(w, "refuse: cannot disable the last admin (yourself)", http.StatusConflict)
			return
		}
	}
	if err := s.Store.SetUserDisabled(body.Username, body.Disabled); err != nil {
		respond(w, nil, err)
		return
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
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if body.Username == ac.Actor {
		http.Error(w, "refuse: cannot delete yourself", http.StatusConflict)
		return
	}
	u, _, _ := s.Store.GetUser(body.Username)
	if u != nil && u.Role == "admin" {
		if n, _ := s.Store.CountAdmins(); n <= 1 {
			http.Error(w, "refuse: cannot delete the last admin", http.StatusConflict)
			return
		}
	}
	if err := s.Store.DeleteUser(body.Username); err != nil {
		respond(w, nil, err)
		return
	}
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
		http.Error(w, "告警未启用 (配置 alerts.enabled=false 或 webhook_url 为空)", http.StatusServiceUnavailable)
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
			http.Error(w, "没有任何已注册 agent, 无法测试", http.StatusBadRequest)
			return
		}
		body.AgentID = ags[0].AgentID
	}
	if err := s.alert.ForceAlert(body.AgentID); err != nil {
		http.Error(w, "告警发送失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.Store.Audit(ac.Actor, "alert_test", body.AgentID, "手动触发 webhook 测试", ac.IP)
	respond(w, map[string]string{"status": "sent", "agent_id": body.AgentID}, nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !loginAllowed(ip) {
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
	u, hash, err := s.Store.GetUser(body.Username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if u == nil || hash == "" || u.Disabled {
		cool := loginFail(ip)
		s.Store.Audit(body.Username, "login_failed", "", "reason=user_not_found_or_disabled ip="+ip, ip)
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
	expires := time.Now().Add(12 * time.Hour).Unix()
	_ = s.Store.SettingSet("session:"+tok, body.Username+"|"+u.Role+"|"+intToStr(expires))
	s.Store.Audit(body.Username, "login", "", "session="+tok, ip)
	respond(w, map[string]string{"token": tok, "actor": body.Username, "role": u.Role, "expires_at": intToStr(expires)}, nil)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	a := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(a, "Bearer ")
	_ = s.Store.SettingSet("session:"+tok, "")
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
		Notes   string   `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ac := actorOf(r)
	if body.Tags != nil {
		_ = s.Store.SetAgentTags(body.AgentID, body.Tags)
	}
	if body.Notes != "" {
		_ = s.Store.SetAgentNotes(body.AgentID, body.Notes)
	}
	s.Store.Audit(ac.Actor, "agent_update", body.AgentID, fmt.Sprintf("tags=%v notes=%s", body.Tags, body.Notes), ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleAgentUpdateID 处理 /api/agent/<id> POST（同 /api/agents）。
func (s *Server) handleAgentUpdateID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/agent/")
	var body struct {
		Tags  []string `json:"tags"`
		Notes string   `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ac := actorOf(r)
	if body.Tags != nil {
		_ = s.Store.SetAgentTags(id, body.Tags)
	}
	if body.Notes != "" {
		_ = s.Store.SetAgentNotes(id, body.Notes)
	}
	s.Store.Audit(ac.Actor, "agent_update", id, fmt.Sprintf("tags=%v notes=%s", body.Tags, body.Notes), ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

func (s *Server) handleAgentDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	// 安全: 先踢活会话, 再尝试硬删除(仅允许离线 agent 被删, 防误删活主机)
	s.KickSession(id)
	del, err := s.Store.DeleteAgent(id)
	if err != nil {
		// 多半是 agent 仍标记 online
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if !del {
		http.Error(w, "agent not found", http.StatusNotFound)
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
	tok := genToken()
	if err := s.Store.EnsureToken(tok, body.Note, body.BindAgentID); err != nil {
		respond(w, nil, err)
		return
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "token_create", tok, "note="+body.Note+" bind="+body.BindAgentID, ac.IP)
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
		http.Error(w, "token and agent_id required", http.StatusBadRequest)
		return
	}
	if err := s.Store.BindToken(body.Token, body.AgentID); err != nil {
		respond(w, nil, err)
		return
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "token_bind", body.Token, "agent_id="+body.AgentID, ac.IP)
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
	s.Store.Audit(ac.Actor, "token_revoke", body.Token, "", ac.IP)
	respond(w, map[string]string{"status": "ok"}, nil)
}

// handleTokenDelete 硬删除一个已 revoked 的 token。
func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"` // 原始 token 或哈希都支持
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	if err := s.Store.DeleteToken(body.Token); err != nil {
		// 多半是 token 未撤销
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	ac := actorOf(r)
	s.Store.Audit(ac.Actor, "token_delete", body.Token, "hard delete", ac.IP)
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.Action == "" {
		http.Error(w, "agent_id and action required", http.StatusBadRequest)
		return
	}
	if req.User == "" {
		req.User = "root"
	}
	if !validAction(req.Action) {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.AgentIDs) == 0 || req.Action == "" {
		http.Error(w, "agent_ids and action required", http.StatusBadRequest)
		return
	}
	if req.User == "" {
		req.User = "root"
	}
	if !validAction(req.Action) {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
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
	}
	return false
}

func respond(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
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
