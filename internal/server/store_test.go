package server

import (
	"os"
	"strings"
	"testing"
	"time"
)

// openTestStore 用内存 SQLite 打开测试用 Store。
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ---- Token 相关测试 ----

func TestEnsureTokenAndListPaged(t *testing.T) {
	s := openTestStore(t)
	raw := "my-secret-token-1234567890"
	if err := s.EnsureToken(raw, "test token", ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	toks, total, err := s.ListTokensPaged(1, 10)
	if err != nil {
		t.Fatalf("ListTokensPaged: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(toks) != 1 {
		t.Fatalf("len(toks) = %d, want 1", len(toks))
	}
	if toks[0].Prefix != TokenPrefix(raw) {
		t.Errorf("prefix = %q, want %q", toks[0].Prefix, TokenPrefix(raw))
	}
	if toks[0].Note != "test token" {
		t.Errorf("note = %q, want %q", toks[0].Note, "test token")
	}
	if toks[0].Revoked {
		t.Error("新 token 不应被撤销")
	}
}

func TestValidToken(t *testing.T) {
	s := openTestStore(t)
	raw := "valid-token-12345678901234"
	if err := s.EnsureToken(raw, "", ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	ok, err := s.ValidToken(raw)
	if err != nil {
		t.Fatalf("ValidToken: %v", err)
	}
	if !ok {
		t.Error("新 token 应有效")
	}
}

func TestRevokeToken(t *testing.T) {
	s := openTestStore(t)
	raw := "revoke-me-token-1234567890"
	if err := s.EnsureToken(raw, "", ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	if err := s.RevokeToken(raw); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	ok, err := s.ValidToken(raw)
	if err != nil {
		t.Fatalf("ValidToken: %v", err)
	}
	if ok {
		t.Error("已撤销的 token 不应有效")
	}
}

func TestDeleteTokenNotFound(t *testing.T) {
	s := openTestStore(t)
	err := s.DeleteToken("nonexistent-token-1234567890")
	if err == nil {
		t.Error("删除不存在的 token 应返回错误")
	}
}

func TestDeleteTokenNotRevoked(t *testing.T) {
	s := openTestStore(t)
	raw := "active-token-123456789012345"
	if err := s.EnsureToken(raw, "", ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	err := s.DeleteToken(raw)
	if err == nil || !strings.Contains(err.Error(), "not revoked") {
		t.Errorf("删除未撤销的 token 应报错, got: %v", err)
	}
}

func TestDeleteTokenSuccess(t *testing.T) {
	s := openTestStore(t)
	raw := "delete-me-token-12345678901"
	if err := s.EnsureToken(raw, "", ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	if err := s.RevokeToken(raw); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if err := s.DeleteToken(raw); err != nil {
		t.Fatalf("DeleteToken 应成功: %v", err)
	}
}

func TestTokenBind(t *testing.T) {
	s := openTestStore(t)
	raw := "bind-token-12345678901234567"
	if err := s.EnsureToken(raw, "bind test", "agent-01"); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	// 绑定校验: agent-01 用此 token 应通过
	bound, unbound, boundTo, err := s.CheckTokenBindAgent(raw, "agent-01")
	if err != nil {
		t.Fatalf("CheckTokenBindAgent: %v", err)
	}
	if !bound {
		t.Error("agent-01 应能绑定")
	}
	if unbound {
		t.Error("已绑定 token 不应返回 unbound=true")
	}
	if boundTo != "agent-01" {
		t.Errorf("boundTo = %q, want agent-01", boundTo)
	}
	// 冒名校验: agent-02 用此 token 应拒绝
	bound2, _, boundTo2, err := s.CheckTokenBindAgent(raw, "agent-02")
	if err != nil {
		t.Fatalf("CheckTokenBindAgent: %v", err)
	}
	if bound2 {
		t.Error("agent-02 冒名应被拒绝")
	}
	if !strings.Contains(boundTo2, "agent-01") {
		t.Errorf("boundTo 应包含 agent-01, got %q", boundTo2)
	}
}

// ---- Agent 相关测试 ----

func TestTouchAgent(t *testing.T) {
	s := openTestStore(t)
	rawToken := "agent-test-token-1234567890"
	// token 需先入库
	if err := s.EnsureToken(rawToken, "", ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	first, err := s.TouchAgent("agent-01", rawToken, "myhost", "linux", "10.0.0.1")
	if err != nil {
		t.Fatalf("TouchAgent: %v", err)
	}
	if !first {
		t.Error("首次注册应返回 first=true")
	}
	a, err := s.GetAgent("agent-01")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if a == nil {
		t.Fatal("agent 不应为 nil")
	}
	if a.Hostname != "myhost" {
		t.Errorf("hostname = %q, want myhost", a.Hostname)
	}
	if a.IP != "10.0.0.1" {
		t.Errorf("ip = %q, want 10.0.0.1", a.IP)
	}
	if !a.Online {
		t.Error("新 agent 应在线")
	}
	// 二次 Touch: 非首次
	first2, err := s.TouchAgent("agent-01", rawToken, "myhost2", "", "10.0.0.2")
	if err != nil {
		t.Fatalf("TouchAgent 2nd: %v", err)
	}
	if first2 {
		t.Error("二次注册不应返回 first=true")
	}
	a2, err := s.GetAgent("agent-01")
	if err != nil {
		t.Fatalf("GetAgent 2nd: %v", err)
	}
	if a2.Hostname != "myhost2" {
		t.Errorf("hostname 应更新, got %q", a2.Hostname)
	}
	if a2.IP != "10.0.0.2" {
		t.Errorf("ip 应更新, got %q", a2.IP)
	}
}

func TestOfflineAgent(t *testing.T) {
	s := openTestStore(t)
	rawToken := "offline-token-1234567890123"
	_ = s.EnsureToken(rawToken, "", "")
	_, _ = s.TouchAgent("agent-off", rawToken, "h", "linux", "1.1.1.1")
	if err := s.OfflineAgent("agent-off"); err != nil {
		t.Fatalf("OfflineAgent: %v", err)
	}
	a, _ := s.GetAgent("agent-off")
	if a.Online {
		t.Error("agent 应离线")
	}
}

func TestListAgentsPaged(t *testing.T) {
	s := openTestStore(t)
	tok := "list-token-1234567890123456"
	_ = s.EnsureToken(tok, "", "")
	for i := 0; i < 5; i++ {
		id := "agent-" + strings.Repeat("0", 2-len(itoa(i))) + itoa(i)
		_, _ = s.TouchAgent(id, tok, "host-"+itoa(i), "linux", "10.0.0."+itoa(i+1))
	}
	// 分页测试
	agents, total, err := s.ListAgentsPaged(1, 2, "")
	if err != nil {
		t.Fatalf("ListAgentsPaged: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(agents) != 2 {
		t.Errorf("page size = %d, want 2", len(agents))
	}
	// 搜索测试
	agents2, total2, _ := s.ListAgentsPaged(1, 10, "host-1")
	if total2 != 1 {
		t.Errorf("搜索 'host-1' total = %d, want 1", total2)
	}
	if len(agents2) != 1 {
		t.Errorf("搜索 'host-1' len = %d, want 1", len(agents2))
	}
}

func TestSetAgentTagsAndNotes(t *testing.T) {
	s := openTestStore(t)
	tok := "tag-token-12345678901234567"
	_ = s.EnsureToken(tok, "", "")
	_, _ = s.TouchAgent("agent-tag", tok, "h", "linux", "1.1.1.1")
	if err := s.SetAgentTags("agent-tag", []string{"prod", "web"}); err != nil {
		t.Fatalf("SetAgentTags: %v", err)
	}
	if err := s.SetAgentNotes("agent-tag", "production web server"); err != nil {
		t.Fatalf("SetAgentNotes: %v", err)
	}
	a, _ := s.GetAgent("agent-tag")
	if len(a.Tags) != 2 || a.Tags[0] != "prod" || a.Tags[1] != "web" {
		t.Errorf("tags = %v, want [prod web]", a.Tags)
	}
	if a.Notes != "production web server" {
		t.Errorf("notes = %q, want 'production web server'", a.Notes)
	}
	// 清空备注
	if err := s.SetAgentNotes("agent-tag", ""); err != nil {
		t.Fatalf("SetAgentNotes empty: %v", err)
	}
	a2, _ := s.GetAgent("agent-tag")
	if a2.Notes != "" {
		t.Errorf("清空后 notes = %q, want ''", a2.Notes)
	}
}

func TestDeleteAgent(t *testing.T) {
	s := openTestStore(t)
	tok := "del-token-123456789012345678"
	_ = s.EnsureToken(tok, "", "")
	_, _ = s.TouchAgent("agent-del", tok, "h", "linux", "1.1.1.1")
	// 先置离线再删
	_ = s.OfflineAgent("agent-del")
	deleted, err := s.DeleteAgent("agent-del")
	if err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if !deleted {
		t.Error("应成功删除离线 agent")
	}
	a, _ := s.GetAgent("agent-del")
	if a != nil {
		t.Error("已删除的 agent 应为 nil")
	}
}

func TestDeleteAgentOnlineRefused(t *testing.T) {
	s := openTestStore(t)
	tok := "online-token-123456789012345"
	_ = s.EnsureToken(tok, "", "")
	_, _ = s.TouchAgent("agent-online", tok, "h", "linux", "1.1.1.1")
	_, err := s.DeleteAgent("agent-online")
	if err == nil {
		t.Error("删除在线 agent 应报错")
	}
}

// ---- Command 相关测试 ----

func TestSaveCmdAndGetCmd(t *testing.T) {
	s := openTestStore(t)
	c := &StoredCmd{
		ID: "cmd-001", AgentID: "agent-01", Action: "unlock",
		User: "root", Params: map[string]string{"password": "secret123"},
		CreatedBy: "admin",
	}
	if err := s.SaveCmd(c); err != nil {
		t.Fatalf("SaveCmd: %v", err)
	}
	got, err := s.GetCmd("cmd-001")
	if err != nil {
		t.Fatalf("GetCmd: %v", err)
	}
	if got == nil {
		t.Fatal("指令不应为 nil")
	}
	if got.Status != "pending" {
		t.Errorf("status = %q, want pending", got.Status)
	}
	if got.Action != "unlock" {
		t.Errorf("action = %q, want unlock", got.Action)
	}
	// 密码不应落库
	if strings.Contains(got.Output, "secret123") {
		t.Error("密码明文不应出现在 output 中 (但 SaveCmd 也不存 output)")
	}
}

func TestFinishCmd(t *testing.T) {
	s := openTestStore(t)
	c := &StoredCmd{
		ID: "cmd-002", AgentID: "agent-01", Action: "chage_status",
		User: "testuser", CreatedBy: "admin",
	}
	_ = s.SaveCmd(c)
	if err := s.FinishCmd("cmd-002", &ResultBody{Output: "ok", OK: true}); err != nil {
		t.Fatalf("FinishCmd: %v", err)
	}
	got, _ := s.GetCmd("cmd-002")
	if got.Status != "done" {
		t.Errorf("status = %q, want done", got.Status)
	}
	if got.Output != "ok" {
		t.Errorf("output = %q, want ok", got.Output)
	}
	if got.FinishedAt.IsZero() {
		t.Error("finished_at 不应为零值")
	}
}

func TestSweepTimeouts(t *testing.T) {
	s := openTestStore(t)
	c := &StoredCmd{
		ID: "cmd-timeout", AgentID: "agent-01", Action: "chage_status",
		User: "testuser", CreatedBy: "admin",
	}
	_ = s.SaveCmd(c)
	// 刚创建不应超时
	ids, err := s.SweepTimeouts(1 * time.Second)
	if err != nil {
		t.Fatalf("SweepTimeouts 1: %v", err)
	}
	if len(ids) > 0 {
		t.Errorf("刚创建的指令不应超时, got %v", ids)
	}
	// 等 1.5 秒后以 500ms 超时扫描应捕获 (Unix 秒精度下需至少跨秒)
	time.Sleep(1500 * time.Millisecond)
	ids2, err := s.SweepTimeouts(500 * time.Millisecond)
	if err != nil {
		t.Fatalf("SweepTimeouts 2: %v", err)
	}
	if len(ids2) != 1 {
		t.Errorf("应超时 1 条, got %v", ids2)
	}
	got, _ := s.GetCmd("cmd-timeout")
	if got.Status != "timeout" {
		t.Errorf("status = %q, want timeout", got.Status)
	}
}

func TestListCmdsPaged(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 3; i++ {
		c := &StoredCmd{
			ID: "cmd-list-" + itoa(i), AgentID: "agent-01", Action: "unlock",
			User: "root", CreatedBy: "admin",
		}
		_ = s.SaveCmd(c)
	}
	cmds, total, err := s.ListCmdsPaged(1, 2, "agent-01", "")
	if err != nil {
		t.Fatalf("ListCmdsPaged: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(cmds) != 2 {
		t.Errorf("page size = %d, want 2", len(cmds))
	}
	// 按 action 过滤
	cmds2, total2, _ := s.ListCmdsPaged(1, 10, "agent-01", "unlock")
	if total2 != 3 {
		t.Errorf("filtered total = %d, want 3", total2)
	}
	if len(cmds2) != 3 {
		t.Errorf("filtered len = %d, want 3", len(cmds2))
	}
}

// ---- 审计相关测试 ----

func TestAudit(t *testing.T) {
	s := openTestStore(t)
	if err := s.Audit("admin", "login", "", "ip=10.0.0.1", "10.0.0.1"); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	f := AuditFilter{Page: 1, PageSize: 10}
	rows, total, err := s.ListAuditPaged(f)
	if err != nil {
		t.Fatalf("ListAuditPaged: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].Actor != "admin" {
		t.Errorf("actor = %q, want admin", rows[0].Actor)
	}
	if rows[0].Action != "login" {
		t.Errorf("action = %q, want login", rows[0].Action)
	}
}

func TestAuditFiltered(t *testing.T) {
	s := openTestStore(t)
	_ = s.Audit("admin", "login", "", "a", "1.1.1.1")
	_ = s.Audit("operator", "dispatch", "agent-01", "action=unlock", "2.2.2.2")
	_ = s.Audit("admin", "dispatch", "agent-02", "action=shell", "1.1.1.1")
	// 按 actor 过滤
	f := AuditFilter{Page: 1, PageSize: 10, Actor: "admin"}
	_, total, _ := s.ListAuditPaged(f)
	if total != 2 {
		t.Errorf("admin audit total = %d, want 2", total)
	}
	// 按 action 过滤
	f2 := AuditFilter{Page: 1, PageSize: 10, Action: "dispatch"}
	_, total2, _ := s.ListAuditPaged(f2)
	if total2 != 2 {
		t.Errorf("dispatch audit total = %d, want 2", total2)
	}
}

// ---- 用户相关测试 ----

func TestCreateUserAndGetUser(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("testpass123")
	if err := s.CreateUser("testuser", h, "operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, hash, err := s.GetUser("testuser")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u == nil {
		t.Fatal("用户不应为 nil")
	}
	if u.Username != "testuser" {
		t.Errorf("username = %q", u.Username)
	}
	if u.Role != "operator" {
		t.Errorf("role = %q, want operator", u.Role)
	}
	if u.Disabled {
		t.Error("新用户不应被禁用")
	}
	if hash != h {
		t.Error("密码哈希不匹配")
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("pass1")
	_ = s.CreateUser("dupuser", h, "operator")
	err := s.CreateUser("dupuser", h, "operator")
	if err == nil {
		t.Error("重复用户名应报错")
	}
}

func TestSetUserPassword(t *testing.T) {
	s := openTestStore(t)
	h1, _ := HashPassword("oldpass123")
	_ = s.CreateUser("pwuser", h1, "operator")
	h2, _ := HashPassword("newpass456")
	if err := s.SetUserPassword("pwuser", h2); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	_, hash, _ := s.GetUser("pwuser")
	if hash != h2 {
		t.Error("密码哈希应已更新")
	}
}

func TestSetUserDisabled(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("pass123")
	_ = s.CreateUser("disuser", h, "operator")
	if err := s.SetUserDisabled("disuser", true); err != nil {
		t.Fatalf("SetUserDisabled true: %v", err)
	}
	u, _, _ := s.GetUser("disuser")
	if !u.Disabled {
		t.Error("用户应被禁用")
	}
	if err := s.SetUserDisabled("disuser", false); err != nil {
		t.Fatalf("SetUserDisabled false: %v", err)
	}
	u2, _, _ := s.GetUser("disuser")
	if u2.Disabled {
		t.Error("用户应已启用")
	}
}

func TestCountAdmins(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("adminpass")
	_ = s.CreateUser("admin1", h, "admin")
	_ = s.CreateUser("admin2", h, "admin")
	_ = s.CreateUser("op1", h, "operator")
	n, err := s.CountAdmins()
	if err != nil {
		t.Fatalf("CountAdmins: %v", err)
	}
	if n != 2 {
		t.Errorf("admin 数量 = %d, want 2", n)
	}
}

func TestDeleteUser(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("pass123")
	_ = s.CreateUser("deluser", h, "operator")
	if err := s.DeleteUser("deluser"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	u, _, _ := s.GetUser("deluser")
	if u != nil {
		t.Error("已删除的用户应为 nil")
	}
}

// ---- Settings 相关测试 ----

func TestSettingsSetGet(t *testing.T) {
	s := openTestStore(t)
	if err := s.SettingSet("test_key", "test_value"); err != nil {
		t.Fatalf("SettingSet: %v", err)
	}
	v, err := s.SettingGet("test_key")
	if err != nil {
		t.Fatalf("SettingGet: %v", err)
	}
	if v != "test_value" {
		t.Errorf("value = %q, want test_value", v)
	}
}

func TestSettingGetAbsent(t *testing.T) {
	s := openTestStore(t)
	v, err := s.SettingGet("nonexistent")
	if err != nil {
		t.Fatalf("SettingGet: %v", err)
	}
	if v != "" {
		t.Errorf("不存在的 key 应返回空字符串, got %q", v)
	}
}

// ---- Shell 规则相关测试 ----

func TestShellRulesCRUD(t *testing.T) {
	s := openTestStore(t)
	id, err := s.AddShellRule("whitelist", "systemctl restart *", "重启服务")
	if err != nil {
		t.Fatalf("AddShellRule: %v", err)
	}
	if id <= 0 {
		t.Errorf("新增规则 id = %d, want > 0", id)
	}
	rules, err := s.ListShellRules("whitelist", true)
	if err != nil {
		t.Fatalf("ListShellRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("whitelist 规则数 = %d, want 1", len(rules))
	}
	if !rules[0].Enabled {
		t.Error("新规则应默认启用")
	}
	// 更新规则
	if err := s.UpdateShellRule(id, "systemctl restart nginx", "仅重启 nginx", false); err != nil {
		t.Fatalf("UpdateShellRule: %v", err)
	}
	rules2, _ := s.ListShellRules("whitelist", false)
	if rules2[0].Enabled {
		t.Error("规则应已禁用")
	}
	if rules2[0].Pattern != "systemctl restart nginx" {
		t.Errorf("pattern = %q, want 'systemctl restart nginx'", rules2[0].Pattern)
	}
	// 删除规则
	if err := s.DeleteShellRule(id); err != nil {
		t.Fatalf("DeleteShellRule: %v", err)
	}
	rules3, _ := s.ListShellRules("whitelist", false)
	if len(rules3) != 0 {
		t.Errorf("删除后规则数 = %d, want 0", len(rules3))
	}
}

func TestSeedShellRules(t *testing.T) {
	s := openTestStore(t)
	if err := s.SeedShellRules(); err != nil {
		t.Fatalf("SeedShellRules: %v", err)
	}
	// 再次种子应什么都不做
	if err := s.SeedShellRules(); err != nil {
		t.Fatalf("SeedShellRules 2nd: %v", err)
	}
	n, _ := s.CountShellRules()
	// 白名单 23 条 + 黑名单 14 条 = 37 条
	if n != 37 {
		t.Errorf("种子后规则数 = %d, want 37", n)
	}
}

// ---- 数据清理测试 ----

func TestPurgeOlderThan(t *testing.T) {
	s := openTestStore(t)
	// 写入一条审计日志和一条指令
	_ = s.Audit("admin", "test", "", "purge test", "1.1.1.1")
	c := &StoredCmd{ID: "purge-cmd", AgentID: "agent-01", Action: "unlock", User: "root", CreatedBy: "admin"}
	_ = s.SaveCmd(c)

	// 清理过去时间的数据：不应影响（记录比过去时间新）
	ac, cc, err := s.PurgeOlderThan(time.Now().Add(-1 * time.Hour))
	if err != nil {
		t.Fatalf("PurgeOlderThan past: %v", err)
	}
	if ac != 0 || cc != 0 {
		t.Errorf("清理过去时间不应影响新记录 audit=%d cmd=%d, want 0 0", ac, cc)
	}
	// 清理未来时间的数据：应清理所有早于未来的记录
	ac2, cc2, err := s.PurgeOlderThan(time.Now().Add(1 * time.Hour))
	if err != nil {
		t.Fatalf("PurgeOlderThan future: %v", err)
	}
	if ac2 < 1 {
		t.Errorf("audit purge = %d, want >=1", ac2)
	}
	if cc2 < 1 {
		t.Errorf("cmd purge = %d, want >=1", cc2)
	}
}

// ---- 辅助函数 ----

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ---- escapeLike 的 LIKE 注入防护验证 ----

func TestEscapeLikeScenario(t *testing.T) {
	s := openTestStore(t)
	h, _ := HashPassword("pass")
	// 创建含下划线（LIKE 通配符）的用户名
	_ = s.CreateUser("test_user", h, "operator")
	// 同时创建不含下划线的用户
	_ = s.CreateUser("testxuser", h, "operator")

	// 模拟 session: v = "test_user|operator|9999999999"
	_ = s.SettingSet("session:abc", "test_user|operator|9999999999")
	_ = s.SettingSet("session:def", "testxuser|operator|9999999999")

	// DeleteSessionsByActor 应只删除 test_user 的会话，
	// 不能因为 LIKE 的 _ 通配符而误删 testxuser
	s.DeleteSessionsByActor("test_user")

	v1, _ := s.SettingGet("session:abc")
	v2, _ := s.SettingGet("session:def")
	if v1 != "" {
		t.Error("test_user 的会话应已删除")
	}
	if v2 == "" {
		t.Error("testxuser 的会话不应被误删（LIKE 注入防护）")
	}
}

// ---- 确保测试数据库文件不留痕 ----
var _ = os.Remove
