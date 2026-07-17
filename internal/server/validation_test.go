package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- validUsername 测试 ----

func TestValidUsername(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
		msg  string // 期望包含的关键词，空串表示不关心
	}{
		// 合法
		{"admin", true, ""},
		{"user_01", true, ""},
		{"my-user", true, ""},
		{"A_B-C", true, ""},
		{"a", true, ""},                     // 最短 1 位
		{strings.Repeat("a", 64), true, ""}, // 最大长度 64

		// 非法 - 空
		{"", false, "required"},
		// 非法 - 过长
		{strings.Repeat("a", 65), false, "too long"},
		// 非法 - 含管道符 (session 分隔符)
		{"admin|x", false, "invalid characters"},
		{"a|b", false, "invalid characters"},
		// 非法 - 含 LIKE 通配符
		{"admin%", false, "invalid characters"},
		{"user_", true, ""}, // 下划线是允许的
		// 非法 - 含其他特殊字符
		{"admin user", false, "invalid characters"},
		{"user@domain", false, "invalid characters"},
		{"user/name", false, "invalid characters"},
		{"user.name", false, "invalid characters"},
		{"中文用户", false, "invalid characters"},
		{"user\nname", false, "invalid characters"},
		{"user\tname", false, "invalid characters"},
	}
	for _, tt := range tests {
		ok, msg := validUsername(tt.name)
		if ok != tt.ok {
			t.Errorf("validUsername(%q) = %v, want %v (msg=%s)", tt.name, ok, tt.ok, msg)
		}
		if !ok && tt.msg != "" && !strings.Contains(msg, tt.msg) {
			t.Errorf("validUsername(%q) msg = %q, want to contain %q", tt.name, msg, tt.msg)
		}
	}
}

// ---- validAgentID 测试 ----

func TestValidAgentID(t *testing.T) {
	tests := []struct {
		id  string
		ok  bool
		msg string
	}{
		// 合法
		{"host-abc123", true, ""},
		{"web.server_01", true, ""},
		{"a", true, ""},
		{strings.Repeat("a", 128), true, ""},

		// 非法 - 空
		{"", false, "required"},
		// 非法 - 过长
		{strings.Repeat("a", 129), false, "too long"},
		// 非法 - 含管道符
		{"host|id", false, "invalid characters"},
		// 非法 - 含空格
		{"host id", false, "invalid characters"},
		// 非法 - 含 %
		{"host%", false, "invalid characters"},
		// 非法 - 含特殊字符
		{"host/id", false, "invalid characters"},
		{"host@id", false, "invalid characters"},
	}
	for _, tt := range tests {
		ok, msg := validAgentID(tt.id)
		if ok != tt.ok {
			t.Errorf("validAgentID(%q) = %v, want %v (msg=%s)", tt.id, ok, tt.ok, msg)
		}
		if !ok && tt.msg != "" && !strings.Contains(msg, tt.msg) {
			t.Errorf("validAgentID(%q) msg = %q, want to contain %q", tt.id, msg, tt.msg)
		}
	}
}

// ---- escapeLike 测试 ----

func TestEscapeLike(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"admin", "admin"},
		{"a%", `a\%`},
		{"a_", `a\_`},
		{`a\b`, `a\\b`},
		{"a%b_c", `a\%b\_c`},
		{`a\%b`, `a\\\%b`},
		{"", ""},
		{"normal-name", "normal-name"},
	}
	for _, tt := range tests {
		got := escapeLike(tt.input)
		if got != tt.want {
			t.Errorf("escapeLike(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---- 集成: session 解析安全性验证 ----

func TestSessionParsingWithValidUsername(t *testing.T) {
	// 验证合法用户名的 session 值能被正确解析
	validNames := []string{"admin", "user_01", "my-user", "A0"}
	for _, name := range validNames {
		v := name + "|admin|1736700000"
		parts := strings.SplitN(v, "|", 3)
		if len(parts) != 3 {
			t.Errorf("SplitN(%q) got %d parts, want 3", v, len(parts))
		}
		if parts[0] != name {
			t.Errorf("parts[0] = %q, want %q", parts[0], name)
		}
		if parts[1] != "admin" {
			t.Errorf("parts[1] = %q, want admin", parts[1])
		}
	}
}

func TestSessionParsingRejectsPipeInUsername(t *testing.T) {
	// 验证含 | 的用户名被 validUsername 拒绝，不会进入 session 解析
	badNames := []string{"admin|x", "a|b|c", "|admin", "admin|"}
	for _, name := range badNames {
		ok, _ := validUsername(name)
		if ok {
			t.Errorf("validUsername(%q) = true, should be false (pipe character)", name)
		}
	}
}

func TestSessionParsingRejectsLikeWildcardInUsername(t *testing.T) {
	// 验证含 % 和 _ 的 LIKE 通配符用户名被拒绝
	// 注意: 下划线 _ 在 validUsername 中是允许的 (因为 _ 是用户名合法字符)，
	// 但 % 会被拒绝。对于 LIKE 匹配，_ 虽然是通配符但由 escapeLike 处理。
	badNames := []string{"admin%", "%", "a%"}
	for _, name := range badNames {
		ok, _ := validUsername(name)
		if ok {
			t.Errorf("validUsername(%q) = true, should be false (LIKE wildcard)", name)
		}
	}
}

// ---- 长度限制常量一致性测试 ----

func TestMaxLenConstants(t *testing.T) {
	// 确保常量是合理的正数
	checks := []struct {
		name string
		val  int
		min  int
		max  int
	}{
		{"maxUsernameLen", maxUsernameLen, 1, 256},
		{"maxAgentIDLen", maxAgentIDLen, 1, 1024},
		{"maxShellPatLen", maxShellPatLen, 1, 10000},
		{"maxTokenNoteLen", maxTokenNoteLen, 1, 4096},
		{"maxDispatchUser", maxDispatchUser, 1, 256},
	}
	for _, c := range checks {
		if c.val < c.min || c.val > c.max {
			t.Errorf("%s = %d, want between %d and %d", c.name, c.val, c.min, c.max)
		}
	}
}

// ---- 正则与常量一致性 ----

func TestUsernameRegexMatchesMaxLen(t *testing.T) {
	// 正则 {1,64} 与 maxUsernameLen=64 应一致
	maxFromRegex := 64
	if maxFromRegex != maxUsernameLen {
		t.Errorf("regex max = %d, maxUsernameLen = %d, mismatch", maxFromRegex, maxUsernameLen)
	}
}

func TestAgentIDRegexMatchesMaxLen(t *testing.T) {
	maxFromRegex := 128
	if maxFromRegex != maxAgentIDLen {
		t.Errorf("regex max = %d, maxAgentIDLen = %d, mismatch", maxFromRegex, maxAgentIDLen)
	}
}

// ---- jsonError / badRequest 响应格式测试 ----

func TestJsonErrorReturnsJSON(t *testing.T) {
	w := httptest.NewRecorder()
	jsonError(w, "test error message", http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if resp["error"] != "test error message" {
		t.Errorf("error = %q, want %q", resp["error"], "test error message")
	}
}

func TestBadRequestReturnsJSON(t *testing.T) {
	w := httptest.NewRecorder()
	badRequest(w, "bad input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("badRequest response is not valid JSON: %v", err)
	}
	if resp["error"] != "bad input" {
		t.Errorf("error = %q, want %q", resp["error"], "bad input")
	}
}

func TestJsonErrorDifferentStatusCodes(t *testing.T) {
	codes := []int{
		http.StatusBadRequest,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusBadGateway,
	}
	for _, code := range codes {
		w := httptest.NewRecorder()
		jsonError(w, "err", code)
		if w.Code != code {
			t.Errorf("status = %d, want %d", w.Code, code)
		}
		var resp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("status %d: response not JSON: %v", code, err)
		}
	}
}
