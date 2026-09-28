// Package agent 实现 Gatekeeper 常驻 agent：主动反连 server 并执行账户救援动作。
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gatekeeper/internal/proto"
)

// validUser 校验用户名是否安全: 仅允许字母、数字、下划线、连字符、点号,
// 拒绝换行符、冒号、空格等可能导致命令注入或 chpasswd stdin 注入的字符。
func validUser(user string) bool {
	if user == "" || len(user) > 32 {
		return false
	}
	for _, c := range user {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.':
		default:
			return false
		}
	}
	return true
}

// validPassword 校验密码不含换行符和回车符, 防止 chpasswd stdin 注入。
func validPassword(pw string) bool {
	if pw == "" {
		return false
	}
	return !strings.ContainsAny(pw, "\n\r")
}

// runCmd 以 root 执行命令并返回合并后的 stdout+stderr。
func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	// 始终静默，不要因为 stdin 阻塞。
	cmd.Stdin = strings.NewReader("")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err := cmd.Run()
	return buf.String(), err
}

// Execute 根据 action 派发并返回结果。
func Execute(c *proto.Cmd) *proto.Result {
	res := &proto.Result{CmdID: c.ID}
	user := c.User
	if user == "" {
		user = "root"
	}
	// 校验用户名: 防止命令注入和 chpasswd stdin 注入
	if !validUser(user) {
		res.Err, res.OK = "invalid username: contains disallowed characters", false
		return res
	}

	switch c.Action {
	case proto.ActionChageStatus:
		out, err := runCmd("chage", "-l", user)
		res.Output, res.Err = out, errStr(err)
		res.OK = err == nil

	case proto.ActionExpireExtend:
		// 关闭过期：永不过期 + 不强制改密 + 不锁定不活动账户
		var all strings.Builder
		for _, args := range [][]string{
			{"-E", "-1", user},
			{"-M", "-1", user},
			{"-I", "-1", user},
			{"-W", "0", user},
		} {
			out, err := runCmd("chage", args...)
			fmt.Fprintf(&all, "chage %s => %v  %s\n", strings.Join(args, " "), err, strings.TrimSpace(out))
			if err != nil {
				res.Output, res.Err, res.OK = all.String(), errStr(err), false
				return res
			}
		}
		res.Output, res.OK = all.String(), true

	case proto.ActionUnlock:
		// 解锁账户有两道独立的锁机制:
		//   usermod -U  → 解除账户锁 (shadow 第2列的 !! 前缀)
		//   passwd -u   → 解除密码锁 (shadow 第2列的 ! 前缀)
		// 等保合规场景可能同时有两道锁, 必须都尝试, 不能因为一道失败就放弃另一道。
		// passwd -u 在密码未锁时会返回 "Warning: password already unlocked" (exit 0),
		// usermod -U 在账户未锁时返回成功, 两者互不冲突。
		var all strings.Builder
		ok := true
		out, err := runCmd("usermod", "-U", user)
		fmt.Fprintf(&all, "usermod -U %s => %v  %s\n", user, err, strings.TrimSpace(out))
		if err != nil {
			ok = false
		}
		out2, err2 := runCmd("passwd", "-u", user)
		fmt.Fprintf(&all, "passwd -u %s => %v  %s\n", user, err2, strings.TrimSpace(out2))
		if err2 != nil {
			// passwd -u 失败可能是"密码本来就未锁" (某些发行版返回非0),
			// 只有 usermod -U 也失败时才算整体失败。
			if err != nil {
				ok = false
			}
		}
		res.Output, res.OK = all.String(), ok
		if !ok {
			res.Err = "usermod -U and passwd -u both failed"
		}

	case proto.ActionClearFail:
		var all strings.Builder
		// faillock 优先（RHEL8+/CentOS Stream），其次 pam_tally2
		out, err := runCmd("faillock", "--user", user, "--reset")
		fmt.Fprintf(&all, "faillock --reset %s => %v  %s\n", user, err, strings.TrimSpace(out))
		if err != nil {
			out2, err2 := runCmd("pam_tally2", "--user", user, "--reset")
			fmt.Fprintf(&all, "pam_tally2 --reset %s => %v  %s\n", user, err2, strings.TrimSpace(out2))
			if err2 != nil {
				res.Output, res.Err, res.OK = all.String(), errStr(err2), false
				return res
			}
		}
		res.Output, res.OK = all.String(), true

	case proto.ActionResetPassword:
		pw := c.Params["password"]
		if pw == "" {
			res.Err, res.OK = "password 参数为空", false
			return res
		}
		if !validPassword(pw) {
			res.Err, res.OK = "password contains invalid characters (\\n, \\r not allowed)", false
			return res
		}
		// 用 chpasswd 改密，避免 stdin TTY 交互
		cmd := exec.Command("chpasswd")
		cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s\n", user, pw))
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		out := buf.String()
		if err != nil {
			res.Output, res.Err, res.OK = out, errStr(err), false
			return res
		}
		// 可选：强制下次登录改密
		if c.Params["force_change"] == "true" {
			out2, err2 := runCmd("chage", "-d", "0", user)
			var b strings.Builder
			fmt.Fprintf(&b, "chage -d 0 %s => %v  %s\n", user, err2, strings.TrimSpace(out2))
			out = out + b.String()
		}
		res.Output, res.OK = out, true

	case proto.ActionCombo:
		// 组合救援：清失败计数 + 解锁 + 关过期 + 改密 + 强制改密
		res.Output, res.OK = execCombo(user, c.Params)
		if !res.OK {
			res.Err = "部分步骤失败"
		}

	case proto.ActionShell:
		res.Output, res.Err, res.OK = execShell(c)
		if res.Err != "" && !res.OK {
			log.Printf("[agent] shell 执行失败: %s err=%s", c.ID, res.Err)
		}

	case proto.ActionScanAccounts:
		res.Output, res.OK = scanAccounts(c)
		if !res.OK {
			res.Err = "scan_accounts failed"
		}

	default:
		res.Err, res.OK = "未知 action: "+c.Action, false
	}
	return res
}

func execCombo(user string, p map[string]string) (string, bool) {
	var all strings.Builder
	ok := true
	step := func(name string, fn func() (string, error)) {
		out, err := fn()
		fmt.Fprintf(&all, "[%s] %v  %s\n", name, err, strings.TrimSpace(out))
		if err != nil {
			ok = false
		}
	}
	if p["clear_fail_count"] == "true" {
		step("clear_fail", func() (string, error) {
			out, err := runCmd("faillock", "--user", user, "--reset")
			if err != nil {
				out2, err2 := runCmd("pam_tally2", "--user", user, "--reset")
				return out + out2, err2
			}
			return out, nil
		})
	}
	if p["unlock_account"] == "true" {
		step("unlock_account", func() (string, error) { return runCmd("usermod", "-U", user) })
	}
	if p["expire_never"] == "true" {
		step("expire_never", func() (string, error) {
			return runCmd("chage", "-E", "-1", "-M", "-1", "-I", "-1", "-W", "0", user)
		})
	}
	if pw := p["password"]; pw != "" {
		step("reset_password", func() (string, error) {
			if !validPassword(pw) {
				return "", fmt.Errorf("password contains invalid characters (\\n, \\r not allowed)")
			}
			cmd := exec.Command("chpasswd")
			cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s\n", user, pw))
			var buf bytes.Buffer
			cmd.Stdout, cmd.Stderr = &buf, &buf
			if err := cmd.Run(); err != nil {
				return buf.String(), err
			}
			if p["force_change"] == "true" {
				out2, err2 := runCmd("chage", "-d", "0", user)
				return buf.String() + out2, err2
			}
			return buf.String(), nil
		})
	}
	return all.String(), ok
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// execShell 执行通用 shell 命令。通过 bash -c 执行, 带超时和输出截断。
func execShell(c *proto.Cmd) (output, errStr string, ok bool) {
	command := c.Params["command"]
	if command == "" {
		return "", "empty command", false
	}
	// 解析超时: 优先取 params, 回退 60s
	timeout := 60 * time.Second
	if t := c.Params["timeout"]; t != "" {
		if d, err := time.ParseDuration(t); err == nil && d > 0 && d <= 10*time.Minute {
			timeout = d
		}
	}
	// 解析输出截断: 优先取 params, 回退 64KB
	maxOutput := 65536
	if m := c.Params["max_output"]; m != "" {
		if n, err := fmtAtoi(m); err == nil && n > 0 && n <= 1048576 {
			maxOutput = n
		}
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Stdin = strings.NewReader("")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	// context 超时/取消时杀整个进程组（含子进程），避免 bash 被杀后子进程残留。
	// exec.CommandContext 只杀主进程，Setpgid 创建独立进程组后需主动 kill -pgid。
	killDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if p := cmd.Process; p != nil {
				_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
			}
		case <-killDone:
		}
	}()

	err := cmd.Run()
	close(killDone)
	duration := time.Since(start)

	out := buf.String()
	if len(out) > maxOutput {
		out = out[:maxOutput] + "\n... [truncated]"
	}

	// 写本地执行日志
	logShellExecution(c.ID, command, err == nil, duration, len(out))

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, "command timed out after " + timeout.String(), false
		}
		return out, err.Error(), false
	}
	return out, "", true
}

// logShellExecution 将 shell 执行记录写入本地日志文件 (~/.gatekeeper/agent-exec.log)。
// 格式: RFC3339 cmd_id=xxx ok=true duration=1.2s output_len=123 command="systemctl restart nginx"
// 简单轮转: 文件超过 10MB 时重命名为 .old, 新建空文件继续写。
func logShellExecution(cmdID, command string, ok bool, duration time.Duration, outputLen int) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".gatekeeper")
	_ = os.MkdirAll(dir, 0700)
	logPath := filepath.Join(dir, "agent-exec.log")

	// 轮转: 超过 10MB 则保留 .old
	if info, err := os.Stat(logPath); err == nil && info.Size() > 10*1024*1024 {
		_ = os.Rename(logPath, logPath+".old")
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("[agent] 无法写入执行日志: %v", err)
		return
	}
	defer f.Close()

	// 截断命令长度, 保持日志可读
	cmdStr := command
	if len(cmdStr) > 200 {
		cmdStr = cmdStr[:200] + "..."
	}
	entry := fmt.Sprintf("%s cmd_id=%s ok=%v duration=%s output_len=%d command=%q\n",
		time.Now().Format(time.RFC3339), cmdID, ok, duration.Round(time.Millisecond), outputLen, cmdStr)
	_, _ = f.WriteString(entry)
}

func fmtAtoi(s string) (int, error) {
	var n int
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<30 {
			return 0, fmt.Errorf("too large")
		}
	}
	return n, nil
}

// AccountInfo 描述单个账户的过期/密码状态, 用于 scan_accounts 上报。
type AccountInfo struct {
	Username       string `json:"username"`
	UID            int    `json:"uid"`
	Status         string `json:"status"`          // active / expired / locked / password_expired / unknown
	LastChange     string `json:"last_change"`     // 密码最后修改日期 (YYYY-MM-DD)
	ExpireDate     string `json:"expire_date"`     // 账户过期日期 (never / YYYY-MM-DD)
	PasswordExpire string `json:"password_expire"` // 密码过期日期
	InactiveDays   int    `json:"inactive_days"`   // 不活跃天数限制
	MinDays        int    `json:"min_days"`        // 最小密码使用天数
	MaxDays        int    `json:"max_days"`        // 最大密码使用天数
	WarnDays       int    `json:"warn_days"`       // 过期前警告天数
}

// scanAccounts 扫描主机上的非系统用户, 解析账户过期信息, 返回 JSON 数组。
// 优化: 直接读取 /etc/shadow 获取密码策略字段, 避免对每个用户 fork 一次 chage。
func scanAccounts(c *proto.Cmd) (string, bool) {
	minUID := 0
	if v := c.Params["min_uid"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			minUID = n
		}
	}
	shadow := readShadow() // map[username][]field, 读失败则为 nil
	var accounts []AccountInfo
	users := listUsers(minUID)
	for _, u := range users {
		var info AccountInfo
		if fields, ok := shadow[u.username]; ok {
			info = parseShadowFields(u.username, fields)
		} else {
			// shadow 中无记录（如无读权限或用户无 shadow 条目），回退 chage
			info = parseChage(u.username)
		}
		info.UID = u.uid
		accounts = append(accounts, info)
	}
	b, err := json.Marshal(accounts)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// readShadow 读取 /etc/shadow 并返回 username -> 字段切片 的映射。
// 读失败（如权限不足）返回 nil, 由调用方回退到 chage。
func readShadow() map[string][]string {
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		log.Printf("[agent] 读取 /etc/shadow 失败, 回退 chage: %v", err)
		return nil
	}
	m := make(map[string][]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 8 {
			continue
		}
		m[fields[0]] = fields
	}
	return m
}

// daysToDate 把自 1970-01-01 起的天数转为 "YYYY-MM-DD"; 空/0 返回 "never"。
func daysToDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "never"
	}
	days, err := strconv.Atoi(s)
	if err != nil || days <= 0 {
		return "never"
	}
	return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days).Format("2006-01-02")
}

// atoiOrZero 解析整数字段, 失败或空返回 0。
func atoiOrZero(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// parseShadowFields 从 /etc/shadow 字段解析账户信息。
// shadow 字段: [0]user [1]pass [2]lastchange [3]min [4]max [5]warn [6]inactive [7]expire
func parseShadowFields(user string, f []string) AccountInfo {
	info := AccountInfo{
		Username:       user,
		Status:         "active",
		LastChange:     daysToDate(f[2]),
		MinDays:        atoiOrZero(f[3]),
		MaxDays:        atoiOrZero(f[4]),
		WarnDays:       atoiOrZero(f[5]),
		InactiveDays:   atoiOrZero(f[6]),
		ExpireDate:     daysToDate(f[7]),
		PasswordExpire: "never",
	}
	// 密码过期日期 = 最后修改日期 + 最大天数
	if info.LastChange != "never" && info.MaxDays > 0 {
		if t, err := time.Parse("2006-01-02", info.LastChange); err == nil {
			info.PasswordExpire = t.AddDate(0, 0, info.MaxDays).Format("2006-01-02")
		}
	}
	info.Status = computeAccountStatus(info)
	return info
}

type userEntry struct {
	username string
	uid      int
}

// listUsers 读取 /etc/passwd 返回 UID >= minUID 且 shell 为可登录的用户列表。
func listUsers(minUID int) []userEntry {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		log.Printf("[agent] 读取 /etc/passwd 失败: %v", err)
		return nil
	}
	var out []userEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil || uid < minUID {
			continue
		}
		// 跳过常见的 nobody (65534)
		if uid == 65534 {
			continue
		}
		// 过滤不可登录的 shell: /usr/sbin/nologin, /sbin/nologin, /bin/false, /bin/sync 等
		shell := strings.TrimSpace(parts[6])
		if isNoLoginShell(shell) {
			continue
		}
		out = append(out, userEntry{username: parts[0], uid: uid})
	}
	return out
}

// isNoLoginShell 判断 shell 是否为不可登录类型。
func isNoLoginShell(shell string) bool {
	switch shell {
	case "/usr/sbin/nologin", "/sbin/nologin", "/bin/nologin",
		"/bin/false", "/usr/bin/false",
		"/bin/sync", "/sbin/shutdown", "/sbin/halt":
		return true
	default:
		// 也匹配路径以 nologin 结尾的变体 (如 /usr/sbin/nologin)
		return strings.HasSuffix(shell, "/nologin")
	}
}

// parseChage 对指定用户运行 chage -l, 解析输出为 AccountInfo。
func parseChage(user string) AccountInfo {
	info := AccountInfo{Username: user, Status: "active"}
	out, err := runCmd("chage", "-l", user)
	if err != nil {
		info.Status = "unknown"
		return info
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		switch {
		case strings.Contains(key, "Last password change"):
			info.LastChange = parseChageDate(val)
		case strings.Contains(key, "Password expires"):
			info.PasswordExpire = parseChageDate(val)
		case strings.Contains(key, "Password inactive"):
			if v, err := strconv.Atoi(val); err == nil {
				info.InactiveDays = v
			}
		case strings.Contains(key, "Account expires"):
			info.ExpireDate = parseChageDate(val)
		case strings.Contains(key, "Minimum number of days"):
			if v, err := strconv.Atoi(val); err == nil {
				info.MinDays = v
			}
		case strings.Contains(key, "Maximum number of days"):
			if v, err := strconv.Atoi(val); err == nil {
				info.MaxDays = v
			}
		case strings.Contains(key, "Number of days of warning"):
			if v, err := strconv.Atoi(val); err == nil {
				info.WarnDays = v
			}
		}
	}
	// 判断状态
	info.Status = computeAccountStatus(info)
	return info
}

// parseChageDate 解析 chage 输出的日期字段, 返回 "YYYY-MM-DD" 或 "never"。
func parseChageDate(val string) string {
	val = strings.TrimSpace(val)
	if val == "" || strings.EqualFold(val, "never") || strings.EqualFold(val, "never expire") {
		return "never"
	}
	// chage 输出格式类似 "May 07, 2026" 或 "Jan 01, 1970"
	layouts := []string{
		"Jan 02, 2006",
		"January 02, 2006",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, val); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return val // 无法解析则返回原文
}

// computeAccountStatus 根据账户信息计算状态: active / password_expired / expired / locked。
func computeAccountStatus(info AccountInfo) string {
	now := time.Now().Truncate(24 * time.Hour)
	// 账户已过期
	if info.ExpireDate != "" && info.ExpireDate != "never" {
		if t, err := time.Parse("2006-01-02", info.ExpireDate); err == nil && !t.After(now) {
			return "expired"
		}
	}
	// 密码已过期
	if info.PasswordExpire != "" && info.PasswordExpire != "never" {
		if t, err := time.Parse("2006-01-02", info.PasswordExpire); err == nil && !t.After(now) {
			return "password_expired"
		}
	}
	if info.LastChange == "" || info.LastChange == "never" {
		// 从未改过密码, 可能被锁定
		return "locked"
	}
	// 检查是否即将过期 (warn 范围内)
	if info.PasswordExpire != "" && info.PasswordExpire != "never" {
		if t, err := time.Parse("2006-01-02", info.PasswordExpire); err == nil {
			warnDays := info.WarnDays
			if warnDays <= 0 {
				warnDays = 7
			}
			if t.Sub(now) <= time.Duration(warnDays)*24*time.Hour {
				return "password_expiring"
			}
		}
	}
	// 账户即将过期
	if info.ExpireDate != "" && info.ExpireDate != "never" {
		if t, err := time.Parse("2006-01-02", info.ExpireDate); err == nil {
			if t.Sub(now) <= 30*24*time.Hour {
				return "expiring"
			}
		}
	}
	return "active"
}
