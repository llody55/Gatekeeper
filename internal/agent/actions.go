// Package agent 实现 Gatekeeper 常驻 agent：主动反连 server 并执行账户救援动作。
package agent

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
		var all strings.Builder
		// usermod -U 解锁账户
		out, err := runCmd("usermod", "-U", user)
		fmt.Fprintf(&all, "usermod -U %s => %v  %s\n", user, err, strings.TrimSpace(out))
		if err != nil {
			res.Output, res.Err, res.OK = all.String(), errStr(err), false
			return res
		}
		// passwd -u 解锁密码（可能本来就未锁，忽略报错）
		out, err = runCmd("passwd", "-u", user)
		fmt.Fprintf(&all, "passwd -u %s => %v  %s\n", user, err, strings.TrimSpace(out))
		res.Output, res.OK = all.String(), true

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
	err := cmd.Run()
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
