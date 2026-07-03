// Package agent 实现 Gatekeeper 常驻 agent：主动反连 server 并执行账户救援动作。
package agent

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"gatekeeper/internal/proto"
)

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
