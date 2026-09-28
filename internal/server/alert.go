package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gatekeeper/internal/config"
)

// AlertChecker 周期性扫描 agent 心跳, 超时未心跳发 webhook/邮件告警, 恢复后发恢复事件。
// 同时负责账户巡检过期告警(由 handleScanResult 触发)。
//
// 配置来源:
//   - 基础设施(SMTP host/user/pass/from、offline_after、check_interval): 来自 config.YAML, 启动时加载
//   - 运行时配置(告警开关、webhook_url、邮件收件人、预警阈值): 来自 settings 表, 可 Web 端热更
//
// 同一 agent_id 同一状态去重, 不会每次扫描都重复发。
type AlertChecker struct {
	Store          *Store
	Cfg            config.AlertConfig
	now            func() time.Time
	httpc          *http.Client
	mu             sync.Mutex
	alerted        map[string]bool // agent_id -> 已发过 offline 告警(恢复后清掉)
	accountAlerted map[string]bool // agent_id:username -> 已发过账户过期告警
}

// settingStr 从 settings 表读取字符串配置, 空时返回 def。
func (a *AlertChecker) settingStr(k, def string) string {
	v, err := a.Store.SettingGet(k)
	if err != nil || v == "" {
		return def
	}
	return v
}

// settingBool 从 settings 表读取布尔配置, 空或解析失败时返回 def。
func (a *AlertChecker) settingBool(k string, def bool) bool {
	v, err := a.Store.SettingGet(k)
	if err != nil || v == "" {
		return def
	}
	return v == "true"
}

// settingInt 从 settings 表读取整数配置, 空或解析失败时返回 def。
func (a *AlertChecker) settingInt(k string, def int) int {
	v, err := a.Store.SettingGet(k)
	if err != nil || v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

// runtimeEnabled 返回运行时告警总开关(settings.alert_enabled), 优先于 config.Alerts.Enabled。
func (a *AlertChecker) runtimeEnabled() bool {
	// config 中 enabled=false 表示完全禁用(基础设施未就绪), 直接返回 false
	if !a.Cfg.Enabled {
		return false
	}
	return a.settingBool("alert_enabled", true)
}

// runtimeWebhookURL 返回运行时 webhook 地址(settings.alert_webhook_url), 回退到 config。
func (a *AlertChecker) runtimeWebhookURL() string {
	return a.settingStr("alert_webhook_url", a.Cfg.WebhookURL)
}

// runtimeRecipients 返回告警邮件收件人列表(去重)。
// 收件人来源(按优先级合并去重):
//  1. 所有未禁用 admin 用户绑定的邮箱
//  2. settings.alert_email_to(可多地址逗号分隔)
//  3. config.alerts.email.to(默认值)
func (a *AlertChecker) runtimeRecipients() []string {
	seen := map[string]bool{}
	var out []string
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, addr)
	}
	// 1. admin 用户绑定邮箱
	if adminEmails, err := a.Store.ListAdminEmails(); err == nil {
		for _, e := range adminEmails {
			add(e)
		}
	}
	// 2. settings.alert_email_to
	if to := a.settingStr("alert_email_to", ""); to != "" {
		for _, e := range strings.Split(to, ",") {
			add(e)
		}
	}
	// 3. config 默认值
	if a.Cfg.Email.To != "" {
		for _, e := range strings.Split(a.Cfg.Email.To, ",") {
			add(e)
		}
	}
	return out
}

// NewAlertChecker 构造告警检查器。若 cfg.Enabled=false 或 webhook/邮件均为空, Run 直接返回。
func NewAlertChecker(s *Store, cfg config.AlertConfig) *AlertChecker {
	return &AlertChecker{
		Store:          s,
		Cfg:            cfg,
		now:            time.Now,
		httpc:          &http.Client{Timeout: 10 * time.Second},
		alerted:        map[string]bool{},
		accountAlerted: map[string]bool{},
	}
}

// Run 阻塞运行; 直到 ctx cancel 或配置无效直接返回。
func (a *AlertChecker) Run(stop <-chan struct{}) {
	if !a.Cfg.Enabled || (a.Cfg.WebhookURL == "" && !a.Cfg.Email.Enabled) {
		log.Printf("[alert] 未启用(配置 alerts.enabled=false 或 webhook/邮件均未配置), 跳过")
		return
	}
	if a.Cfg.OfflineAfter <= 0 {
		a.Cfg.OfflineAfter = 10 * time.Minute
	}
	if a.Cfg.CheckInterval <= 0 {
		a.Cfg.CheckInterval = 60 * time.Second
	}
	log.Printf("[alert] 健康告警已启用: offline_after=%s check_interval=%s webhook=%s email=%v",
		a.Cfg.OfflineAfter, a.Cfg.CheckInterval, maskURL(a.Cfg.WebhookURL), a.Cfg.Email.Enabled)
	t := time.NewTicker(a.Cfg.CheckInterval)
	defer t.Stop()
	// 启动后先等一个周期再扫描, 让 agent 有机会上线
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.scanOnce()
		}
	}
}

// scanOnce 做一次扫描, 内部使用。暴露 ScanOnce 给测试用。
func (a *AlertChecker) scanOnce() {
	if !a.runtimeEnabled() {
		return
	}
	cutoff := a.now().Add(-a.Cfg.OfflineAfter)
	stale, err := a.Store.ListAgentsStale(cutoff)
	if err != nil {
		log.Printf("[alert] 扫描 stale agent 失败: %v", err)
		return
	}
	a.mu.Lock()
	alertedNow := map[string]bool{}
	for _, ag := range stale {
		alertedNow[ag.AgentID] = true
		if a.alerted[ag.AgentID] {
			continue // 已发过 offline, 不重复
		}
		a.alerted[ag.AgentID] = true
		go a.postAlert("agent_offline", ag, cutoff)
	}
	// 恢复检测: 之前 alert 过但这次没在 stale 集合 -> 已恢复
	for id := range a.alerted {
		if !alertedNow[id] {
			delete(a.alerted, id)
			go a.postRestore(id)
		}
	}
	a.mu.Unlock()
}

// ScanOnce 公开的单次扫描入口, 供测试或 /api/alerts/test 调用。
func (a *AlertChecker) ScanOnce() {
	a.scanOnce()
}

// ForceAlert 立即对指定 agent_id 发一次 offline 告警, 不去重。用于测试端点。
func (a *AlertChecker) ForceAlert(agentID string) error {
	ag, err := a.Store.GetAgentByID(agentID)
	if err != nil || ag == nil {
		return fmt.Errorf("agent %s not found", agentID)
	}
	return a.postAlert("agent_offline_test", *ag, a.now().Add(-a.Cfg.OfflineAfter))
}

// postAlert POST JSON 到 webhook。事件类型 event: agent_offline / agent_offline_test。
func (a *AlertChecker) postAlert(event string, ag AgentRow, cutoff time.Time) error {
	payload := map[string]any{
		"event":         event,
		"agent_id":      ag.AgentID,
		"hostname":      ag.Hostname,
		"ip":            ag.IP,
		"last_seen":     ag.LastSeen.Unix(),
		"last_seen_ts":  ag.LastSeen.Format(time.RFC3339),
		"offline_after": int64(a.Cfg.OfflineAfter / time.Second),
		"ts":            a.now().Format(time.RFC3339),
	}
	return a.post(payload)
}

// postRestore 发 agent_recovered 事件。
func (a *AlertChecker) postRestore(agentID string) error {
	payload := map[string]any{
		"event":    "agent_recovered",
		"agent_id": agentID,
		"ts":       a.now().Format(time.RFC3339),
	}
	return a.post(payload)
}

func (a *AlertChecker) post(payload map[string]any) error {
	event, _ := payload["event"].(string)
	subject := fmt.Sprintf("[Gatekeeper] %s", event)
	webhookURL := a.runtimeWebhookURL()
	recipients := a.runtimeRecipients()
	// 1. webhook
	if webhookURL != "" {
		b, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(b))
		if err != nil {
			log.Printf("[alert] webhook 构造失败: %v event=%s", err, event)
		} else {
			req.Header.Set("Content-Type", "application/json")
			if a.Cfg.WebhookToken != "" {
				req.Header.Set("X-Gatekeeper-Token", a.Cfg.WebhookToken)
			}
			resp, err := a.httpc.Do(req)
			if err != nil {
				log.Printf("[alert] webhook 发送失败: %v event=%s", err, event)
			} else {
				resp.Body.Close()
				log.Printf("[alert] webhook 已发送: event=%s status=%d", event, resp.StatusCode)
			}
		}
	}
	// 2. 邮件
	if a.Cfg.Email.Enabled && len(recipients) > 0 {
		log.Printf("[alert] 邮件收件人: %s", strings.Join(recipients, ", "))
		body := formatAlertEmail(payload)
		if err := a.sendEmail(subject, body, recipients); err != nil {
			log.Printf("[alert] 邮件发送失败: %v event=%s", err, event)
		} else {
			log.Printf("[alert] 邮件已发送: event=%s to=%s", event, strings.Join(recipients, ","))
		}
	}
	return nil
}

// formatAlertEmail 把告警 payload 格式化为纯文本邮件正文。
func formatAlertEmail(payload map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Gatekeeper 告警通知\n")
	fmt.Fprintf(&b, "========================\n\n")
	for k, v := range payload {
		fmt.Fprintf(&b, "%s: %v\n", k, v)
	}
	fmt.Fprintf(&b, "\n-- Gatekeeper\n")
	return b.String()
}

// sendEmail 通过 SMTP 发送邮件。支持 STARTTLS(587) 和 TLS(465)。
// recipients 为收件人列表(由 runtimeRecipients 合并 admin 邮箱 + 全局配置)。
func (a *AlertChecker) sendEmail(subject, body string, recipients []string) error {
	cfg := a.Cfg.Email
	if cfg.Host == "" || cfg.From == "" || len(recipients) == 0 {
		return fmt.Errorf("email host/from/to 未配置")
	}
	host, _, err := net.SplitHostPort(cfg.Host)
	if err != nil {
		return fmt.Errorf("解析 email host 失败: %w", err)
	}

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, host)
	}
	to := strings.Join(recipients, ", ")

	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		cfg.From, to, subject, body))

	if cfg.UseTLS {
		// 端口 465: 直接 TLS
		tlsCfg := &tls.Config{ServerName: host}
		conn, err := tls.Dial("tcp", cfg.Host, tlsCfg)
		if err != nil {
			return err
		}
		defer conn.Close()
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			return err
		}
		defer c.Close()
		if auth != nil {
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
		if err := c.Mail(cfg.From); err != nil {
			return err
		}
		for _, rcpt := range recipients {
			if err := c.Rcpt(rcpt); err != nil {
				return err
			}
		}
		w, err := c.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(msg); err != nil {
			return err
		}
		return w.Close()
	}

	// 默认 STARTTLS(587)
	return smtp.SendMail(cfg.Host, auth, cfg.From, recipients, msg)
}

// NotifyAccountExpired 在账户巡检结果写入后调用, 对过期/即将过期账户发告警。
// accounts 为本次巡检的账户列表。同一 agent+username 只告警一次, 直到账户恢复 active。
// 运行时配置(开关/阈值)从 settings 表读取, 可 Web 端热更。
func (a *AlertChecker) NotifyAccountExpired(agentID, hostname string, accounts []AccountScanRow) {
	if !a.runtimeEnabled() {
		return
	}
	if !a.settingBool("alert_account_expired_enabled", a.Cfg.AccountExpired.Enabled) {
		return
	}
	if a.runtimeWebhookURL() == "" && (!a.Cfg.Email.Enabled || len(a.runtimeRecipients()) == 0) {
		return
	}
	warnDays := a.settingInt("alert_warn_days", a.Cfg.AccountExpired.WarnDays)
	if warnDays <= 0 {
		warnDays = 7
	}
	now := a.now()

	a.mu.Lock()
	for _, acct := range accounts {
		key := agentID + ":" + acct.Username
		shouldAlert := false
		reason := ""

		switch acct.Status {
		case "expired", "password_expired":
			shouldAlert = true
			reason = fmt.Sprintf("账户状态=%s", acct.Status)
		case "active":
			// 检查是否即将过期
			if acct.PasswordExpire != "" && acct.PasswordExpire != "never" {
				if exp, err := time.Parse("2006-01-02", acct.PasswordExpire); err == nil {
					days := int(exp.Sub(now).Hours() / 24)
					if days <= warnDays {
						shouldAlert = true
						reason = fmt.Sprintf("密码将在 %d 天后过期(%s)", days, acct.PasswordExpire)
					}
				}
			}
		}

		if shouldAlert {
			if a.accountAlerted[key] {
				continue
			}
			a.accountAlerted[key] = true
			payload := map[string]any{
				"event":           "account_expired",
				"agent_id":        agentID,
				"hostname":        hostname,
				"username":        acct.Username,
				"uid":             acct.UID,
				"status":          acct.Status,
				"password_expire": acct.PasswordExpire,
				"expire_date":     acct.ExpireDate,
				"reason":          reason,
				"ts":              now.Format(time.RFC3339),
			}
			go a.post(payload)
		} else if acct.Status == "active" {
			// 已恢复 active 且未即将过期, 清除告警标记
			delete(a.accountAlerted, key)
		}
	}
	a.mu.Unlock()
}

func maskURL(u string) string {
	if len(u) <= 12 {
		return u
	}
	return u[:12] + "..."
}
