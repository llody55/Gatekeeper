package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"gatekeeper/internal/config"
)

// AlertChecker 周期性扫描 agent 心跳, 超时未心跳发 webhook 告警, 恢复后发恢复事件。
// 同一 agent_id 同一状态(alertedoffline vs already-alerted)去重, 不会每次扫描都重复发。
type AlertChecker struct {
	Store   *Store
	Cfg     config.AlertConfig
	now     func() time.Time
	httpc   *http.Client
	mu      sync.Mutex
	alerted map[string]bool // agent_id -> 已发过 offline 告警(恢复后清掉)
}

// NewAlertChecker 构造告警检查器。若 cfg.Enabled=false 或 webhook 为空, Run 直接返回。
func NewAlertChecker(s *Store, cfg config.AlertConfig) *AlertChecker {
	return &AlertChecker{
		Store:   s,
		Cfg:     cfg,
		now:     time.Now,
		httpc:   &http.Client{Timeout: 10 * time.Second},
		alerted: map[string]bool{},
	}
}

// Run 阻塞运行; 直到 ctx cancel 或配置无效直接返回。
func (a *AlertChecker) Run(stop <-chan struct{}) {
	if !a.Cfg.Enabled || a.Cfg.WebhookURL == "" {
		log.Printf("[alert] 未启用(配置 alerts.enabled=false 或 webhook_url 为空), 跳过")
		return
	}
	if a.Cfg.OfflineAfter <= 0 {
		a.Cfg.OfflineAfter = 10 * time.Minute
	}
	if a.Cfg.CheckInterval <= 0 {
		a.Cfg.CheckInterval = 60 * time.Second
	}
	log.Printf("[alert] 健康告警已启用: offline_after=%s check_interval=%s webhook=%s",
		a.Cfg.OfflineAfter, a.Cfg.CheckInterval, maskURL(a.Cfg.WebhookURL))
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
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", a.Cfg.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Cfg.WebhookToken != "" {
		req.Header.Set("X-Gatekeeper-Token", a.Cfg.WebhookToken)
	}
	resp, err := a.httpc.Do(req)
	if err != nil {
		log.Printf("[alert] webhook 发送失败: %v event=%s agent=%v", err, payload["event"], payload["agent_id"])
		return err
	}
	defer resp.Body.Close()
	log.Printf("[alert] webhook 已发送: event=%s agent=%v status=%d", payload["event"], payload["agent_id"], resp.StatusCode)
	return nil
}

func maskURL(u string) string {
	if len(u) <= 12 {
		return u
	}
	return u[:12] + "..."
}
