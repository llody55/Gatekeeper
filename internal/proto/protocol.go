// Package proto 定义 Gatekeeper server 与 agent 之间的 WebSocket JSON 消息协议。
package proto

// Action 名常量：账户救援的 5 个原子动作。
const (
	ActionChageStatus   = "chage_status"   // 查看过期状态
	ActionExpireExtend  = "expire_extend"   // 延期/关闭过期
	ActionUnlock        = "unlock"          // 解锁账户与密码
	ActionClearFail     = "clear_fail"      // 清除登录失败计数
	ActionResetPassword = "reset_password"  // 重置密码
	ActionCombo         = "combo"           // 组合执行（救援套餐）
)

// Kind 名常量。
const (
	KindRegister = "register" // agent -> server 注册
	KindOK       = "ok"        // server -> agent 注册成功
	KindErr      = "error"     // server -> agent 出错
	KindCmd      = "cmd"       // server -> agent 下发指令
	KindResult   = "result"   // agent -> server 回执
	KindPing     = "ping"     // agent -> server 心跳
	KindPong     = "pong"     // server -> agent 心跳回执
)

// Envelope 是所有 WebSocket 消息的外层包装。
type Envelope struct {
	Kind     string `json:"kind"`
	Token    string `json:"token,omitempty"`     // 仅 register
	AgentID  string `json:"agent_id,omitempty"`  // agent 自上报的唯一 id（hostname+uuid）
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Cmd      *Cmd   `json:"cmd,omitempty"`    // 下发指令
	Result   *Result `json:"result,omitempty"` // 仅 result
	Payload  string `json:"payload,omitempty"` // error 的文字 / ping 等
}

// Cmd 是 server 下发给 agent 的指令。
type Cmd struct {
	ID     string            `json:"id"`
	Action string            `json:"action"`
	User   string            `json:"user,omitempty"`
	Params map[string]string `json:"params,omitempty"` // 扩展参数
}

// Result 是 agent 对 Cmd 的回执。
type Result struct {
	CmdID  string `json:"cmd_id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"` // 命令 stdout+stderr
	Err    string `json:"err,omitempty"`
}

// ComboParams 定义 ActionCombo 的参数（组合救援）。
type ComboParams struct {
	ClearFailCount bool   `json:"clear_fail_count"`
	UnlockAccount  bool   `json:"unlock_account"`
	NewPassword    string `json:"new_password,omitempty"` // 不填则不重置密码
	ExpireNever    bool   `json:"expire_never,omitempty"`  // 关闭过期
	ForceChange    bool   `json:"force_change,omitempty"`  // 下次登录强制改密
}