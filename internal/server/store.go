package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store 封装 SQLite，存储 agent 注册信息、Token、指令历史与操作审计。
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS agents (
  agent_id      TEXT PRIMARY KEY,
  token         TEXT NOT NULL,
  hostname      TEXT,
  os            TEXT,
  ip            TEXT,
  tags          TEXT,
  notes         TEXT,
  last_seen     INTEGER NOT NULL,
  online        INTEGER NOT NULL DEFAULT 0,
  meta          TEXT
);
CREATE TABLE IF NOT EXISTS tokens (
  token           TEXT PRIMARY KEY,  -- sha256(原始 token) hex, 不可逆
  token_prefix    TEXT,                -- 原始 token 前 8 位, 仅用于 UI 辨识
  note            TEXT,
  created_at      INTEGER NOT NULL,
  revoked         INTEGER NOT NULL DEFAULT 0,
  bound_agent_id  TEXT                  -- 绑定的 agent_id; 非空则仅允许该 agent 用此 token 注册, 防止冒名
);
CREATE TABLE IF NOT EXISTS commands (
  id            TEXT PRIMARY KEY,
  agent_id      TEXT NOT NULL,
  action        TEXT NOT NULL,
  user          TEXT,
  params        TEXT,
  created_at    INTEGER NOT NULL,
  created_by    TEXT,
  status        TEXT NOT NULL,
  output        TEXT,
  err           TEXT,
  finished_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_commands_agent ON commands(agent_id, created_at DESC);
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,
  actor         TEXT NOT NULL,
  action        TEXT NOT NULL,
  target        TEXT,
  detail        TEXT,
  ip            TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE TABLE IF NOT EXISTS settings (
  k             TEXT PRIMARY KEY,
  v             TEXT NOT NULL,
  updated_at    INTEGER NOT NULL
);
`)
	if err != nil {
		return err
	}
	// 老库兼容: 若 tokens 缺列则补上(忽略重复列报错)。
	_, _ = s.db.Exec(`ALTER TABLE tokens ADD COLUMN token_prefix TEXT`)
	_, _ = s.db.Exec(`ALTER TABLE tokens ADD COLUMN bound_agent_id TEXT`)
	return nil
}

// Close 关闭底层数据库。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// TokenCount 返回未撤销的 token 数量。
func (s *Store) TokenCount() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE revoked=0`).Scan(&n)
	return n, err
}

// EnsureToken 若 token 不存在则登记。token 原文会被 sha256 后入库，DB 中不留明文。
// boundAgentID 非空时同时写入绑定关系（首次即锁死到该 agent）。
func (s *Store) EnsureToken(rawToken, note, boundAgentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := HashToken(rawToken)
	prefix := tokenPrefix(rawToken)
	_, err := s.db.Exec(`INSERT OR IGNORE INTO tokens(token, token_prefix, note, created_at, bound_agent_id) VALUES(?,?,?,?,?)`,
		h, prefix, note, time.Now().Unix(), boundAgentID)
	return err
}

// ListTokensPaged 分页返回 token 信息与总数。含 bound_agent_id。
func (s *Store) ListTokensPaged(page, pageSize int) ([]TokenRow, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 200
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(`SELECT token, COALESCE(token_prefix,''), note, created_at, revoked, COALESCE(bound_agent_id,'') FROM tokens ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []TokenRow
	for rows.Next() {
		var t TokenRow
		var created int64
		var revoked int
		if err := rows.Scan(&t.Token, &t.Prefix, &t.Note, &created, &revoked, &t.BoundAgentID); err != nil {
			return nil, 0, err
		}
		t.CreatedAt = time.Unix(created, 0)
		t.Revoked = revoked == 1
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// DeleteToken 硬删除一个 token。仅允许删除已 revoked 的 token (避免误删活跃凭据)。
// 参数支持原始 token 或其哈希。
func (s *Store) DeleteToken(tokenOrHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := tokenOrHash
	if len(h) != 64 {
		h = HashToken(tokenOrHash)
	}
	var revoked int
	err := s.db.QueryRow(`SELECT revoked FROM tokens WHERE token=?`, h).Scan(&revoked)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if revoked == 0 {
		return fmt.Errorf("token not revoked, refuse delete")
	}
	_, err = s.db.Exec(`DELETE FROM tokens WHERE token=?`, h)
	return err
}

// BoundAgentIDForToken 返回某 token 哈希所绑定的 agent_id；未绑定返回空。
func (s *Store) BoundAgentIDForToken(tokenHash string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b sql.NullString
	_ = s.db.QueryRow(`SELECT bound_agent_id FROM tokens WHERE token=?`, tokenHash).Scan(&b)
	return b.String
}

// CheckTokenBindAgent 校验原始 token 与 agent_id 的绑定关系。
// 返回 (bound, unbound, boundTo, err):
//   - bound=true: 允许该 agent 使用此 token
//   - unbound=true: 该 token 尚未绑定到任何 agent(开放模式), 调用方可决定是否首次锁定
//
// 规则:
//   - token 不存在/已撤销: bound=false, unbound=false
//   - bound_agent_id 为空: bound=true, unbound=true
//   - bound_agent_id == agentID: bound=true, unbound=false
//   - 否则(冒名): bound=false, unbound=false
func (s *Store) CheckTokenBindAgent(rawToken, agentID string) (bound bool, unbound bool, boundTo string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := HashToken(rawToken)
	var revoked int
	var existing sql.NullString
	err = s.db.QueryRow(`SELECT revoked, bound_agent_id FROM tokens WHERE token=?`, h).Scan(&revoked, &existing)
	if err == sql.ErrNoRows {
		return false, false, "", nil
	}
	if err != nil {
		return false, false, "", err
	}
	if revoked == 1 {
		return false, false, "", nil
	}
	if !existing.Valid || existing.String == "" {
		// 未绑定: 允许任意 agent_id(开放模式), 由上层决定是否首次锁定
		return true, true, "", nil
	}
	if existing.String == agentID {
		return true, false, existing.String, nil
	}
	// 冒名: 拒绝并暴露原绑定 agent_id 供审计
	return false, false, existing.String, nil
}

// BindToken 主动把一个 token 绑定到指定 agent_id。tokenOrHash 支持原始或哈希。
func (s *Store) BindToken(tokenOrHash, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := tokenOrHash
	if len(h) != 64 {
		h = HashToken(tokenOrHash)
	}
	_, err := s.db.Exec(`UPDATE tokens SET bound_agent_id=? WHERE token=?`, agentID, h)
	return err
}

// RevokeToken 撤销一个 token。参数为原始 token 或其哈希都支持；同时把对应 agent 置离线。
func (s *Store) RevokeToken(tokenOrHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := tokenOrHash
	if len(h) != 64 {
		h = HashToken(tokenOrHash)
	}
	_, err := s.db.Exec(`UPDATE tokens SET revoked=1 WHERE token=?`, h)
	if err != nil {
		return err
	}
	// agent 表里 token 字段存的是原始 token(便于归属查询), 这里撤销时把所有用此 token 的 agent 置离线
	_, _ = s.db.Exec(`UPDATE agents SET online=0 WHERE token=?`, h)
	return nil
}

// ValidToken 校验原始 token 是否存在且未撤销。
func (s *Store) ValidToken(rawToken string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := HashToken(rawToken)
	var revoked int
	err := s.db.QueryRow(`SELECT revoked FROM tokens WHERE token=?`, h).Scan(&revoked)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return revoked == 0, nil
}

// TokenHashForAgent 返回与该原始 token 对应的哈希，用于 agents 表 token 字段去标识存储。
func (s *Store) TokenHashForAgent(rawToken string) string { return HashToken(rawToken) }

// tokenPrefix 取原始 token 前 8 位作为 UI 识别用。
func tokenPrefix(raw string) string {
	if len(raw) <= 8 {
		return raw
	}
	return raw[:8]
}

// TouchAgent 注册/续约一个 agent。token 原文会被哈希后入库，agents 表不留明文。
func (s *Store) TouchAgent(agentID, rawToken, hostname, osName, ip string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM agents WHERE agent_id=?`, agentID).Scan(&exists)
	first := false
	if err == sql.ErrNoRows {
		first = true
		err = nil
	}
	if err != nil {
		return false, err
	}
	h := HashToken(rawToken)
	_, err = s.db.Exec(`INSERT INTO agents(agent_id, token, hostname, os, ip, last_seen, online)
		VALUES(?,?,?,?,?,?,1)
		ON CONFLICT(agent_id) DO UPDATE SET
		  token=excluded.token,
		  hostname=COALESCE(NULLIF(excluded.hostname,''), agents.hostname),
		  os=COALESCE(NULLIF(excluded.os,''), agents.os),
		  ip=excluded.ip,
		  last_seen=excluded.last_seen,
		  online=1`,
		agentID, h, hostname, osName, ip, time.Now().Unix())
	return first, err
}

// SetAgentTags 设置 agent 的标签（覆盖式）。
func (s *Store) SetAgentTags(agentID string, tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE agents SET tags=? WHERE agent_id=?`,
		strings.Join(tags, ","), agentID)
	return err
}

// SetAgentNotes 设置 agent 备注。
func (s *Store) SetAgentNotes(agentID, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE agents SET notes=? WHERE agent_id=?`, notes, agentID)
	return err
}

func (s *Store) OfflineAgent(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE agents SET online=0 WHERE agent_id=?`, agentID)
	return err
}

// SweepStaleAgents 把 last_seen 超过 timeout 仍标记 online=1 的 agent 置离线，
// 返回被置离线的 agent_id 列表。用于弥补 agent 没有 TCP FIN 就掉线的场景。
func (s *Store) SweepStaleAgents(timeout time.Duration) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	threshold := time.Now().Add(-timeout).Unix()
	rows, err := s.db.Query(`SELECT agent_id FROM agents WHERE online=1 AND last_seen < ?`, threshold)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		_, _ = s.db.Exec(`UPDATE agents SET online=0 WHERE agent_id=? AND online=1`, id)
	}
	return ids, nil
}

func (s *Store) MarkSeen(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE agents SET last_seen=?, online=1 WHERE agent_id=?`, time.Now().Unix(), agentID)
	return err
}

// GetAgent 返回单个 agent 详情。
func (s *Store) GetAgent(agentID string) (*AgentRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var a AgentRow
	var ls int64
	var online int
	var tags, notes, ip sql.NullString
	err := s.db.QueryRow(`SELECT agent_id, token, hostname, os, ip, tags, notes, last_seen, online FROM agents WHERE agent_id=?`, agentID).
		Scan(&a.AgentID, &a.Token, &a.Hostname, &a.OS, &ip, &tags, &notes, &ls, &online)
	if err != nil {
		return nil, err
	}
	if tags.Valid && tags.String != "" {
		a.Tags = strings.Split(tags.String, ",")
	}
	a.Notes = notes.String
	a.IP = ip.String
	a.LastSeen = time.Unix(ls, 0)
	a.Online = online == 1
	return &a, nil
}

// SaveCmd 写入下发指令（初始 pending）。params 中的 password 字段会被剔除，明文密码不落库。
func (s *Store) SaveCmd(c *StoredCmd) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sanitized := sanitizeParams(c.Params)
	params, _ := json.Marshal(sanitized)
	_, err := s.db.Exec(`INSERT INTO commands(id, agent_id, action, user, params, created_at, created_by, status)
		VALUES(?,?,?,?,?,?,?,?)`,
		c.ID, c.AgentID, c.Action, c.User, string(params), time.Now().Unix(), c.CreatedBy, "pending")
	return err
}

// sanitizeParams 返回不含敏感字段(password)的副本, 仅供落库审计使用。
func sanitizeParams(p map[string]string) map[string]string {
	if p == nil {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		if k == "password" {
			out[k] = "<redacted>"
			continue
		}
		out[k] = v
	}
	return out
}

// FinishCmd 写入 agent 回执。
func (s *Store) FinishCmd(id string, r *ResultBody) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE commands SET status=?, output=?, err=?, finished_at=? WHERE id=?`,
		boolStatus(r.OK), r.Output, r.Err, time.Now().Unix(), id)
	return err
}

// TimeoutCmd 把未完成指令标记为超时。
func (s *Store) TimeoutCmd(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE commands SET status='timeout', err='agent no response within timeout', finished_at=? WHERE id=? AND status='pending'`,
		time.Now().Unix(), id)
	return err
}

// SweepTimeouts 扫描超过 timeout 仍 pending 的指令并标记为 timeout，返回被超时的 id 列表。
func (s *Store) SweepTimeouts(timeout time.Duration) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	threshold := time.Now().Add(-timeout).Unix()
	rows, err := s.db.Query(`SELECT id FROM commands WHERE status='pending' AND created_at < ?`, threshold)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		_, _ = s.db.Exec(`UPDATE commands SET status='timeout', err='no response', finished_at=? WHERE id=? AND status='pending'`,
			time.Now().Unix(), id)
	}
	return ids, nil
}

// ListAgentsPaged 分页返回 agent 列表与总数。page 从 1 起, pageSize<=0 取 200。
// q 非空时按 hostname/ip/agent_id/tags 模糊过滤。
func (s *Store) ListAgentsPaged(page, pageSize int, q string) ([]AgentRow, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 200
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	where := ""
	args := []interface{}{}
	if q != "" {
		where = " WHERE (hostname LIKE ? OR ip LIKE ? OR agent_id LIKE ? OR COALESCE(tags,'') LIKE ?)"
		p := "%" + q + "%"
		args = append(args, p, p, p, p)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM agents"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)
	rows, err := s.db.Query("SELECT agent_id, token, hostname, os, ip, COALESCE(tags,''), COALESCE(notes,''), last_seen, online FROM agents"+
		where+" ORDER BY online DESC, hostname LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AgentRow
	for rows.Next() {
		var a AgentRow
		var ls int64
		var online int
		var tags, notes, ip sql.NullString
		if err := rows.Scan(&a.AgentID, &a.Token, &a.Hostname, &a.OS, &ip, &tags, &notes, &ls, &online); err != nil {
			return nil, 0, err
		}
		if tags.Valid && tags.String != "" {
			a.Tags = strings.Split(tags.String, ",")
		}
		a.Notes = notes.String
		a.IP = ip.String
		a.LastSeen = time.Unix(ls, 0)
		a.Online = online == 1
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// DeleteAgent 硬删除一个 agent 记录(含其命令历史一并清除以释放空间)。
// 安全前置: 仅允许删除当前 online=0 的 agent, 避免误删活会话。
// 返回 (deleted bool, err error)。
func (s *Store) DeleteAgent(agentID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var online int
	err := s.db.QueryRow(`SELECT online FROM agents WHERE agent_id=?`, agentID).Scan(&online)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if online == 1 {
		return false, fmt.Errorf("agent online, refuse delete")
	}
	// 不要保留已删 agent 的命令历史(无主), 否则破坏归属完整性
	_, _ = s.db.Exec("DELETE FROM commands WHERE agent_id=?", agentID)
	_, err = s.db.Exec("DELETE FROM agents WHERE agent_id=?", agentID)
	return err == nil, err
}

// HostnameOf 返回 agent_id 对应 hostname, 找不到返回空。
func (s *Store) HostnameOf(agentID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var h sql.NullString
	_ = s.db.QueryRow("SELECT hostname FROM agents WHERE agent_id=?", agentID).Scan(&h)
	return h.String
}

// ListCmdsPaged 分页返回指令列表与总数。page 从 1 起。
func (s *Store) ListCmdsPaged(page, pageSize int, agentID string) ([]CmdRow, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 200
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	where := ""
	args := []interface{}{}
	if agentID != "" {
		where = " WHERE agent_id = ?"
		args = append(args, agentID)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM commands"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)
	q := `SELECT id, agent_id, action, user, created_at, status, COALESCE(output,''), COALESCE(err,''), COALESCE(finished_at,0), COALESCE(created_by,'') FROM commands` +
		where + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []CmdRow
	for rows.Next() {
		var c CmdRow
		var created, finished int64
		if err := rows.Scan(&c.ID, &c.AgentID, &c.Action, &c.User, &created, &c.Status, &c.Output, &c.Err, &finished, &c.CreatedBy); err != nil {
			return nil, 0, err
		}
		c.CreatedAt = time.Unix(created, 0)
		if finished > 0 {
			c.FinishedAt = time.Unix(finished, 0)
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// GetCmd 按 id 直接取单条指令，避免 ListCmds 全表扫描。
func (s *Store) GetCmd(id string) (*CmdRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var c CmdRow
	var created, finished int64
	err := s.db.QueryRow(`SELECT id, agent_id, action, user, created_at, status, COALESCE(output,''), COALESCE(err,''), COALESCE(finished_at,0), COALESCE(created_by,'') FROM commands WHERE id=?`, id).
		Scan(&c.ID, &c.AgentID, &c.Action, &c.User, &created, &c.Status, &c.Output, &c.Err, &finished, &c.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = time.Unix(created, 0)
	if finished > 0 {
		c.FinishedAt = time.Unix(finished, 0)
	}
	return &c, nil
}

// Audit 记录一条审计日志。
func (s *Store) Audit(actor, action, target, detail, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO audit_log(ts, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)`,
		time.Now().Unix(), actor, action, target, detail, ip)
	return err
}

// AuditFilter 描述审计日志查询条件；空字段不过滤。
type AuditFilter struct {
	Page     int    // 从 1 起
	PageSize int    // <=0 取 200
	Actor    string // 精确匹配
	Action   string // 精确匹配
	Target   string // LIKE %target%
	Q        string // 全文 LIKE (actor/action/target/detail 之一含)
	From     int64  // 起始时间 unix；0 不限
	To       int64  // 结束时间 unix；0 不限
}

func (f *AuditFilter) normalize() {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 200
	}
	if f.PageSize > 1000 {
		f.PageSize = 1000
	}
}

// ListAuditPaged 按条件分页返回审计日志与总数。
func (s *Store) ListAuditPaged(f AuditFilter) ([]AuditRow, int, error) {
	f.normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	where := " WHERE 1=1"
	args := []interface{}{}
	if f.Actor != "" {
		where += " AND actor=?"
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		where += " AND action=?"
		args = append(args, f.Action)
	}
	if f.Target != "" {
		where += " AND target LIKE ?"
		args = append(args, "%"+f.Target+"%")
	}
	if f.Q != "" {
		where += " AND (actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ?)"
		p := "%" + f.Q + "%"
		args = append(args, p, p, p, p)
	}
	if f.From > 0 {
		where += " AND ts>=?"
		args = append(args, f.From)
	}
	if f.To > 0 {
		where += " AND ts<=?"
		args = append(args, f.To)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (f.Page - 1) * f.PageSize
	args = append(args, f.PageSize, offset)
	q := "SELECT id, ts, actor, action, COALESCE(target,''), COALESCE(detail,''), COALESCE(ip,'') FROM audit_log" +
		where + " ORDER BY ts DESC LIMIT ? OFFSET ?"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var a AuditRow
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.IP); err != nil {
			return nil, 0, err
		}
		a.Ts = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// AuditActions 返回 audit_log 中出现过的所有动作类型(SELECT DISTINCT)。
func (s *Store) AuditActions() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SettingGet / SettingSet 提供简单键值存储，用于 admin password 等。
func (s *Store) SettingGet(k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v string
	err := s.db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SettingSet(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO settings(k, v, updated_at) VALUES(?,?,?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at`,
		k, v, time.Now().Unix())
	return err
}

func boolStatus(ok bool) string {
	if ok {
		return "done"
	}
	return "failed"
}

// ---- 数据结构 ----

type StoredCmd struct {
	ID        string
	AgentID   string
	Action    string
	User      string
	Params    map[string]string
	CreatedBy string
}

type ResultBody struct {
	Output string
	Err    string
	OK     bool
}

type AgentRow struct {
	AgentID  string    `json:"agent_id"`
	Token    string    `json:"token"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	IP       string    `json:"ip"`
	Tags     []string  `json:"tags"`
	Notes    string    `json:"notes"`
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen"`
}

type CmdRow struct {
	ID         string    `json:"id"`
	AgentID    string    `json:"agent_id"`
	Action     string    `json:"action"`
	User       string    `json:"user"`
	Status     string    `json:"status"`
	Output     string    `json:"output"`
	Err        string    `json:"err"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	CreatedBy  string    `json:"created_by,omitempty"`
}

type TokenRow struct {
	Token         string    `json:"token"`  // 哈希, 不可回推明文
	Prefix        string    `json:"prefix"` // 原始 token 前 8 位, 供 UI 辨识
	Note          string    `json:"note"`
	Revoked       bool      `json:"revoked"`
	CreatedAt     time.Time `json:"created_at"`
	BoundAgentID  string    `json:"bound_agent_id,omitempty"` // 绑定的 agent_id; 空表示开放
	BoundHostname string    `json:"bound_hostname,omitempty"` // 绑定主机的 hostname(供 UI 直接显示)
}

type AuditRow struct {
	ID     int64     `json:"id"`
	Ts     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

// keep fmt import (used indirectly through tests / future)
var _ = fmt.Sprintf
