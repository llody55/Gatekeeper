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
CREATE INDEX IF NOT EXISTS idx_audit_actor_action_ts ON audit_log(actor, action, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);
CREATE TABLE IF NOT EXISTS settings (
  k             TEXT PRIMARY KEY,
  v             TEXT NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'operator', -- admin / operator / auditor
  created_at    INTEGER NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS shell_rules (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  type          TEXT NOT NULL,           -- 'whitelist' 或 'blacklist'
  pattern       TEXT NOT NULL,           -- glob 匹配模式, * 匹配任意字符
  note          TEXT,                    -- 可选说明
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shell_rules_type ON shell_rules(type, enabled);
`)
	if err != nil {
		return err
	}
	// 老库兼容: 若 tokens 缺列则补上(忽略重复列报错)。
	_, _ = s.db.Exec(`ALTER TABLE tokens ADD COLUMN token_prefix TEXT`)
	_, _ = s.db.Exec(`ALTER TABLE tokens ADD COLUMN bound_agent_id TEXT`)

	// v0.7: 账户巡检记录表
	s.db.Exec(`CREATE TABLE IF NOT EXISTS account_scans (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id        TEXT NOT NULL,
		username        TEXT NOT NULL,
		uid             INTEGER NOT NULL DEFAULT 0,
		status          TEXT NOT NULL DEFAULT 'unknown',
		last_change     TEXT NOT NULL DEFAULT '',
		expire_date     TEXT NOT NULL DEFAULT '',
		password_expire TEXT NOT NULL DEFAULT '',
		inactive_days   INTEGER NOT NULL DEFAULT 0,
		min_days        INTEGER NOT NULL DEFAULT 0,
		max_days        INTEGER NOT NULL DEFAULT 0,
		warn_days       INTEGER NOT NULL DEFAULT 0,
		scan_ts         INTEGER NOT NULL DEFAULT 0
	)`)
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_account_scans_agent ON account_scans(agent_id)`)
	s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_account_scans_status ON account_scans(status)`)
	s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_account_scans_unique ON account_scans(agent_id, username)`)
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
	prefix := TokenPrefix(rawToken)
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
		return fmt.Errorf("token not found")
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

// TokenPrefix 取原始 token 前 8 位作为 UI 识别用, 不暴露完整 token。
func TokenPrefix(raw string) string {
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

// GetAgentByID 按 agent_id 取一行, 不存在返回 (nil, nil)。
func (s *Store) GetAgentByID(agentID string) (*AgentRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var a AgentRow
	var ls sql.NullInt64
	var tags sql.NullString
	err := s.db.QueryRow(`SELECT agent_id, hostname, ip, online, last_seen, COALESCE(tags,'') FROM agents WHERE agent_id=?`, agentID).
		Scan(&a.AgentID, &a.Hostname, &a.IP, &a.Online, &ls, &tags)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ls.Valid {
		a.LastSeen = time.Unix(ls.Int64, 0)
	}
	if tags.Valid && tags.String != "" {
		a.Tags = strings.Split(tags.String, ",")
	}
	return &a, nil
}

// ListAgentsStale 返回 last_seen 早于 cutoff 的 agent(不论 online 列), 用于告警扫描。
// audit_log 路径不调用此函数; 仅 alert checker 用。
func (s *Store) ListAgentsStale(cutoff time.Time) ([]AgentRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT agent_id, hostname, ip, online, last_seen, COALESCE(tags,'') FROM agents WHERE last_seen < ?`, cutoff.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentRow
	for rows.Next() {
		var a AgentRow
		var ls sql.NullInt64
		var tags sql.NullString
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.Online, &ls, &tags); err != nil {
			return nil, err
		}
		if ls.Valid {
			a.LastSeen = time.Unix(ls.Int64, 0)
		}
		if tags.Valid && tags.String != "" {
			a.Tags = strings.Split(tags.String, ",")
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAgentsSeenSince 返回 last_seen >= since 的 agent, 用于告警恢复扫描。
func (s *Store) ListAgentsSeenSince(since time.Time) ([]AgentRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT agent_id, hostname, ip, online, last_seen, COALESCE(tags,'') FROM agents WHERE last_seen >= ?`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentRow
	for rows.Next() {
		var a AgentRow
		var ls sql.NullInt64
		var tags sql.NullString
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.Online, &ls, &tags); err != nil {
			return nil, err
		}
		if ls.Valid {
			a.LastSeen = time.Unix(ls.Int64, 0)
		}
		if tags.Valid && tags.String != "" {
			a.Tags = strings.Split(tags.String, ",")
		}
		out = append(out, a)
	}
	return out, rows.Err()
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

// ListCmdsPaged 分页返回指令列表与总数。page 从 1 起。actionFilter 为空表示不限。
func (s *Store) ListCmdsPaged(page, pageSize int, agentID, actionFilter string) ([]CmdRow, int, error) {
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
	if actionFilter != "" {
		if where == "" {
			where = " WHERE action = ?"
		} else {
			where += " AND action = ?"
		}
		args = append(args, actionFilter)
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

// DeleteSessionsByActor 清除指定用户的所有活跃会话。
// 用于改密/禁用/删除用户时即时吊销既有 session, 防止被禁用户继续操作。
// 安全: 使用 escapeLike 转义通配符，防止 username 中的 %/_ 扩大匹配范围；
// 同时通过应用层 validUsername 白名单已杜绝 | 字符，确保 LIKE 精确匹配。
func (s *Store) DeleteSessionsByActor(actor string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// v 格式: "username|role|expires"，用 LIKE "actor|%" 匹配以 actor| 开头的行。
	// escapeLike 转义 actor 中的 % 和 _，防止 LIKE 通配符注入。
	rows, err := s.db.Query(`SELECT k FROM settings WHERE k LIKE 'session:%' AND v LIKE ? ESCAPE '\'`,
		escapeLike(actor)+"|%")
	if err != nil {
		return
	}
	var keys []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			keys = append(keys, k)
		}
	}
	rows.Close()
	for _, k := range keys {
		_, _ = s.db.Exec(`DELETE FROM settings WHERE k=?`, k)
	}
}

// escapeLike 转义 SQLite LIKE 中的通配符 % 和 _，防止 LIKE 注入。
// 使用 \ 作为 ESCAPE 字符，需与查询中的 ESCAPE '\' 配合。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// ---- 用户与 RBAC ----

// UserRow 描述一个管理端用户(admin/operator/auditor)。
type UserRow struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt int64  `json:"created_at"`
}

// CreateUser 创建用户; username 唯一, password 已被 bcrypt 哈希。
func (s *Store) CreateUser(username, passwordHash, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if role == "" {
		role = "operator"
	}
	_, err := s.db.Exec(`INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)`,
		username, passwordHash, role, time.Now().Unix())
	return err
}

// GetUser 按 username 取一个用户(含 password_hash)。
func (s *Store) GetUser(username string) (*UserRow, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var u UserRow
	var created int64
	var disabled int
	var hash string
	err := s.db.QueryRow(`SELECT id, username, password_hash, role, created_at, disabled FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &hash, &u.Role, &created, &disabled)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	u.Disabled = disabled == 1
	u.CreatedAt = created
	return &u, hash, nil
}

// ListUsers 列出所有用户(不含 password_hash)。
func (s *Store) ListUsers() ([]UserRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, username, role, created_at, disabled FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		var created int64
		var disabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &created, &disabled); err != nil {
			return nil, err
		}
		u.Disabled = disabled == 1
		u.CreatedAt = created
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserPassword 更新某用户口令哈希。
func (s *Store) SetUserPassword(username, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE username=?`, passwordHash, username)
	return err
}

// SetUserDisabled 启用/禁用某用户。
func (s *Store) SetUserDisabled(username string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := 0
	if disabled {
		d = 1
	}
	_, err := s.db.Exec(`UPDATE users SET disabled=? WHERE username=?`, d, username)
	return err
}

// DeleteUser 硬删除用户。
func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM users WHERE username=?`, username)
	return err
}

// CountAdmins 返回未禁用的 admin 用户数(用于防止删除最后一个 admin)。
func (s *Store) CountAdmins() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0`).Scan(&n)
	return n, err
}

// PurgeOlderThan 删除 audit_log/commands 中早于 cutoff 的记录, 返回各自删除条数。
// 用于实现 history_retention 双层下限锁: 由 caller 计算最终 cutoff 后调用。
func (s *Store) PurgeOlderThan(cutoff time.Time) (auditRows, cmdRows int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := cutoff.Unix()
	r, e := s.db.Exec(`DELETE FROM audit_log WHERE ts < ?`, c)
	if e != nil {
		return 0, 0, e
	}
	auditRows, _ = r.RowsAffected()
	r, e = s.db.Exec(`DELETE FROM commands WHERE created_at < ?`, c)
	if e != nil {
		return auditRows, 0, e
	}
	cmdRows, _ = r.RowsAffected()
	return auditRows, cmdRows, nil
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

// ---- Shell 规则管理 ----

// ShellRule 描述一条 shell 黑/白名单规则。
type ShellRule struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`    // whitelist / blacklist
	Pattern   string    `json:"pattern"` // glob 匹配模式
	Note      string    `json:"note"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListShellRules 返回指定类型的规则列表; enabledOnly=true 时只返回启用的规则。
func (s *Store) ListShellRules(ruleType string, enabledOnly bool) ([]ShellRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := `SELECT id, type, pattern, COALESCE(note,''), enabled, created_at, updated_at FROM shell_rules`
	args := []interface{}{}
	if ruleType != "" {
		q += ` WHERE type=?`
		args = append(args, ruleType)
	}
	if enabledOnly {
		if len(args) > 0 {
			q += ` AND enabled=1`
		} else {
			q += ` WHERE enabled=1`
		}
	}
	q += ` ORDER BY type, id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShellRule
	for rows.Next() {
		var r ShellRule
		var enabled, created, updated int64
		if err := rows.Scan(&r.ID, &r.Type, &r.Pattern, &r.Note, &enabled, &created, &updated); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		r.CreatedAt = time.Unix(created, 0)
		r.UpdatedAt = time.Unix(updated, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddShellRule 新增一条规则。type 必须为 whitelist 或 blacklist。
func (s *Store) AddShellRule(ruleType, pattern, note string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO shell_rules(type, pattern, note, enabled, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
		ruleType, pattern, note, 1, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateShellRule 更新一条规则的 pattern/note/enabled。
func (s *Store) UpdateShellRule(id int64, pattern, note string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := 0
	if enabled {
		e = 1
	}
	_, err := s.db.Exec(`UPDATE shell_rules SET pattern=?, note=?, enabled=?, updated_at=? WHERE id=?`,
		pattern, note, e, time.Now().Unix(), id)
	return err
}

// DeleteShellRule 硬删除一条规则。
func (s *Store) DeleteShellRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM shell_rules WHERE id=?`, id)
	return err
}

// CountShellRules 返回 shell_rules 表总行数, 用于判断是否需要种子默认数据。
func (s *Store) CountShellRules() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM shell_rules`).Scan(&n)
	return n, err
}

// SeedShellRules 在 shell_rules 表为空时插入默认黑白名单。
func (s *Store) SeedShellRules() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM shell_rules`).Scan(&n); err != nil {
		return fmt.Errorf("seed: count shell_rules: %w", err)
	}
	if n > 0 {
		return nil
	}
	now := time.Now().Unix()
	// 默认白名单: 常用安全只读/运维命令
	whitelist := []struct{ pattern, note string }{
		{"systemctl status *", "查看服务状态"},
		{"systemctl restart *", "重启服务"},
		{"systemctl start *", "启动服务"},
		{"systemctl stop *", "停止服务"},
		{"journalctl *", "查看日志"},
		{"df *", "查看磁盘"},
		{"free *", "查看内存"},
		{"ps *", "查看进程"},
		{"netstat *", "查看网络连接"},
		{"ss *", "查看 socket"},
		{"tail *", "查看日志尾部"},
		{"head *", "查看文件头部"},
		{"cat /etc/*", "查看配置文件"},
		{"ls *", "列出目录"},
		{"ping *", "网络连通性测试"},
		{"uptime", "系统负载"},
		{"uname *", "系统信息"},
		{"hostname", "主机名"},
		{"ip *", "网络接口信息"},
		{"dmesg *", "内核日志"},
		{"who", "登录用户"},
		{"w", "登录用户详情"},
		{"date", "系统时间"},
	}
	// 默认黑名单: 危险操作
	blacklist := []struct{ pattern, note string }{
		{"rm -rf /*", "递归删除根目录"},
		{"rm -rf /", "递归删除根目录"},
		{"rm -rf *", "递归删除当前目录所有文件"},
		{"shutdown*", "关机"},
		{"reboot*", "重启"},
		{"halt*", "停机"},
		{"init *", "切换运行级别"},
		{"mkfs*", "格式化文件系统"},
		{"dd *of=/dev/*", "写入块设备"},
		{"chmod -R * / *", "递归修改根目录权限"},
		{"chown -R * / *", "递归修改根目录属主"},
		{" :* ", "fork bomb"},
		{"> /dev/sda*", "写入块设备"},
		{"mv /* /dev/null", "将根目录移入黑洞"},
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("seed: begin tx: %w", err)
	}
	for _, r := range whitelist {
		if _, err := tx.Exec(`INSERT INTO shell_rules(type, pattern, note, enabled, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
			"whitelist", r.pattern, r.note, 1, now, now); err != nil {
			tx.Rollback()
			return fmt.Errorf("seed: insert whitelist %q: %w", r.pattern, err)
		}
	}
	for _, r := range blacklist {
		if _, err := tx.Exec(`INSERT INTO shell_rules(type, pattern, note, enabled, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
			"blacklist", r.pattern, r.note, 1, now, now); err != nil {
			tx.Rollback()
			return fmt.Errorf("seed: insert blacklist %q: %w", r.pattern, err)
		}
	}
	return tx.Commit()
}

// ShellSettingGet 读取 shell 策略设置 (enabled/timeout/max_output), 缺省回退到传入默认值。
func (s *Store) ShellSettingGet(key string, defVal string) string {
	v, err := s.SettingGet("shell_" + key)
	if err != nil || v == "" {
		return defVal
	}
	return v
}

// ---- 账户巡检(account_scans) ----

// AccountScanRow 表示一条账户巡检记录。
type AccountScanRow struct {
	ID             int64  `json:"id"`
	AgentID        string `json:"agent_id"`
	Username       string `json:"username"`
	UID            int    `json:"uid"`
	Status         string `json:"status"`
	LastChange     string `json:"last_change"`
	ExpireDate     string `json:"expire_date"`
	PasswordExpire string `json:"password_expire"`
	InactiveDays   int    `json:"inactive_days"`
	MinDays        int    `json:"min_days"`
	MaxDays        int    `json:"max_days"`
	WarnDays       int    `json:"warn_days"`
	ScanTs         int64  `json:"scan_ts"`
}

// UpsertAccountScan 批量写入/更新账户扫描结果。agent_id+username 唯一约束确保同一主机同一用户只保留最新一条。
func (s *Store) UpsertAccountScan(agentID string, accounts []AccountScanRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for _, a := range accounts {
		a.AgentID = agentID
		a.ScanTs = now
		_, err := s.db.Exec(`INSERT INTO account_scans(agent_id, username, uid, status, last_change, expire_date, password_expire, inactive_days, min_days, max_days, warn_days, scan_ts)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(agent_id, username) DO UPDATE SET
				uid=excluded.uid, status=excluded.status, last_change=excluded.last_change,
				expire_date=excluded.expire_date, password_expire=excluded.password_expire,
				inactive_days=excluded.inactive_days, min_days=excluded.min_days,
				max_days=excluded.max_days, warn_days=excluded.warn_days, scan_ts=excluded.scan_ts`,
			a.AgentID, a.Username, a.UID, a.Status, a.LastChange, a.ExpireDate,
			a.PasswordExpire, a.InactiveDays, a.MinDays, a.MaxDays, a.WarnDays, now)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListAccountScans 返回指定 agent 的账户扫描结果, 可按 status 过滤。
func (s *Store) ListAccountScans(agentID, statusFilter string) ([]AccountScanRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := `SELECT id, agent_id, username, uid, status, last_change, expire_date,
		password_expire, inactive_days, min_days, max_days, warn_days, scan_ts
		FROM account_scans`
	args := []interface{}{}
	cond := ""
	if agentID != "" {
		cond = " WHERE agent_id=?"
		args = append(args, agentID)
	}
	if statusFilter != "" {
		if cond == "" {
			cond = " WHERE status=?"
		} else {
			cond += " AND status=?"
		}
		args = append(args, statusFilter)
	}
	q += cond + " ORDER BY agent_id, username"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountScanRow
	for rows.Next() {
		var r AccountScanRow
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Username, &r.UID, &r.Status,
			&r.LastChange, &r.ExpireDate, &r.PasswordExpire,
			&r.InactiveDays, &r.MinDays, &r.MaxDays, &r.WarnDays, &r.ScanTs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AccountScanSummary 返回全局巡检摘要: 各类状态的账户数量。
type AccountScanSummary struct {
	Total            int `json:"total"`
	Active           int `json:"active"`
	Expired          int `json:"expired"`
	PasswordExpired  int `json:"password_expired"`
	PasswordExpiring int `json:"password_expiring"`
	Expiring         int `json:"expiring"`
	Locked           int `json:"locked"`
	Unknown          int `json:"unknown"`
}

// GetAccountScanSummary 返回全局账户状态汇总。
func (s *Store) GetAccountScanSummary() (AccountScanSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum AccountScanSummary
	count := func(status string) int {
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM account_scans WHERE status=?`, status).Scan(&n)
		return n
	}
	sum.Active = count("active")
	sum.Expired = count("expired")
	sum.PasswordExpired = count("password_expired")
	sum.PasswordExpiring = count("password_expiring")
	sum.Expiring = count("expiring")
	sum.Locked = count("locked")
	sum.Unknown = count("unknown")
	sum.Total = sum.Active + sum.Expired + sum.PasswordExpired + sum.PasswordExpiring + sum.Expiring + sum.Locked + sum.Unknown
	return sum, nil
}

// CleanAccountScans 清理早于 cutoff 的巡检记录。
func (s *Store) CleanAccountScans(cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.db.Exec(`DELETE FROM account_scans WHERE scan_ts < ?`, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
