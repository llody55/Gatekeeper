package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// reSafeID 只保留字母/数字/点/下划线/连字符，与 server 端 validAgentID 白名单一致。
var reSafeID = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// loadOrCreateAgentID 读取持久化文件；不存在则生成并写入(权限 0600)。
// path 为空则使用 ~/.gatekeeper/agent_id。
// 优先级: 显式传入(命令行/配置) > 文件 > 现场生成。
func loadOrCreateAgentID(path string) (string, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/root"
		}
		path = filepath.Join(home, ".gatekeeper", "agent_id")
	}

	// 1) 已存在则读
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}

	// 2) 生成并写
	id, err := generateAgentID()
	if err != nil {
		return "", err
	}
	if err := writeAgentIDFile(path, id); err != nil {
		// 写失败不致命，本次先用内存里的 id
		return id, nil
	}
	return id, nil
}

// generateAgentID 生成 hostname-随机 的稳定 id。
// hostname 中的非白名单字符会被替换为 -，确保与 server 端 validAgentID 兼容。
func generateAgentID() (string, error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "host"
	}
	host = reSafeID.ReplaceAllString(host, "-")
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", host, hex.EncodeToString(b)), nil
}

func writeAgentIDFile(path, id string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// 原子写: tmp + rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
