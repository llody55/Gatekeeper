package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashToken 把 agent 预共享 token 不可逆地存入 SQLite: sha256 hex。
// 这样即使数据库泄露，攻击者也无法直接用表里的值冒充 agent。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// HashPassword 用 bcrypt 哈希管理员口令，cost=10。
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	return string(b), err
}

// CheckPassword 比对明文口令与 bcrypt 哈希。
func CheckPassword(hashed, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(pw)) == nil
}
