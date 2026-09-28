package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// HashToken 把 agent 预共享 token 不可逆地存入 SQLite: sha256 hex。
// 这样即使数据库泄露，攻击者也无法直接用表里的值冒充 agent。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// HashSession 对管理端会话 token 做 sha256 哈希后再作为 settings key 存库。
// 与 HashToken 算法一致，确保数据库泄露时无法直接还原 session token 冒充登录。
func HashSession(token string) string {
	return HashToken(token)
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

// ValidatePassword 校验口令复杂度：长度>=8，且大写/小写/数字/特殊字符四类中至少包含三类。
// 返回 (是否合法, 失败原因)。
func ValidatePassword(pw string) (bool, string) {
	if len(pw) < 8 {
		return false, "password must be at least 8 characters"
	}
	var upper, lower, digit, special bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			special = true
		}
	}
	categories := 0
	if upper {
		categories++
	}
	if lower {
		categories++
	}
	if digit {
		categories++
	}
	if special {
		categories++
	}
	if categories < 3 {
		return false, "password must contain at least 3 of: uppercase, lowercase, digit, special character"
	}
	return true, ""
}
