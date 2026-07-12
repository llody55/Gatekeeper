// Package version 集中管理 Gatekeeper 的版本号, 供 server / agent / UI / Makefile 共享。
//
// 默认 VERSION 由本文件变量给出; 构建时通过 -ldflags "-X gatekeeper/internal/version.VERSION=x.y.z" 注入,
// 这样 Makefile 读 VERSION 文件再传给 go build, 不必每次发版改源码。
package version

// VERSION 是当前发布版本号, 与仓库根目录 VERSION 文件保持一致。
// 使用 var 而非 const, 以便 -ldflags -X 在构建时注入覆盖。
// 修改版本只需更新 VERSION 文件, make build 会自动注入。
var VERSION = "0.6.0"

// String 返回版本号字符串, 供 log / API / UI 引用。
func String() string { return VERSION }
