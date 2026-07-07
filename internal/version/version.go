// Package version 集中管理 Gatekeeper 的版本号, 供 server / agent / UI / Makefile 共享。
//
// 默认 VERSION 由本文件常量给出; 构建时可通过 -ldflags "-X gatekeeper/internal/version.VERSION=x.y.z" 注入,
// 这样 Makefile 读 VERSION 文件再传给 go build, 不必每次发版改源码。
package version

// VERSION 是当前发布版本号, 与仓库根目录 VERSION 文件保持一致。
// 修改版本请同时更新 VERSION 文件(由 Makefile 注入覆盖此默认值)。
const VERSION = "0.5.0"

// String 返回版本号字符串, 供 log / API / UI 引用。
func String() string { return VERSION }
