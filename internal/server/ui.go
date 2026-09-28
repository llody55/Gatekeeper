package server

import (
	"embed"
	"io/fs"
	"net/http"
)

/* 前端资源采用 go:embed 内嵌，源码位于 web/ 目录：
 *   web/index.html          SPA 外壳
 *   web/css/style.css       企业级设计系统
 *   web/js/api.js           统一请求层
 *   web/js/components.js    通用组件（弹窗 / Toast / 分页等）
 *   web/js/views/*.js       各业务视图
 */

//go:embed web
var webAssets embed.FS

// serveUI 返回内置的单页管理界面。
func serveUI(w http.ResponseWriter, _ *http.Request) {
	data, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui assets not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// staticHandler 提供前端静态资源（CSS/JS），URL 前缀 /static/。
func staticHandler() http.Handler {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "static assets not found", http.StatusInternalServerError)
		})
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
