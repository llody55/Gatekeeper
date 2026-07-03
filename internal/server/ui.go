package server

import "net/http"

// serveUI 返回内置的单页管理界面。
func serveUI(w http.ResponseWriter, r *http.Request) {
	html := uiHTML()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func uiHTML() string {
	return "<!doctype html>\n" +
		"<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\n" +
		"<title>Gatekeeper · 账户救援控制台</title>\n" +
		"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n" +
		"<style>\n" +
		uiCSS() +
		"</style></head><body>\n" +
		"<header class=\"top\">\n" +
		"  <div class=\"brand\"><span class=\"logo\"> GK </span><div><b>Gatekeeper</b><span class=\"v\">v0.3 · 在线账户救援</span></div></div>\n" +
		"  <nav class=\"tabs\" id=\"tabs\">\n" +
		"    <button class=\"active\" data-tab=\"agents\">主&shy;机</button>\n" +
		"    <button data-tab=\"rescue\">救&shy;援</button>\n" +
		"    <button data-tab=\"cmd\">指令历史</button>\n" +
		"    <button data-tab=\"audit\">审计日志</button>\n" +
		"    <button data-tab=\"tokens\">Token</button>\n" +
		"  </nav>\n" +
		"  <div class=\"uinfo\" id=\"uinfo\"></div>\n" +
		"</header>\n" +
		"<div id=\"login\" class=\"login hidden\">\n" +
		"  <div class=\"login-card\">\n" +
		"  <div class=\"login-logo\">GK</div>\n" +
		"  <h2>账户救援控制台</h2>\n" +
		"  <p>使用启动日志中的 admin 口令登录</p>\n" +
		"  <input id=\"pw\" type=\"password\" placeholder=\"管理员口令\" autocomplete=\"current-password\" onkeydown=\"if(event.key==='Enter')doLogin()\">\n" +
		"  <button class=\"primary block\" onclick=\"doLogin()\">登&shy;录</button>\n" +
		"  <div id=\"loginErr\" class=\"err\" style=\"margin-top:10px\"></div>\n" +
		"  </div>\n" +
		"</div>\n" +
		"<main id=\"app\" class=\"hidden\">\n" +
		"  <section id=\"tab-agents\" class=\"tab-content\">\n" +
		"    <div class=\"card\">\n" +
		"      <div class=\"card-h\"><h3>被管主机</h3><span class=\"hint\" id=\"agentCount\"></span>\n" +
		"        <div class=\"r\">\n" +
		"          <input id=\"agentSearch\" class=\"grow\" placeholder=\"按 hostname / IP / 标签 过滤\" onkeydown=\"if(event.key==='Enter')agentPage=1;loadAgents()\">\n" +
		"          <button class=\"ghost\" onclick=\"agentPage=1;loadAgents()\">刷新</button>\n" +
		"          <button class=\"ghost\" onclick=\"goBatch()\">批量救援选中</button>\n" +
		"          <button class=\"ok\" onclick=\"tagSelected()\">批量打标签</button>\n" +
		"        </div></div>\n" +
		"      <table class=\"tbl\"><thead><tr><th></th><th>主机</th><th>Token前缀</th><th>IP</th><th>系统</th><th>标签</th><th>备注</th><th>状态</th><th>最近心跳</th><th>操作</th></tr></thead><tbody id=\"agentBody\"></tbody></table>\n" +
		"      <div class=\"pager\" id=\"agentPager\"></div>\n" +
		"    </div>\n" +
		"  </section>\n" +
		"  <section id=\"tab-rescue\" class=\"tab-content hidden\">\n" +
		"    <div class=\"card\">\n" +
		"      <div class=\"card-h\"><h3>账户救援</h3><span class=\"hint\" id=\"rescueTarget\"></span></div>\n" +
		"      <div class=\"grid\">\n" +
		"        <div class=\"field\"><label>目标主机</label><select id=\"agentSel\" class=\"grow\" onchange=\"saveRescueTarget()\"></select></div>\n" +
		"        <div class=\"field\"><label>账户</label><input id=\"userIn\" value=\"root\" style=\"width:120px\"></div>\n" +
		"        <div class=\"field\"><label>动作</label><select id=\"actSel\" onchange=\"onActChange()\">\n" +
		"          <option value=\"combo\">组合救援 (推荐)</option>" +
		"          <option value=\"chage_status\">查看过期状态</option>" +
		"          <option value=\"expire_extend\">关闭密码过期</option>" +
		"          <option value=\"unlock\">解锁账户</option>" +
		"          <option value=\"clear_fail\">清除失败计数</option>" +
		"          <option value=\"reset_password\">重置密码</option>" +
		"        </select></div>\n" +
		"      </div>\n" +
		"      <div class=\"chk-row\" id=\"comboOpts\">\n" +
		"        <label class=\"chk\"><input type=\"checkbox\" id=\"cb_fail\" checked>清失败计数</label>\n" +
		"        <label class=\"chk\"><input type=\"checkbox\" id=\"cb_unlock\" checked>解锁账户</label>\n" +
		"        <label class=\"chk\"><input type=\"checkbox\" id=\"cb_expire\" checked>关闭过期</label>\n" +
		"        <label class=\"chk\"><input type=\"checkbox\" id=\"cb_force\">下次登录强制改密</label>\n" +
		"      </div>\n" +
		"      <div class=\"r\" style=\"margin-top:12px\">\n" +
		"        <div class=\"field\"><label>新密码（可选）</label><input id=\"pwIn\" type=\"text\" placeholder=\"留空则不改密\" style=\"width:220px\"></div>\n" +
		"        <button class=\"primary\" onclick=\"dispatch()\">下&shy;发</button>\n" +
		"        <span class=\"hint\">密码不会被写入数据库(仅内存下发)</span>\n" +
		"      </div>\n" +
		"      <div class=\"hint\" style=\"margin-top:12px\">最近回执：</div>\n" +
		"      <pre id=\"lastOut\">—</pre>\n" +
		"    </div>\n" +
		"  </section>\n" +
		"  <section id=\"tab-cmd\" class=\"tab-content hidden\">\n" +
		"    <div class=\"card\"><div class=\"card-h\"><h3>指令历史</h3><div class=\"r\"><select id=\"cmdAgentFilter\" onchange=\"cmdPage=1;loadCmds()\" style=\"min-width:220px\"></select><button class=\"ghost\" onclick=\"cmdPage=1;loadCmds()\">刷新</button></div></div></div>\n" +
		"    <div class=\"card\"><table class=\"tbl\"><thead><tr><th>时间</th><th>主机</th><th>动作</th><th>账户</th><th>创建者</th><th>状态</th><th>输出</th></tr></thead><tbody id=\"cmdBody\"></tbody></table>\n" +
		"      <div class=\"pager\" id=\"cmdPager\"></div>\n" +
		"    </div>\n" +
		"  </section>\n" +
		"  <section id=\"tab-audit\" class=\"tab-content hidden\">\n" +
		"    <div class=\"card\">\n" +
		"      <div class=\"card-h\"><h3>操作审计</h3><button class=\"ghost\" onclick=\"loadAudit()\">刷新</button></div>\n" +
		"      <div class=\"filter grid4\">\n" +
		"        <div class=\"field\"><label>操作者</label><input id=\"afActor\" placeholder=\"精确\" onkeydown=\"if(event.key==='Enter')loadAudit()\"></div>\n" +
		"        <div class=\"field\"><label>动作</label><select id=\"afAction\"><option value=\"\">全部</option></select></div>\n" +
		"        <div class=\"field\"><label>目标</label><input id=\"afTarget\" placeholder=\"包含\" onkeydown=\"if(event.key==='Enter')loadAudit()\"></div>\n" +
		"        <div class=\"field\"><label>关键字</label><input id=\"afQ\" placeholder=\"全文\" onkeydown=\"if(event.key==='Enter')loadAudit()\"></div>\n" +
		"      </div>\n" +
		"      <div class=\"r\" style=\"margin-top:10px\">\n" +
		"        <div class=\"field\"><label>开始时间</label><input id=\"afFrom\" type=\"datetime-local\"></div>\n" +
		"        <div class=\"field\"><label>结束时间</label><input id=\"afTo\" type=\"datetime-local\"></div>\n" +
		"        <button class=\"primary\" onclick=\"auditPage=1;loadAudit()\">检&shy;索</button>\n" +
		"        <button class=\"ghost\" onclick=\"resetAuditFilter()\">重置</button>\n" +
		"      </div>\n" +
		"      <div class=\"hint\" id=\"auditCount\" style=\"margin-top:8px\"></div>\n" +
		"    </div>\n" +
		"    <div class=\"card\"><table class=\"tbl\"><thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>目标</th><th>详情</th><th>来源IP</th></tr></thead><tbody id=\"auditBody\"></tbody></table>\n" +
		"      <div class=\"pager\" id=\"auditPager\"></div>\n" +
		"    </div>\n" +
		"  </section>\n" +
		"  <section id=\"tab-tokens\" class=\"tab-content hidden\">\n" +
		"    <div class=\"card\">\n" +
		"      <div class=\"card-h\"><h3>Agent Token</h3></div>\n" +
		"      <div class=\"r\"><div class=\"field\"><label>备注</label><input id=\"tokNote\" placeholder=\"哪台机器 / 批次\" style=\"width:240px\"></div><div class=\"field\"><label>绑定主机 agent_id (可选, 创建即绑定)</label><input id=\"tokBind\" placeholder=\"留空则走自动绑定模式\" style=\"width:240px\"></div><button class=\"primary\" onclick=\"genToken()\">生成 Token</button></div>\n" +
		"      <div class=\"hint\">Token 仅在生成时完整显示一次。数据库只存哈希；带绑定时一台 token 只能注册一台 agent，防冒名。撤销后可硬删除。</div>\n" +
		"      <pre id=\"tokOut\" style=\"margin-top:10px\">—</pre>\n" +
		"    </div>\n" +
		"    <div class=\"card\"><table class=\"tbl\"><thead><tr><th>Token 前缀</th><th>备注</th><th>绑定主机</th><th>创建时间</th><th>状态</th><th>操作</th></tr></thead><tbody id=\"tokBody\"></tbody></table>\n" +
		"      <div class=\"pager\" id=\"tokPager\"></div>\n" +
		"    </div>\n" +
		"  </section>\n" +
		"</main>\n" +
		"<div class=\"toast\" id=\"toast\"></div>\n" +
		"<script>\n" +
		uiJS() +
		"</script>\n" +
		"</body></html>"
}

func uiCSS() string {
	return ":root{--bg:#0b1220;--panel:#121d33;--panel2:#0f1830;--border:#1f2d4d;--border2:#2a3b63;--txt:#e6edf7;--muted:#8aa0bd;--accent:#3b82f6;--accent2:#1d4ed8;--ok:#22c55e;--warn:#facc15;--err:#f87171;--danger:#b91c1c}\n" +
		"*{box-sizing:border-box}\n" +
		"html,body{margin:0;padding:0}\n" +
		"body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,'PingFang SC','Microsoft YaHei',sans-serif;background:linear-gradient(180deg,#0b1220 0%,#0a1020 100%);color:var(--txt);font-size:13px}\n" +
		"a{color:var(--accent)}\n" +
		".top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:14px;padding:10px 22px;background:rgba(11,18,32,.78);backdrop-filter:blur(10px);border-bottom:1px solid var(--border)}\n" +
		".brand{display:flex;align-items:center;gap:10px}\n" +
		".logo{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff;font-weight:700;font-size:13px;box-shadow:0 4px 14px rgba(59,130,246,.45)}\n" +
		".brand b{font-size:15px}.brand .v{color:var(--muted);font-size:11px;margin-left:6px}\n" +
		".tabs{display:flex;gap:2px;background:rgba(255,255,255,.03);padding:4px;border-radius:10px;border:1px solid var(--border)}\n" +
		".tabs button{background:transparent;border:0;color:var(--muted);padding:7px 14px;border-radius:7px;cursor:pointer;font-size:12.5px;font-weight:600;letter-spacing:.02em}\n" +
		".tabs button.active{background:linear-gradient(180deg,#1e3a6f,#16294f);color:#fff;box-shadow:0 1px 0 rgba(255,255,255,.05) inset}\n" +
		".tabs button:hover:not(.active){color:#cbd5e1}\n" +
		".uinfo{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:8px}\n" +
		".uinfo button{background:var(--border2);color:var(--txt);border:0;border-radius:6px;padding:5px 10px;cursor:pointer;font-size:12px}\n" +
		"main{padding:20px 22px 80px;max-width:1320px;margin:0 auto}\n" +
		".card{background:linear-gradient(180deg,#121d33,#0f1830);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:14px;box-shadow:0 6px 20px rgba(0,0,0,.25)}\n" +
		".card-h{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:12px}\n" +
		".card-h h3{margin:0;font-size:14px;color:#dbe7ff}\n" +
		".hint{color:var(--muted);font-size:11.5px}\n" +
		".r{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}\n" +
		".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}\n" +
		".grid4{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}\n" +
		".field{display:flex;flex-direction:column;gap:4px;min-width:0}\n" +
		".field label{font-size:11px;color:var(--muted);font-weight:600}\n" +
		".chk-row{display:flex;gap:14px;flex-wrap:wrap;margin-top:12px}\n" +
		".chk{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;cursor:pointer;color:#cbd5e1}\n" +
		".chk input{width:auto;accent-color:#3b82f6}\n" +
		".grow{flex:1;min-width:160px}\n" +
		"table.tbl{width:100%;border-collapse:collapse;font-size:12.5px}\n" +
		"th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}\n" +
		"th{color:var(--muted);font-weight:600;font-size:11.5px;letter-spacing:.02em;background:rgba(255,255,255,.02)}\n" +
		"tbody tr:hover{background:rgba(59,130,246,.06)}\n" +
		"pre{background:#070d1c;border:1px solid var(--border);border-radius:8px;padding:10px;max-height:240px;overflow:auto;white-space:pre-wrap;font-size:11.5px;margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#cfe2ff}\n" +
		"code{background:rgba(255,255,255,.06);padding:1px 5px;border-radius:4px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}\n" +
		"button{background:var(--border2);color:var(--txt);border:1px solid #2a3b63;border-radius:8px;padding:6px 12px;cursor:pointer;font-size:12.5px;font-weight:600;transition:all .12s}\n" +
		"button:hover{filter:brightness(1.15)}\n" +
		"button.primary{background:linear-gradient(180deg,#3b82f6,#1d4ed8);border-color:#1d4ed8;color:#fff;box-shadow:0 3px 10px rgba(59,130,246,.35)}\n" +
		"button.ghost{background:rgba(255,255,255,.04);border-color:var(--border)}\n" +
		"button.ok{background:linear-gradient(180deg,#16a34a,#15803d);border-color:#15803d;color:#fff}\n" +
		"button.danger{background:linear-gradient(180deg,#dc2626,#991b1b);border-color:#991b1b;color:#fff}\n" +
		"button.block{width:100%}\n" +
		"input,select,textarea{background:#070d1c;color:var(--txt);border:1px solid var(--border2);border-radius:8px;padding:7px 10px;font-size:12.5px;font-family:inherit;min-width:0}\n" +
		"input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.18)}\n" +
		".dot{display:inline-block;width:9px;height:9px;border-radius:50%;vertical-align:middle;margin-right:6px}\n" +
		".on{background:var(--ok);box-shadow:0 0 8px rgba(34,197,94,.65)}.off{background:#475569}\n" +
		".badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}\n" +
		".b-ok{background:rgba(34,197,94,.15);color:#86efac;border:1px solid rgba(34,197,94,.3)}\n" +
		".b-err{background:rgba(248,113,113,.15);color:#fca5a5;border:1px solid rgba(248,113,113,.3)}\n" +
		".b-warn{background:rgba(250,204,21,.15);color:#fde68a;border:1px solid rgba(250,204,21,.3)}\n" +
		".b-mut{background:rgba(148,163,184,.12);color:#cbd5e1;border:1px solid rgba(148,163,184,.25)}\n" +
		".tag{display:inline-block;background:rgba(59,130,246,.16);color:#bfdbfe;border:1px solid rgba(59,130,246,.3);border-radius:6px;padding:1px 7px;font-size:11px;margin-right:4px}\n" +
		".login{min-height:78vh;display:flex;align-items:flex-start;justify-content:center;padding-top:10vh}\n" +
		".login-card{width:380px;max-width:92vw;background:linear-gradient(180deg,#121d33,#0f1830);border:1px solid var(--border);border-radius:16px;padding:30px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}\n" +
		".login-logo{width:56px;height:56px;margin:0 auto 14px;border-radius:14px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:20px;box-shadow:0 8px 24px rgba(59,130,246,.5)}\n" +
		".login-card h2{margin:0 0 4px;font-size:18px}.login-card p{margin:0 0 20px;color:var(--muted);font-size:12.5px}\n" +
		".login-card input{width:100%;margin-bottom:14px;padding:11px;font-size:14px}\n" +
		".toast{position:fixed;bottom:24px;right:24px;background:linear-gradient(180deg,#121d33,#0f1830);border:1px solid var(--border2);padding:11px 16px;border-radius:10px;font-size:12.5px;z-index:99;display:none;box-shadow:0 10px 30px rgba(0,0,0,.5)}\n" +
		".toast.show{display:block}\n" +
		".hidden{display:none}\n" +
		".pager{display:flex;align-items:center;justify-content:flex-end;gap:6px;margin-top:12px;flex-wrap:wrap}\n" +
		".pager .hint{margin-right:auto}\n" +
		".pager button{min-width:34px;padding:5px 8px}\n" +
		".pager button.active{background:linear-gradient(180deg,#3b82f6,#1d4ed8);border-color:#1d4ed8;color:#fff}\n" +
		".pager select{width:auto;padding:5px 8px}\n" +
		"@media(max-width:860px){.top{flex-wrap:wrap}.tabs{order:3;width:100%;justify-content:space-between}}\n" +
		"::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#1f2d4d;border-radius:6px}::-webkit-scrollbar-track{background:transparent}\n"
}

func uiJS() string {
	return "let TOK=localStorage.getItem('gk_tok')||'';\n" +
		"let agents=[], cmds=[], audit=[], tokens=[];\n" +
		"let selectedAgents=new Set();\n" +
		"let agentPage=1,agentSize=20,agentTotal=0,agentPages=1;\n" +
		"let cmdPage=1,cmdSize=20,cmdTotal=0,cmdPages=1;\n" +
		"let auditPage=1,auditSize=50,auditTotal=0,auditPages=1;\n" +
		"let tokPage=1,tokSize=50,tokTotal=0,tokPages=1;\n" +
		"async function api(path, opts, body){\n" +
		"  const r = await fetch('/api'+path, {headers:{'Authorization':'Bearer '+TOK,'Content-Type':'application/json'}, method:opts||'GET', body:body?JSON.stringify(body):undefined});\n" +
		"  if(r.status===401 && path!=='/login' && path!=='/me'){ localStorage.removeItem('gk_tok'); TOK=''; showLogin(); throw new Error('auth'); }\n" +
		"  return r.json();\n" +
		"}\n" +
		"// 从分页响应 {items,total,page,page_size,pages} 中取 items; 兼容老数组形态\n" +
		"function pageItems(j){ return Array.isArray(j)?j:(j&&j.items)||[]; }\n" +
		"function pageMeta(j){ if(!Array.isArray(j)&&j){ return {total:j.total||0, pages:j.pages||1}; } return {total:0,pages:1}; }\n" +
		"// 通用分页渲染。goto(page) 跳页，setsize(v) 改每页条数。\n" +
		"function renderPager(elId, page, pages, total, size, goto, setsize){\n" +
		"  const el=$(elId); if(!el)return;\n" +
		"  el.innerHTML='';\n" +
		"  if(pages<=1){ if(total>0){ const s=document.createElement('span');s.className='hint';s.textContent='共 '+total+' 条';el.appendChild(s);} return; }\n" +
		"  const hint=document.createElement('span');hint.className='hint';hint.textContent='共 '+total+' 条 / '+pages+' 页';el.appendChild(hint);\n" +
		"  const add=(label,p,active)=>{const b=document.createElement('button');b.textContent=label;b.className=active?'active':'';b.onclick=()=>{goto(p);};el.appendChild(b);};\n" +
		"  add('‹', Math.max(1,page-1), false);\n" +
		"  const win=2;\n" +
		"  for(let p=1;p<=pages;p++){ if(p===1||p===pages||Math.abs(p-page)<=win){ add(p,p,p===page); } else if(Math.abs(p-page)===win+1){ const e=document.createElement('span');e.className='hint';e.textContent='…';el.appendChild(e); } }\n" +
		"  add('›', Math.min(pages,page+1), false);\n" +
		"  const sz=document.createElement('select'); sz.onchange=()=>{ const v=parseInt(sz.value,10); if(setsize)setsize(v); goto(1); };\n" +
		"  [20,50,100,200].forEach(n=>{const o=document.createElement('option');o.value=n;o.textContent=n+'/页';if(n===size)o.selected=true;sz.appendChild(o);});\n" +
		"  sz.style.width='auto'; el.appendChild(sz);\n" +
		"}\n" +
		"function esc(s){return (s==null?'':String(s)).replace(/[<>&\"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','\"':'&quot;'}[c]));}\n" +
		"function fmtTime(t){if(!t)return '—'; const d=new Date(typeof t==='string'&&t.includes('T')?t:t*1000); return isNaN(d.getTime())?String(t):d.toLocaleString();}\n" +
		"function toast(m){const e=document.getElementById('toast');e.textContent=m;e.classList.add('show');setTimeout(()=>e.classList.remove('show'),2500);}\n" +
		"function $(id){return document.getElementById(id);}\n" +
		"function badge(cls, txt){return '<span class=\"badge '+cls+'\">'+txt+'</span>';}\n" +
		"function statusBadge(s){ if(s==='done')return badge('b-ok','成功'); if(s==='pending')return badge('b-warn','进行中'); if(s==='timeout')return badge('b-warn','超时'); return badge('b-err',s||'失败'); }\n" +
		"function showLogin(){ $('login').classList.remove('hidden'); $('app').classList.add('hidden'); $('uinfo').innerHTML=''; setTimeout(()=>$('pw').focus(),30); }\n" +
		"async function doLogin(){\n" +
		"  $('loginErr').textContent='';\n" +
		"  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:$('pw').value})});\n" +
		"  const j=await r.json();\n" +
		"  if(!r.ok){$('loginErr').textContent=j.error||'登录失败';return;}\n" +
		"  TOK=j.token; localStorage.setItem('gk_tok',TOK); enterApp();\n" +
		"}\n" +
		"function logout(){ fetch('/api/logout',{method:'POST',headers:{'Authorization':'Bearer '+TOK}}); localStorage.removeItem('gk_tok'); TOK=''; showLogin(); }\n" +
		"async function enterApp(){\n" +
		"  $('login').classList.add('hidden'); $('app').classList.remove('hidden');\n" +
		"  $('uinfo').innerHTML='<span class=\"hint\">admin</span><button onclick=\"logout()\">退出</button>';\n" +
		"  try{ await Promise.all([loadAgents(), loadTokens()]); }catch(e){}\n" +
		"  buildAgentFilters(); connectEvents(); loadAuditActions();\n" +
		"}\n" +
		"async function loadAgents(){\n" +
		"  const q=($('agentSearch').value||'').trim();\n" +
		"  let p=new URLSearchParams({page:agentPage,page_size:agentSize}); if(q)p.set('q',q);\n" +
		"  const j=await api('/agents?'+p.toString());\n" +
		"  agents=pageItems(j); const m=pageMeta(j); agentTotal=m.total; agentPages=m.pages;\n" +
		"  renderAgents(); buildAgentFilters(); refreshRescueSelect();\n" +
		"  renderPager('agentPager', agentPage, agentPages, agentTotal, agentSize, p=>{agentPage=p;loadAgents();}, v=>{agentSize=v;});\n" +
		"}\n" +
		"function renderAgents(){\n" +
		"  const tb=$('agentBody'); tb.innerHTML='';\n" +
		"  const onlineCount=agents.filter(a=>a.online).length;\n" +
		"  $('agentCount').textContent='当前页 '+agents.length+' 台 · 在线 '+onlineCount;\n" +
		"  agents.forEach(a=>{\n" +
		"    const tr=document.createElement('tr');\n" +
		"    const checked=selectedAgents.has(a.agent_id)?'checked':'';\n" +
		"    const tags=(a.tags||[]).map(t=>'<span class=\"tag\">'+esc(t)+'</span>').join('')||'—';\n" +
		"    const tokenShort=(a.token||'').slice(0,8)+'…';\n" +
		"    tr.innerHTML='<td><input type=\"checkbox\" '+checked+' onchange=\"toggleSel(\\''+esc(a.agent_id)+'\\',this.checked)\"></td>'+\n" +
		"      '<td><b>'+esc(a.hostname||'-')+'</b><div class=\"hint\">'+esc(a.agent_id)+'</div></td>'+\n" +
		"      '<td><code>'+esc(tokenShort)+'</code></td>'+\n" +
		"      '<td>'+esc(a.ip||'-')+'</td>'+\n" +
		"      '<td>'+esc(a.os||'-')+'</td>'+\n" +
		"      '<td>'+tags+'</td>'+\n" +
		"      '<td>'+esc(a.notes||'—')+'</td>'+\n" +
		"      '<td><span class=\"dot '+(a.online?'on':'off')+'\"></span>'+(a.online?'在线':'离线')+'</td>'+\n" +
		"      '<td class=\"hint\">'+fmtTime(a.last_seen)+'</td>'+\n" +
		"      '<td><div class=\"r\"><button class=\"primary\" onclick=\"rescueHere(\\''+esc(a.agent_id)+'\\')\">救援</button>'+\n" +
		"        '<button class=\"ghost\" onclick=\"tagPrompt(\\''+esc(a.agent_id)+'\\')\">标签</button>'+\n" +
		"        '<button class=\"ghost\" onclick=\"clearFailHere(\\''+esc(a.agent_id)+'\\')\">清失败</button>'+\n" +
		"        '<button class=\"danger\" onclick=\"deleteAgent(\\''+esc(a.agent_id)+'\\')\">删除</button></div></td>';\n" +
		"    tr.addEventListener('click',e=>{ if(e.target.tagName==='INPUT'||e.target.tagName==='BUTTON')return; rescueHere(a.agent_id); });\n" +
		"    tb.appendChild(tr);\n" +
		"  });\n" +
		"}\n" +
		"async function deleteAgent(id){\n" +
		"  if(!confirm('硬删除主机 '+id+'?\\\\n仅当主机已离线时允许, 同时会清除其历史指令记录, 不可恢复!'))return;\n" +
		"  const r=await fetch('/api/agents?id='+encodeURIComponent(id),{method:'DELETE',headers:{'Authorization':'Bearer '+TOK}});\n" +
		"  const j=await r.json(); if(!r.ok){ toast(j.error||'删除失败'); return; }\n" +
		"  toast('已删除'); selectedAgents.delete(id); loadAgents();\n" +
		"}\n" +
		"function toggleSel(id, on){ if(on)selectedAgents.add(id); else selectedAgents.delete(id); }\n" +
		"function rescueHere(id){\n" +
		"  document.querySelector('.tabs button[data-tab=\"rescue\"]').click();\n" +
		"  const sel=$('agentSel'); sel.disabled=false;\n" +
		"  for(const o of sel.options){ if(o.value===id){sel.value=id;break;} }\n" +
		"  saveRescueTarget();\n" +
		"}\n" +
		"async function tagPrompt(id){\n" +
		"  const a=agents.find(x=>x.agent_id===id)||{};\n" +
		"  const t=prompt('标签（逗号分隔，覆盖写入）:', (a.tags||[]).join(','));\n" +
		"  if(t===null)return;\n" +
		"  await api('/agent/'+encodeURIComponent(id),'POST',{tags:t.split(',').map(x=>x.trim()).filter(Boolean)});\n" +
		"  toast('已更新'); loadAgents();\n" +
		"}\n" +
		"async function clearFailHere(id){\n" +
		"  const r=await api('/dispatch','POST',{agent_id:id,action:'clear_fail',user:'root'});\n" +
		"  toast('已下发清失败计数: '+(r.id||''));\n" +
		"  setTimeout(loadCmds,1200);\n" +
		"}\n" +
		"function goBatch(){\n" +
		"  if(selectedAgents.size===0){toast('请先勾选主机');return;}\n" +
		"  document.querySelector('.tabs button[data-tab=\"rescue\"]').click();\n" +
		"  $('rescueTarget').textContent='（批量模式：将下发到 '+selectedAgents.size+' 台主机）';\n" +
		"  $('agentSel').disabled=true;\n" +
		"}\n" +
		"async function tagSelected(){\n" +
		"  if(selectedAgents.size===0){toast('请先勾选主机');return;}\n" +
		"  const t=prompt('为 '+selectedAgents.size+' 台主机打标签（逗号分隔，覆盖写入）:','');\n" +
		"  if(t===null)return;\n" +
		"  const tags=t.split(',').map(x=>x.trim()).filter(Boolean);\n" +
		"  for(const id of selectedAgents){ await api('/agent/'+encodeURIComponent(id),'POST',{tags}); }\n" +
		"  toast('已批量打标签'); await loadAgents();\n" +
		"}\n" +
		"function refreshRescueSelect(){\n" +
		"  const sel=$('agentSel'); if(!sel)return;\n" +
		"  sel.disabled=false; const cur=sel.value; sel.innerHTML='';\n" +
		"  agents.forEach(a=>{const o=document.createElement('option');o.value=a.agent_id;o.textContent=(a.hostname||a.agent_id)+' '+(a.online?'●':'○');sel.appendChild(o);});\n" +
		"  if(cur){ for(const o of sel.options){if(o.value===cur){sel.value=cur;break;} } }\n" +
		"}\n" +
		"function saveRescueTarget(){ const sel=$('agentSel'); if(!sel||!sel.options.length){return;} $('rescueTarget').textContent='目标: '+(sel.options[sel.selectedIndex]?sel.options[sel.selectedIndex].textContent:''); }\n" +
		"function onActChange(){ const v=$('actSel').value; $('comboOpts').style.display=v==='combo'?'flex':'none'; $('pwIn').parentElement.style.display=(v==='reset_password'||v==='combo')?'flex':'none'; }\n" +
		"function buildParams(){\n" +
		"  const a=$('actSel').value; const p={};\n" +
		"  if(a==='reset_password'){ p.password=$('pwIn').value; if(!p.password){alert('请填新密码');return null;} p.force_change='false'; }\n" +
		"  if(a==='combo'){\n" +
		"    if($('cb_fail').checked)p.clear_fail_count='true';\n" +
		"    if($('cb_unlock').checked)p.unlock_account='true';\n" +
		"    if($('cb_expire').checked)p.expire_never='true';\n" +
		"    if($('cb_force').checked)p.force_change='true';\n" +
		"    if($('pwIn').value)p.password=$('pwIn').value;\n" +
		"  }\n" +
		"  return p;\n" +
		"}\n" +
		"async function dispatch(){\n" +
		"  const params=buildParams(); if(params===null)return;\n" +
		"  if($('agentSel').disabled && selectedAgents.size>0){\n" +
		"    const r=await api('/dispatch_batch','POST',{agent_ids:[...selectedAgents],action:$('actSel').value,user:$('userIn').value||'root',params});\n" +
		"    $('lastOut').textContent='批量已下发 '+r.length+' 条:\\n'+JSON.stringify(r,null,2);\n" +
		"  }else{\n" +
		"    const agent_id=$('agentSel').value;\n" +
		"    const r=await api('/dispatch','POST',{agent_id,action:$('actSel').value,user:$('userIn').value||'root',params});\n" +
		"    $('lastOut').textContent=JSON.stringify(r,null,2);\n" +
		"  }\n" +
		"  toast('已下发'); setTimeout(loadCmds,1500); $('agentSel').disabled=false; saveRescueTarget();\n" +
		"}\n" +
		"function buildAgentFilters(){ const fa=$('cmdAgentFilter'); if(!fa)return; fa.innerHTML='<option value=\"\">全部主机</option>'; agents.forEach(a=>{const o=document.createElement('option');o.value=a.agent_id;o.textContent=a.hostname||a.agent_id;fa.appendChild(o);}); }\n" +
		"async function loadCmds(){\n" +
		"  const aid=$('cmdAgentFilter').value;\n" +
		"  let p=new URLSearchParams({page:cmdPage,page_size:cmdSize}); if(aid)p.set('agent_id',aid);\n" +
		"  const j=await api('/commands?'+p.toString());\n" +
		"  cmds=pageItems(j); const m=pageMeta(j); cmdTotal=m.total; cmdPages=m.pages;\n" +
		"  const tb=$('cmdBody'); tb.innerHTML='';\n" +
		"  cmds.forEach(c=>{ const tr=document.createElement('tr'); const host=(agents.find(a=>a.agent_id===c.agent_id)||{}).hostname||c.agent_id; tr.innerHTML='<td class=\"hint\">'+fmtTime(c.created_at)+'</td><td>'+esc(host)+'</td><td>'+esc(c.action)+'</td><td>'+esc(c.user||'')+'</td><td class=\"hint\">'+esc(c.created_by||'-')+'</td><td>'+statusBadge(c.status)+'</td><td><pre>'+esc(c.output||c.err||'')+'</pre></td>'; tb.appendChild(tr); });\n" +
		"  renderPager('cmdPager', cmdPage, cmdPages, cmdTotal, cmdSize, p=>{cmdPage=p;loadCmds();}, v=>{cmdSize=v;});\n" +
		"}\n" +
		// ---------- 审计过滤 ----------
		"async function loadAuditActions(){ try{ const a=await api('/audit/actions'); const sel=$('afAction'); if(sel.options.length>1)return; (a||[]).forEach(x=>{const o=document.createElement('option');o.value=x;o.textContent=x;sel.appendChild(o);}); }catch(e){} }\n" +
		"function dtToUnix(v){ if(!v)return 0; const d=new Date(v); return isNaN(d.getTime())?0:Math.floor(d.getTime()/1000); }\n" +
		"function resetAuditFilter(){ ['afActor','afTarget','afQ'].forEach(i=>$(i).value=''); $('afAction').value=''; $('afFrom').value=''; $('afTo').value=''; auditPage=1; loadAudit(); }\n" +
		"async function loadAudit(){\n" +
		"  const p=new URLSearchParams();\n" +
		"  p.set('page',auditPage); p.set('page_size',auditSize);\n" +
		"  if($('afActor').value)p.set('actor',$('afActor').value);\n" +
		"  if($('afAction').value)p.set('action',$('afAction').value);\n" +
		"  if($('afTarget').value)p.set('target',$('afTarget').value);\n" +
		"  if($('afQ').value)p.set('q',$('afQ').value);\n" +
		"  const from=dtToUnix($('afFrom').value); if(from)p.set('from',from);\n" +
		"  const to=dtToUnix($('afTo').value); if(to)p.set('to',to);\n" +
		"  const j=await api('/audit?'+p.toString());\n" +
		"  audit=pageItems(j); const m=pageMeta(j); auditTotal=m.total; auditPages=m.pages;\n" +
		"  const tb=$('auditBody'); tb.innerHTML='';\n" +
		"  $('auditCount').textContent='命中 '+auditTotal+' 条 (当前页 '+audit.length+')';\n" +
		"  if(audit.length===0){ tb.innerHTML='<tr><td colspan=6 class=hint>无匹配记录</td></tr>'; renderPager('auditPager',auditPage,auditPages,auditTotal,auditSize,p=>{auditPage=p;loadAudit();},v=>{auditSize=v;}); return; }\n" +
		"  audit.forEach(a=>{ const tr=document.createElement('tr'); const cls=a.action.includes('failed')||a.action.includes('revoke')||a.action.includes('delete')||a.action.includes('denied')?'b-err':'b-mut'; tr.innerHTML='<td class=\"hint\">'+fmtTime(a.ts)+'</td><td>'+esc(a.actor)+'</td><td>'+badge(cls,esc(a.action))+'</td><td>'+esc(a.target||'-')+'</td><td class=\"hint\">'+esc(a.detail||'-')+'</td><td>'+esc(a.ip||'-')+'</td>'; tb.appendChild(tr); });\n" +
		"  renderPager('auditPager', auditPage, auditPages, auditTotal, auditSize, p=>{auditPage=p;loadAudit();}, v=>{auditSize=v;});\n" +
		"}\n" +
		// ---------- Token ----------
		"async function loadTokens(){\n" +
		"  let p=new URLSearchParams({page:tokPage,page_size:tokSize});\n" +
		"  const j=await api('/tokens?'+p.toString());\n" +
		"  tokens=pageItems(j); const m=pageMeta(j); tokTotal=m.total; tokPages=m.pages;\n" +
		"  const tb=$('tokBody'); tb.innerHTML='';\n" +
		"  tokens.forEach(t=>{\n" +
		"    const tr=document.createElement('tr');\n" +
		"    const bound=t.bound_agent_id?('<div><b>'+esc(t.bound_hostname||'-')+'</b><div class=\"hint\">'+esc(t.bound_agent_id)+'</div></div>'):'<span class=\"hint\">未绑定 (开放)</span>';\n" +
		"    let ops='<button class=\"danger\" onclick=\"revokeTok(\\''+esc(t.token)+'\\')\">撤销</button>';\n" +
		"    if(t.revoked){ ops='<button class=\"danger\" onclick=\"deleteTok(\\''+esc(t.token)+'\\')\">删除</button>'; }\n" +
		"    tr.innerHTML='<td><code>'+esc(t.prefix||'????????')+'…</code></td><td>'+esc(t.note||'-')+'</td><td>'+bound+'</td><td class=\"hint\">'+fmtTime(t.created_at)+'</td><td>'+(t.revoked?badge('b-err','已撤销'):badge('b-ok','有效'))+'</td><td><div class=\"r\">'+ops+'</div></td>';\n" +
		"    tb.appendChild(tr);\n" +
		"  });\n" +
		"  renderPager('tokPager', tokPage, tokPages, tokTotal, tokSize, p=>{tokPage=p;loadTokens();}, v=>{tokSize=v;});\n" +
		"}\n" +
		"async function genToken(){ const r=await api('/tokens','POST',{note:$('tokNote').value, bind_agent_id:$('tokBind').value||''}); $('tokOut').textContent='Token: '+r.token+'\\n备注: '+r.note+(r.bound_agent_id?('\\n绑定: '+r.bound_agent_id):'')+'\\n\\n安装命令:\\n  gatekeeper-agent -server <SERVER> -token '+r.token+'\\n\\n⚠ 此 token 仅显示一次, 请立即保存; 数据库只存哈希。'; toast('已生成, 请立即保存'); tokPage=1; loadTokens(); }\n" +
		"async function revokeTok(t){ if(!confirm('撤销后该 token 关联的 agent 将被立即踢下线且无法重连, 确定?'))return; await api('/tokens/revoke','POST',{token:t}); toast('已撤销'); loadTokens(); }\n" +
		"async function deleteTok(t){ if(!confirm('硬删除已撤销的 token? 已绑定 agent 的历史记录会保留但失去对应凭据, 不可恢复, 确定?'))return; const r=await fetch('/api/tokens/delete',{method:'POST',headers:{'Authorization':'Bearer '+TOK,'Content-Type':'application/json'},body:JSON.stringify({token:t})}); const j=await r.json(); if(!r.ok){ toast(j.error||'删除失败'); return; } toast('已删除'); loadTokens(); }\n" +
		// ---------- 实时事件 ----------
		"let es;\n" +
		"function connectEvents(){ if(es)return; try{ es=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ui/events?t='+encodeURIComponent(TOK)); es.onmessage=ev=>{ let m; try{m=JSON.parse(ev.data);}catch(e){return;} if(m.type==='result'||m.type==='agent_online'||m.type==='agent_offline'){ loadAgents(); loadCmds(); } }; es.onclose=()=>{ es=null; setTimeout(connectEvents,3000); }; }catch(e){} }\n" +
		// ---------- tabs ----------
		"document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{\n" +
		"  document.querySelectorAll('.tabs button').forEach(x=>x.classList.remove('active'));\n" +
		"  b.classList.add('active');\n" +
		"  document.querySelectorAll('.tab-content').forEach(s=>s.classList.add('hidden'));\n" +
		"  $('tab-'+b.dataset.tab).classList.remove('hidden');\n" +
		"  if(b.dataset.tab==='cmd')loadCmds();\n" +
		"  if(b.dataset.tab==='audit')loadAudit();\n" +
		"  if(b.dataset.tab==='tokens')loadTokens();\n" +
		"  if(b.dataset.tab==='rescue')refreshRescueSelect();\n" +
		"});\n" +
		// ---------- 启动 ----------
		"if(TOK){ fetch('/api/me',{headers:{'Authorization':'Bearer '+TOK}}).then(r=>{if(!r.ok){showLogin();}else enterApp();}).catch(showLogin); } else { showLogin(); }\n" +
		"onActChange();\n"
}
