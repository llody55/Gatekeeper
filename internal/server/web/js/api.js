/* ============================================================
 * api.js — 统一请求层与通用工具
 * 提供: GK.api / GK.esc / GK.fmtTime / GK.fmtDuration / GK.cache
 * ============================================================ */
window.GK = window.GK || {};

GK.token = localStorage.getItem('gk_tok') || '';
GK.role = localStorage.getItem('gk_role') || '';
GK.me = { actor: '', role: '' };

/* ---- 统一请求 ----
 * 用法: GK.api('/agents?page=1')
 *       GK.api('/tokens', { method: 'POST', body: { note: 'x' } })
 * 失败抛出 Error, error.status / error.msg 可用。
 */
GK.api = async function (path, opts) {
  opts = opts || {};
  const init = {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json' }
  };
  if (GK.token) init.headers.Authorization = 'Bearer ' + GK.token;
  if (opts.body !== undefined && opts.body !== null) {
    init.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
  }
  let r;
  try {
    r = await fetch('/api' + path, init);
  } catch (e) {
    const err = new Error('无法连接服务器，请检查网络');
    err.status = 0;
    throw err;
  }

  // 401: 会话失效（登录接口除外）
  if (r.status === 401 && path !== '/login') {
    GK.sessionExpired();
    const err = new Error('登录已失效，请重新登录');
    err.status = 401;
    throw err;
  }

  let j = null;
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    try { j = await r.json(); } catch (e) { j = null; }
  }

  if (!r.ok) {
    const err = new Error((j && j.error) || ('请求失败 (HTTP ' + r.status + ')'));
    err.status = r.status;
    err.data = j;
    throw err;
  }
  return j;
};

GK.sessionExpired = function () {
  localStorage.removeItem('gk_tok');
  localStorage.removeItem('gk_role');
  GK.token = '';
  if (GK.showLogin) GK.showLogin();
};

/* ---- 分页响应解包（兼容数组旧形态） ---- */
GK.items = function (j) {
  if (Array.isArray(j)) return j;
  return (j && Array.isArray(j.items)) ? j.items : [];
};
GK.pageMeta = function (j) {
  if (!j || Array.isArray(j)) return { total: 0, page: 1, pages: 1, page_size: 10 };
  return { total: j.total || 0, page: j.page || 1, pages: j.pages || 1, page_size: j.page_size || 10 };
};

/* ---- 工具函数 ---- */
GK.esc = function (s) {
  return (s == null ? '' : String(s)).replace(/[<>&"']/g, function (c) {
    return { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c];
  });
};

GK.fmtTime = function (t) {
  if (!t) return '—';
  let d;
  if (typeof t === 'number') d = new Date(t * 1000);
  else d = new Date(t);
  if (isNaN(d.getTime())) return GK.esc(t);
  const pad = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
};

GK.relTime = function (t) {
  if (!t) return '—';
  const ts = typeof t === 'number' ? t * 1000 : new Date(t).getTime();
  const diff = Date.now() - ts;
  if (isNaN(diff)) return GK.fmtTime(t);
  if (diff < 0) return '刚刚';
  const m = Math.floor(diff / 60000);
  if (m < 1) return '刚刚';
  if (m < 60) return m + ' 分钟前';
  const h = Math.floor(m / 60);
  if (h < 24) return h + ' 小时前';
  const d = Math.floor(h / 24);
  if (d < 30) return d + ' 天前';
  return GK.fmtTime(t);
};

/* datetime-local 输入框 <-> unix */
GK.dtInput = function (unix) {
  if (!unix) return '';
  const d = new Date(unix * 1000);
  if (isNaN(d.getTime())) return '';
  const pad = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
};
GK.dtUnix = function (v) {
  if (!v) return 0;
  const d = new Date(v);
  return isNaN(d.getTime()) ? 0 : Math.floor(d.getTime() / 1000);
};

/* ---- 主机数据缓存（供各视图反查 hostname） ---- */
GK.cache = { agents: [], ts: 0 };

GK.loadAgentsAll = async function (force) {
  const fresh = (Date.now() - GK.cache.ts) < 30000;
  if (!force && fresh && GK.cache.agents.length) return GK.cache.agents;
  try {
    const j = await GK.api('/agents?page=1&page_size=200');
    GK.cache.agents = GK.items(j);
    GK.cache.ts = Date.now();
  } catch (e) {
    if (!GK.cache.agents) GK.cache.agents = [];
  }
  return GK.cache.agents;
};

GK.hostname = function (id) {
  const a = GK.cache.agents.find(x => x.agent_id === id);
  return a ? (a.hostname || id) : id;
};

/* 查询串构造（跳过空值） */
GK.qs = function (obj) {
  const p = new URLSearchParams();
  Object.keys(obj).forEach(k => {
    if (obj[k] !== '' && obj[k] !== null && obj[k] !== undefined) p.set(k, obj[k]);
  });
  const s = p.toString();
  return s ? '?' + s : '';
};

/* 动作字典（全局统一） */
GK.ACTIONS = [
  { v: 'combo', t: '组合救援' },
  { v: 'shell', t: '自定义命令' },
  { v: 'chage_status', t: '查看过期状态' },
  { v: 'expire_extend', t: '关闭密码过期' },
  { v: 'unlock', t: '解锁账户' },
  { v: 'clear_fail', t: '清除失败计数' },
  { v: 'reset_password', t: '重置密码' }
];
GK.actionText = function (v) {
  const a = GK.ACTIONS.find(x => x.v === v);
  return a ? a.t : v;
};
GK.actionBadge = function (v) {
  const map = {
    combo: 'b-purple', shell: 'b-cyan', chage_status: 'b-blue',
    expire_extend: 'b-green', unlock: 'b-green', clear_fail: 'b-gray',
    reset_password: 'b-orange'
  };
  return '<span class="badge ' + (map[v] || 'b-gray') + '">' + GK.esc(GK.actionText(v)) + '</span>';
};

/* ---- 账户巡检状态字典（全局统一） ---- */
GK.SCAN_STATUS = [
  { v: 'active', t: '正常' },
  { v: 'password_expiring', t: '密码即将过期' },
  { v: 'expiring', t: '账户即将过期' },
  { v: 'expired', t: '账户已过期' },
  { v: 'password_expired', t: '密码已过期' },
  { v: 'locked', t: '已锁定' },
  { v: 'unknown', t: '未知' }
];
GK.scanStatusText = function (s) {
  const x = GK.SCAN_STATUS.find(i => i.v === s);
  return x ? x.t : (s || '未知');
};
GK.scanBadge = function (s) {
  const map = {
    active: 'b-green',
    password_expiring: 'b-orange',
    expiring: 'b-orange',
    expired: 'b-red',
    password_expired: 'b-red',
    locked: 'b-purple',
    unknown: 'b-gray'
  };
  return '<span class="badge ' + (map[s] || 'b-gray') + '">' + GK.esc(GK.scanStatusText(s)) + '</span>';
};
