/* ============================================================
 * app.js — 应用核心：菜单 / 路由 / 登录 / 实时事件
 * ============================================================ */
(function () {

  const ROLE_LABEL = { admin: '管理员', operator: '操作员', auditor: '审计员' };
  const ALL = ['admin', 'operator', 'auditor'];
  const OPS = ['admin', 'operator'];
  const ADM = ['admin'];

  /* ---- 菜单定义 ---- */
  const MENU = [
    {
      group: '总览',
      items: [
        { r: 'dashboard', t: '工作台', ico: 'dashboard', roles: ALL }
      ]
    },
    {
      group: '运维管理',
      items: [
        { r: 'agents', t: '主机管理', ico: 'server', roles: OPS },
        { r: 'rescue', t: '账户救援', ico: 'rescue', roles: OPS },
        { r: 'commands', t: '指令历史', ico: 'history', roles: OPS },
        { r: 'scans', t: '账户巡检', ico: 'scan', roles: OPS }
      ]
    },
    {
      group: '安全管理',
      items: [
        { r: 'audit', t: '审计日志', ico: 'audit', roles: ALL },
        { r: 'tokens', t: 'Token 管理', ico: 'token', roles: ADM },
        { r: 'users', t: '用户管理', ico: 'users', roles: ADM },
        { r: 'shell', t: 'Shell 策略', ico: 'shield', roles: ADM },
        { r: 'settings', t: '系统设置', ico: 'bolt', roles: ADM }
      ]
    }
  ];

  const $ = id => document.getElementById(id);
  let renderSeq = 0;
  let refreshTimer = null;

  /* ---------- 菜单构建 ---------- */
  function buildNav () {
    const nav = $('nav');
    nav.innerHTML = '';
    MENU.forEach(g => {
      const items = g.items.filter(i => i.roles.includes(GK.me.role));
      if (!items.length) return;
      const gt = document.createElement('div');
      gt.className = 'nav-group-title';
      gt.textContent = g.group;
      nav.appendChild(gt);
      items.forEach(i => {
        const b = document.createElement('button');
        b.className = 'nav-item';
        b.dataset.r = i.r;
        b.innerHTML = '<span class="nav-ico">' + GK.icons[i.ico] + '</span>' +
          '<span class="nav-txt"></span><span class="nav-tip">' + i.t + '</span>';
        b.querySelector('.nav-txt').textContent = i.t;
        b.onclick = () => {
          if (location.hash === '#/' + i.r) route();
          else location.hash = '#/' + i.r;
          document.body.classList.remove('mobile-open');
        };
        nav.appendChild(b);
      });
    });
  }

  function highlight (route) {
    document.querySelectorAll('.nav-item').forEach(b =>
      b.classList.toggle('active', b.dataset.r === route));
  }

  function allowedRoutes () {
    const set = new Set();
    MENU.forEach(g => g.items.forEach(i => {
      if (i.roles.includes(GK.me.role)) set.add(i.r);
    }));
    return set;
  }

  function menuLabel (r) {
    for (const g of MENU) {
      const f = g.items.find(i => i.r === r);
      if (f) return f.t;
    }
    return '';
  }

  /* ---------- 路由 ---------- */
  async function route () {
    const raw = location.hash.replace(/^#/, '') || '/dashboard';
    const [pathPart, queryPart] = split2(raw, '?');
    const key = (pathPart || '/dashboard').replace(/^\//, '');
    const params = parseQuery(queryPart);

    const allowed = allowedRoutes();
    if (!allowed.has(key) || !GK.views[key]) {
      const fallback = allowed.has('dashboard') ? 'dashboard' : [...allowed][0];
      location.hash = '#/' + fallback;
      return;
    }

    highlight(key);
    const view = $('view');
    view.scrollTop = 0;
    GK.loading(view);
    const seq = ++renderSeq;
    try {
      await GK.views[key].render(view, params);
      if (seq !== renderSeq) return;
      view.classList.remove('view-enter');
      void view.offsetWidth; // 重启动画
      view.classList.add('view-enter');
    } catch (e) {
      if (seq === renderSeq) {
        GK.empty(view, '页面加载失败', e.message || '请点击刷新重试');
      }
    }

    // 面包屑
    $('breadcrumb').innerHTML = '<span>Gatekeeper</span><span class="sep">/</span><b>' + menuLabel(key) + '</b>';
  }

  function split2 (s, sep) {
    const i = s.indexOf(sep);
    return i < 0 ? [s, ''] : [s.slice(0, i), s.slice(i + 1)];
  }
  function parseQuery (s) {
    const o = {};
    if (!s) return o;
    new URLSearchParams(s).forEach((v, k) => { o[k] = v; });
    return o;
  }

  function refreshCurrent () {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(route, 600);
  }

  /* ---------- 登录 ---------- */
  GK.showLogin = function () {
    $('app').classList.add('hidden');
    $('loginPage').classList.remove('hidden');
    setTimeout(() => $('loginUser').focus(), 50);
  };

  function showApp () {
    $('loginPage').classList.add('hidden');
    $('app').classList.remove('hidden');
  }

  async function doLogin (e) {
    e.preventDefault();
    const btn = $('loginBtn');
    const errBox = $('loginErr');
    errBox.textContent = '';
    btn.classList.add('loading');
    try {
      const username = $('loginUser').value.trim() || 'admin';
      const r = await GK.api('/login', {
        method: 'POST',
        body: { username: username, password: $('loginPw').value }
      });
      GK.token = r.token;
      localStorage.setItem('gk_tok', r.token);
      await enterWithSession(r.role, r.actor || username);
      $('loginPw').value = '';
    } catch (err) {
      if (err.data && err.data.cooldown) {
        errBox.textContent = '尝试过于频繁，请 ' + err.data.cooldown + ' 秒后再试';
      } else {
        errBox.textContent = err.message || '登录失败';
      }
    } finally {
      btn.classList.remove('loading');
    }
  }

  /* 已有会话恢复 */
  async function restore () {
    try {
      const me = await GK.api('/me');
      await enterWithSession(me.role, me.actor);
      return true;
    } catch (e) {
      return false;
    }
  }

  async function enterWithSession (role, actor) {
    GK.me.role = role || 'admin';
    GK.me.actor = actor || 'admin';
    GK.role = GK.me.role;
    localStorage.setItem('gk_role', GK.me.role);

    // 顶栏用户区
    $('userName').textContent = GK.me.actor;
    $('userRole').textContent = ROLE_LABEL[GK.me.role] || GK.me.role;
    $('umName').textContent = GK.me.actor;
    $('umRole').textContent = ROLE_LABEL[GK.me.role] || GK.me.role;
    $('userAvatar').textContent = (GK.me.actor || 'A').slice(0, 1).toUpperCase();

    buildNav();
    showApp();
    connectEvents();
    if (!location.hash) location.hash = '#/dashboard';
    route();
  }

  /* ---------- 退出 ---------- */
  async function logout () {
    try { await GK.api('/logout', { method: 'POST' }); } catch (e) {}
    localStorage.removeItem('gk_tok');
    localStorage.removeItem('gk_role');
    GK.token = '';
    GK.me = { actor: '', role: '' };
    if (es) { try { es.close(); } catch (e) {} es = null; }
    location.hash = '';
    GK.showLogin();
  }

  /* ---------- 实时事件 WebSocket ---------- */
  let es = null;
  let esRetry = 0;
  let esManual = false;

  function connectEvents () {
    if (es) return;
    esManual = false;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    let ws;
    try {
      ws = new WebSocket(proto + '://' + location.host + '/ui/events?t=' + encodeURIComponent(GK.token));
    } catch (e) {
      scheduleReconnect();
      return;
    }
    es = ws;
    ws.onopen = () => {
      esRetry = 0;
      $('connState').classList.remove('off');
    };
    ws.onmessage = ev => {
      let m;
      try { m = JSON.parse(ev.data); } catch (e) { return; }
      // 事件驱动的当前视图轻量刷新（已防抖）
      if (['result', 'agent_online', 'agent_offline', 'account_scan_updated'].includes(m.type)) {
        // agent 列表缓存失效，供下次读取
        GK.cache.ts = 0;
        refreshCurrent();
      }
    };
    ws.onclose = () => {
      es = null;
      $('connState').classList.add('off');
      if (!esManual) scheduleReconnect();
    };
    ws.onerror = () => { try { ws.close(); } catch (e) {} };
  }

  function scheduleReconnect () {
    esRetry++;
    setTimeout(connectEvents, Math.min(3000 * esRetry, 15000));
  }

  /* ---------- 侧栏收起 / 移动端 ---------- */
  function initChrome () {
    if (localStorage.getItem('gk_collapsed') === '1') {
      $('app').classList.add('collapsed');
    }
    $('collapseBtn').onclick = () => {
      const on = $('app').classList.toggle('collapsed');
      localStorage.setItem('gk_collapsed', on ? '1' : '0');
    };
    $('mobileToggle').onclick = () => document.body.classList.toggle('mobile-open');

    // 用户菜单
    const chip = $('userChip');
    chip.onclick = e => { e.stopPropagation(); chip.classList.toggle('open'); };
    document.addEventListener('click', () => chip.classList.remove('open'));
    $('logoutBtn').onclick = logout;
  }

  /* ---------- 启动 ---------- */
  function boot () {
    // 注入登录页图标
    $('icUser').innerHTML = GK.icons.user;
    $('icLock').innerHTML = GK.icons.lock;

    $('loginForm').addEventListener('submit', doLogin);
    window.addEventListener('hashchange', route);
    initChrome();

    if (GK.token) {
      // 先展示应用外壳的登录态过渡，后台恢复会话
      restore().then(ok => { if (!ok) GK.showLogin(); });
    } else {
      GK.showLogin();
    }
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
