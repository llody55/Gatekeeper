/* ============================================================
 * dashboard.js — 工作台（总览仪表盘）
 * ============================================================ */
GK.views = GK.views || {};

GK.views.dashboard = {
  title: '工作台',
  async render (el) {
    el.innerHTML =
      '<div class="hero">' +
        '<div class="hero-txt">' +
          '<h1 id="heroHi"></h1>' +
          '<p id="heroDate"></p>' +
        '</div>' +
        '<div class="hero-deco"><span></span><span></span><span></span></div>' +
      '</div>' +
      '<div class="stat-grid" id="dStats"></div>' +
      '<div class="split-2">' +
        '<div class="card"><div class="card-head"><h3>最近指令</h3>' +
          '<button class="act-link" id="goCmds">查看全部</button></div>' +
          '<div id="recentCmds" class="mini-list"></div></div>' +
        '<div class="card"><div class="card-head"><h3>风险账户</h3>' +
          '<button class="act-link" id="goScans">查看全部</button></div>' +
          '<div id="riskAccts" class="mini-list"></div></div>' +
      '</div>';

    // 欢迎区
    const hour = new Date().getHours();
    const greet = hour < 6 ? '夜深了' : hour < 12 ? '早上好' : hour < 14 ? '中午好' : hour < 18 ? '下午好' : '晚上好';
    document.getElementById('heroHi').textContent = greet + '，' + GK.me.actor;
    document.getElementById('heroDate').textContent =
      '今天是 ' + new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' });

    // 并行加载，互不阻塞（任一失败单独降级）
    const [agRes, sumRes, cmdRes] = await Promise.allSettled([
      GK.loadAgentsAll(true),
      GK.api('/account_scans/summary'),
      GK.api('/commands?page=1&page_size=6')
    ]);

    // ---- 统计卡片 ----
    const agents = agRes.status === 'fulfilled' ? (agRes.value || []) : [];
    const onlineN = agents.filter(a => a.online).length;
    const offlineN = agents.length - onlineN;
    const sum = sumRes.status === 'fulfilled' ? (sumRes.value || {}) : {};
    const riskN = (sum.expiring || 0) + (sum.password_expiring || 0) +
      (sum.expired || 0) + (sum.password_expired || 0);
    const stats = [
      { l: '主机总数', v: agents.length, ico: 'server', c: 'blue', foot: '已纳管的主机数量' },
      { l: '在线主机', v: onlineN, ico: 'bolt', c: 'green', foot: '实时在线 · 可下发指令' },
      { l: '离线主机', v: offlineN, ico: 'clock', c: 'purple', foot: '离线期间无法救援' },
      { l: '风险账户', v: riskN, ico: 'warn', c: 'red', foot: '即将过期或已过期账户' }
    ];
    const stEl = document.getElementById('dStats');
    stEl.innerHTML = stats.map((s, i) =>
      '<div class="stat-card" style="animation-delay:' + (i * 60) + 'ms">' +
        '<div class="stat-top"><span class="stat-label">' + s.l + '</span>' +
          '<span class="stat-ico ' + s.c + '">' + GK.icons[s.ico] + '</span></div>' +
        '<div class="stat-num" data-v="' + s.v + '">0</div>' +
        '<div class="stat-foot">' + s.foot + '</div>' +
        '<span class="deco"></span>' +
      '</div>').join('');
    // 数字滚动
    stEl.querySelectorAll('.stat-num').forEach(n => {
      const target = parseInt(n.dataset.v, 10);
      const t0 = performance.now(), dur = 700;
      (function tick (t) {
        const p = Math.min(1, (t - t0) / dur);
        n.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
        if (p < 1) requestAnimationFrame(tick);
      })(t0);
    });

    // ---- 最近指令 ----
    const rc = document.getElementById('recentCmds');
    if (cmdRes.status === 'fulfilled') {
      const cmds = GK.items(cmdRes.value);
      if (!cmds.length) {
        GK.empty(rc, '暂无指令记录', '去主机页面发起一次救援吧');
      } else {
        rc.innerHTML = cmds.map(c => {
          const ok = c.status === 'done';
          return '<div class="mini-item" data-id="' + GK.esc(c.id) + '">' +
            '<span class="mini-avatar" style="' + (ok ? 'background:var(--success-soft);color:var(--success)' : 'background:var(--danger-soft);color:var(--danger)') + '">' +
              (ok ? '✓' : '…') + '</span>' +
            '<div class="mini-main"><b>' + GK.esc(GK.actionText(c.action)) + ' · ' + GK.esc(GK.hostname(c.agent_id)) + '</b>' +
              '<span>账户 ' + GK.esc(c.user || 'root') + ' · ' + GK.esc(c.created_by || '') + '</span></div>' +
            '<span class="mini-time">' + GK.relTime(c.created_at) + '</span></div>';
        }).join('');
        rc.querySelectorAll('.mini-item').forEach(it =>
          it.onclick = () => { location.hash = '#/commands'; });
      }
    } else {
      GK.empty(rc, '指令数据加载失败', '稍后点击刷新重试');
    }

    // ---- 风险账户 ----
    const ra = document.getElementById('riskAccts');
    if (sumRes.status === 'fulfilled') {
      let scans = [];
      try {
        const r = await GK.api('/account_scans');
        scans = Array.isArray(r) ? r : [];
      } catch (e) { scans = []; }
      const riskSet = ['expired', 'password_expired', 'expiring', 'password_expiring'];
      scans = scans.filter(s => riskSet.includes(s.status)).slice(0, 6);
      if (!scans.length) {
        GK.empty(ra, '暂无风险账户', '所有账户状态正常');
      } else {
        ra.innerHTML = scans.map(s =>
          '<div class="mini-item">' +
            '<span class="mini-avatar" style="background:var(--danger-soft);color:var(--danger">' + GK.esc((s.username || '?').slice(0, 2)) + '</span>' +
            '<div class="mini-main"><b>' + GK.esc(s.username) + ' · ' + GK.esc(GK.hostname(s.agent_id)) + '</b>' +
              '<span>' + GK.esc(GK.scanStatusText(s.status)) + '</span></div>' +
            '<span class="mini-time">' + GK.relTime(s.scan_ts || 0) + '</span></div>').join('');
      }
    } else {
      GK.empty(ra, '巡检数据加载失败', '稍后点击刷新重试');
    }

    document.getElementById('goCmds').onclick = () => { location.hash = '#/commands'; };
    document.getElementById('goScans').onclick = () => { location.hash = '#/scans'; };
  }
};
