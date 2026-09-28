/* ============================================================
 * scans.js — 账户巡检（概览卡片 / 过滤 / 明细 / 手动触发）
 * ============================================================ */
GK.views.scans = {
  title: '账户巡检',

  state: { agent: '', status: '', items: [] },

  async render (el) {
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.scan + '账户巡检</div>' +
          '<div class="page-desc">定时扫描主机账户过期与锁定状态，及时发现账户风险</div></div>' +
        '<div class="page-actions">' +
          '<button class="btn" id="sRefresh">' + GK.icons.refresh + '刷新</button>' +
          '<button class="btn btn-primary" id="sTrigger">' + GK.icons.bolt + '立即巡检</button>' +
        '</div>' +
      '</div>' +
      '<div class="stat-grid" id="sSummary" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))"></div>' +
      '<div class="card">' +
        '<div class="card-head">' +
          '<h3>巡检明细</h3>' +
          '<div class="card-tools">' +
            '<select class="form-control" id="sAgent" style="min-width:180px"></select>' +
            '<select class="form-control" id="sStatus"></select>' +
          '</div>' +
        '</div>' +
        '<div class="table-wrap">' +
          '<table class="tbl"><thead><tr>' +
            '<th>主机</th><th>账户</th><th>UID</th><th>状态</th>' +
            '<th>密码最后修改</th><th>密码过期</th><th>账户过期</th>' +
            '<th>最大天数</th><th>告警天数</th><th>扫描时间</th>' +
          '</tr></thead><tbody id="sBody"></tbody></table>' +
        '</div>' +
      '</div>';

    const agents = await GK.loadAgentsAll(true);
    GK.fillSelect(document.getElementById('sAgent'), agents.map(a => ({
      v: a.agent_id, t: a.hostname || a.agent_id
    })), { placeholder: '全部主机' });
    document.getElementById('sAgent').value = this.state.agent;

    GK.fillSelect(document.getElementById('sStatus'), GK.SCAN_STATUS.map(i => ({
      v: i.v, t: i.t
    })), { placeholder: '全部状态' });
    document.getElementById('sStatus').value = this.state.status;

    document.getElementById('sAgent').onchange = () => {
      this.state.agent = document.getElementById('sAgent').value;
      this.loadScans();
    };
    document.getElementById('sStatus').onchange = () => {
      this.state.status = document.getElementById('sStatus').value;
      this.loadScans();
    };
    document.getElementById('sRefresh').onclick = () => { this.loadAll(true); };
    document.getElementById('sTrigger').onclick = () => this.trigger();

    await this.loadAll();
  },

  async loadAll (force) {
    await Promise.allSettled([this.loadSummary(), this.loadScans(force)]);
  },

  async loadSummary () {
    const el = document.getElementById('sSummary');
    el.innerHTML = '';
    try {
      const s = await GK.api('/account_scans/summary');
      const cards = [
        { l: '总计', v: s.total || 0, c: 'blue', ico: 'inbox' },
        { l: '正常', v: s.active || 0, c: 'green', ico: 'check' },
        { l: '即将过期', v: (s.expiring || 0) + (s.password_expiring || 0), c: 'orange', ico: 'clock' },
        { l: '已过期', v: (s.expired || 0) + (s.password_expired || 0), c: 'red', ico: 'warn' },
        { l: '锁定', v: s.locked || 0, c: 'purple', ico: 'lock' },
        { l: '未知', v: s.unknown || 0, c: 'purple', ico: 'info' }
      ];
      el.innerHTML = cards.map(x =>
        '<div class="stat-card">' +
          '<div class="stat-top"><span class="stat-label">' + x.l + '</span>' +
            '<span class="stat-ico ' + x.c + '">' + GK.icons[x.ico] + '</span></div>' +
          '<div class="stat-num">' + x.v + '</div>' +
        '</div>').join('');
    } catch (e) {
      el.innerHTML = '<div class="card card-pad" style="grid-column:1/-1;color:var(--txt-3)">概览加载失败：' + GK.esc(e.message) + '</div>';
    }
  },

  async loadScans (forceCache) {
    await GK.loadAgentsAll(forceCache === true);
    const tb = document.getElementById('sBody');
    GK.tblSkeleton(tb, 10, 6);
    try {
      const r = await GK.api('/account_scans' + GK.qs({
        agent_id: this.state.agent, status: this.state.status
      }));
      this.state.items = Array.isArray(r) ? r : [];
      this.drawScans();
    } catch (e) {
      GK.toast(e.message || '加载失败', 'error');
    }
  },

  drawScans () {
    const tb = document.getElementById('sBody');
    const items = this.state.items;
    if (!items.length) {
      tb.innerHTML = '<tr><td colspan="10" id="sEmpty"></td></tr>';
      GK.empty(document.getElementById('sEmpty'), '暂无巡检数据', '点击右上角"立即巡检"开始扫描');
      return;
    }
    tb.innerHTML = items.map(a =>
      '<tr>' +
        '<td class="nowrap"><b>' + GK.esc(GK.hostname(a.agent_id)) + '</b>' +
          '<div class="cell-sub mono">' + GK.esc(a.agent_id) + '</div></td>' +
        '<td class="nowrap">' + GK.esc(a.username) + '</td>' +
        '<td>' + a.uid + '</td>' +
        '<td class="nowrap">' + GK.scanBadge(a.status) + '</td>' +
        '<td class="nowrap cell-sub">' + GK.esc(a.last_change || '—') + '</td>' +
        '<td class="nowrap cell-sub">' + GK.esc(a.password_expire || '—') + '</td>' +
        '<td class="nowrap cell-sub">' + GK.esc(a.expire_date || '—') + '</td>' +
        '<td>' + a.max_days + '</td>' +
        '<td>' + a.warn_days + '</td>' +
        '<td class="nowrap cell-sub">' + GK.fmtTime(a.scan_ts || 0) + '</td>' +
      '</tr>').join('');
  },

  async trigger () {
    // 当前选中主机则只巡检该主机，否则全部在线主机
    const agent = this.state.agent;
    let confirmMsg = agent
      ? '立即巡检主机 <b>' + GK.esc(GK.hostname(agent)) + '</b>？'
      : '立即巡检<b>全部在线主机</b>？';
    const ok = await GK.confirm(confirmMsg, { okText: '开始巡检', danger: false });
    if (!ok) return;
    try {
      const r = await GK.api('/account_scans/trigger', {
        method: 'POST',
        body: { agent_id: agent || '' }
      });
      GK.toast('已向 ' + r.accepted + ' 台主机下发巡检指令', 'success');
      // 稍候刷新结果
      setTimeout(() => this.loadAll(), 4000);
    } catch (e) {
      GK.toast(e.message || '下发失败', 'error');
    }
  }
};
