/* ============================================================
 * commands.js — 指令历史（主机/动作过滤，输出详情弹窗）
 * ============================================================ */
GK.views.commands = {
  title: '指令历史',

  state: { page: 1, size: 10, agent: '', action: '', items: [] },

  async render (el) {
    const st = this.state;
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.history + '指令历史</div>' +
          '<div class="page-desc">查询所有已下发指令及其执行回执</div></div>' +
        '<div class="page-actions">' +
          '<button class="btn" id="cRefresh">' + GK.icons.refresh + '刷新</button>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="card-head">' +
          '<h3>筛选条件</h3>' +
        '</div>' +
        '<div class="card-body" style="padding-top:16px">' +
          '<div class="form-inline">' +
            '<select class="form-control" id="cAgent" style="min-width:200px"></select>' +
            '<select class="form-control" id="cAction"></select>' +
            '<button class="btn btn-primary" id="cSearch">查询</button>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="table-wrap">' +
          '<table class="tbl"><thead><tr>' +
            '<th>时间</th><th>主机</th><th>动作</th><th>账户</th><th>创建者</th>' +
            '<th>状态</th><th class="col-actions">回执</th>' +
          '</tr></thead><tbody id="cBody"></tbody></table>' +
        '</div>' +
        '<div id="cPager"></div>' +
      '</div>';

    const agents = await GK.loadAgentsAll(true);
    GK.fillSelect(document.getElementById('cAgent'), agents.map(a => ({
      v: a.agent_id, t: a.hostname || a.agent_id
    })), { placeholder: '全部主机' });
    document.getElementById('cAgent').value = st.agent;

    GK.fillSelect(document.getElementById('cAction'), GK.ACTIONS.map(a => ({
      v: a.v, t: a.t
    })), { placeholder: '全部动作' });
    document.getElementById('cAction').value = st.action;

    document.getElementById('cSearch').onclick = () => {
      st.agent = document.getElementById('cAgent').value;
      st.action = document.getElementById('cAction').value;
      st.page = 1;
      this.load();
    };
    document.getElementById('cRefresh').onclick = () => { this.load(true); };

    await this.load();
  },

  async load (forceCache) {
    const st = this.state;
    const tb = document.getElementById('cBody');
    GK.tblSkeleton(tb, 7, 6);
    try {
      await GK.loadAgentsAll(forceCache === true);
      const j = await GK.api('/commands' + GK.qs({
        page: st.page, page_size: st.size,
        agent_id: st.agent, action: st.action
      }));
      st.items = GK.items(j);
      this.draw(GK.pageMeta(j));
    } catch (e) {
      GK.toast(e.message || '加载失败', 'error');
    }
  },

  statusBadge (s) {
    if (s === 'done') return '<span class="badge b-green"><span class="bd-dot"></span>成功</span>';
    if (s === 'pending' || s === 'sent') return '<span class="badge b-orange"><span class="bd-dot"></span>进行中</span>';
    if (s === 'timeout') return '<span class="badge b-orange"><span class="bd-dot"></span>超时</span>';
    return '<span class="badge b-red"><span class="bd-dot"></span>' + GK.esc(s || '失败') + '</span>';
  },

  draw (meta) {
    const st = this.state;
    const tb = document.getElementById('cBody');
    if (!st.items.length) {
      tb.innerHTML = '<tr><td colspan="7" id="cEmpty"></td></tr>';
      GK.empty(document.getElementById('cEmpty'), '暂无指令记录', '调整筛选条件或去发起一次救援');
    } else {
      tb.innerHTML = st.items.map((c, i) => {
        const out = c.output || c.err || '';
        return '<tr data-i="' + i + '">' +
          '<td class="nowrap cell-sub">' + GK.fmtTime(c.created_at) + '</td>' +
          '<td><b>' + GK.esc(GK.hostname(c.agent_id)) + '</b>' +
            '<div class="cell-sub mono">' + GK.esc(c.agent_id) + '</div></td>' +
          '<td>' + GK.actionBadge(c.action) + '</td>' +
          '<td class="nowrap">' + GK.esc(c.user || 'root') + '</td>' +
          '<td class="nowrap cell-sub">' + GK.esc(c.created_by || '—') + '</td>' +
          '<td class="nowrap">' + this.statusBadge(c.status) + '</td>' +
          '<td class="col-actions">' +
            (out
              ? '<button class="act-link" data-i="' + i + '">查看回执</button>'
              : '<span class="cell-sub">暂无回执</span>') +
          '</td>' +
        '</tr>';
      }).join('');

      tb.querySelectorAll('.act-link').forEach(b =>
        b.onclick = () => this.showOut(parseInt(b.dataset.i, 10)));
    }

    GK.pager(document.getElementById('cPager'), {
      page: meta.page, pages: meta.pages, total: meta.total, pageSize: meta.page_size,
      onChange: p => { st.page = p; this.load(); },
      onSize: n => { st.size = n; st.page = 1; this.load(); }
    });
  },

  showOut (i) {
    const c = this.state.items[i];
    const ok = c.status === 'done';
    const m = GK.modal({
      title: '指令回执',
      size: 'lg',
      hideFoot: true,
      body:
        '<div class="desc-grid" style="margin-bottom:16px">' +
          '<div class="desc-item"><span class="d-k">主机</span><span class="d-v">' + GK.esc(GK.hostname(c.agent_id)) + '</span></div>' +
          '<div class="desc-item"><span class="d-k">动作</span><span class="d-v">' + GK.esc(GK.actionText(c.action)) + '</span></div>' +
          '<div class="desc-item"><span class="d-k">账户</span><span class="d-v">' + GK.esc(c.user || 'root') + '</span></div>' +
          '<div class="desc-item"><span class="d-k">状态</span><span class="d-v">' + (ok ? '成功' : GK.esc(c.status)) + '</span></div>' +
        '</div>' +
        '<pre class="output-pre" id="mOut"></pre>'
    });
    m.el.querySelector('#mOut').textContent = c.output || c.err || '(空)';
  }
};
