/* ============================================================
 * audit.js — 审计日志（多维过滤 / 留存策略）
 * ============================================================ */
GK.views.audit = {
  title: '审计日志',

  state: {
    page: 1, size: 10,
    actor: '', action: '', target: '', q: '', from: '', to: '',
    items: []
  },

  async render (el) {
    const isAdmin = GK.me.role === 'admin';
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.audit + '审计日志</div>' +
          '<div class="page-desc">记录平台全部关键操作，支持按操作者、动作、时间等维度检索</div></div>' +
        '<div class="page-actions">' +
          (isAdmin ? '<button class="btn" id="dRetention">' + GK.icons.clock + '留存策略</button>' : '') +
          '<button class="btn" id="dRefresh">' + GK.icons.refresh + '刷新</button>' +
        '</div>' +
      '</div>' +
      '<div class="filter-panel">' +
        '<div><label class="form-label">操作者</label>' +
          '<input class="form-control" id="fActor" maxlength="64" placeholder="精确匹配"></div>' +
        '<div><label class="form-label">动作</label>' +
          '<select class="form-control" id="fAction"><option value="">全部动作</option></select></div>' +
        '<div><label class="form-label">目标</label>' +
          '<input class="form-control" id="fTarget" maxlength="128" placeholder="包含匹配"></div>' +
        '<div><label class="form-label">关键字</label>' +
          '<input class="form-control" id="fQ" maxlength="100" placeholder="全文检索"></div>' +
        '<div><label class="form-label">开始时间</label>' +
          '<input class="form-control" id="fFrom" type="datetime-local"></div>' +
        '<div><label class="form-label">结束时间</label>' +
          '<input class="form-control" id="fTo" type="datetime-local"></div>' +
        '<div class="fp-actions">' +
          '<button class="btn btn-primary" id="fSearch">检索</button>' +
          '<button class="btn" id="fReset">重置</button>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="table-wrap">' +
          '<table class="tbl"><thead><tr>' +
            '<th>时间</th><th>操作者</th><th>动作</th><th>目标</th>' +
            '<th>详情</th><th>来源 IP</th>' +
          '</tr></thead><tbody id="dBody"></tbody></table>' +
        '</div>' +
        '<div id="dPager"></div>' +
      '</div>';

    // 动作下拉
    try {
      const actions = await GK.api('/audit/actions');
      GK.fillSelect(document.getElementById('fAction'), (actions || []).map(x => ({ v: x, t: x })),
        { placeholder: '全部动作' });
    } catch (e) {}

    document.getElementById('fSearch').onclick = () => {
      const st = this.state;
      st.actor = document.getElementById('fActor').value.trim();
      st.action = document.getElementById('fAction').value;
      st.target = document.getElementById('fTarget').value.trim();
      st.q = document.getElementById('fQ').value.trim();
      st.page = 1;
      this.load();
    };
    document.getElementById('fReset').onclick = () => {
      ['fActor', 'fTarget', 'fQ', 'fFrom', 'fTo'].forEach(i => document.getElementById(i).value = '');
      document.getElementById('fAction').value = '';
      this.state.page = 1;
      this.load();
    };
    document.getElementById('dRefresh').onclick = () => this.load();
    if (isAdmin) document.getElementById('dRetention').onclick = () => this.retention();

    // Enter 快捷检索
    ['fActor', 'fTarget', 'fQ'].forEach(i =>
      document.getElementById(i).addEventListener('keydown', e => {
        if (e.key === 'Enter') document.getElementById('fSearch').click();
      }));

    await this.load();
  },

  async load () {
    const st = this.state;
    const tb = document.getElementById('dBody');
    GK.tblSkeleton(tb, 6, 6);
    try {
      const from = GK.dtUnix(document.getElementById('fFrom').value);
      const to = GK.dtUnix(document.getElementById('fTo').value);
      const j = await GK.api('/audit' + GK.qs({
        page: st.page, page_size: st.size,
        actor: st.actor, action: st.action, target: st.target, q: st.q,
        from: from, to: to
      }));
      st.items = GK.items(j);
      this.draw(GK.pageMeta(j));
    } catch (e) {
      GK.toast(e.message || '加载失败', 'error');
    }
  },

  draw (meta) {
    const st = this.state;
    const tb = document.getElementById('dBody');
    if (!st.items.length) {
      tb.innerHTML = '<tr><td colspan="6" id="dEmpty"></td></tr>';
      GK.empty(document.getElementById('dEmpty'), '没有匹配的审计记录', '调整检索条件后重试');
    } else {
      tb.innerHTML = st.items.map(a => {
        const dangerish = /failed|revoke|delete|denied|blocked|offline/.test(a.action);
        return '<tr>' +
          '<td class="nowrap cell-sub">' + GK.fmtTime(a.ts) + '</td>' +
          '<td class="nowrap"><b>' + GK.esc(a.actor) + '</b></td>' +
          '<td class="nowrap"><span class="badge ' + (dangerish ? 'b-red' : 'b-blue') + '">' + GK.esc(a.action) + '</span></td>' +
          '<td class="nowrap">' + GK.esc(a.target || '—') + '</td>' +
          '<td class="cell-sub" style="max-width:280px" title="' + GK.esc(a.detail || '') + '">' + GK.esc(a.detail || '—') + '</td>' +
          '<td class="nowrap mono cell-sub">' + GK.esc(a.ip || '—') + '</td>' +
        '</tr>';
      }).join('');
    }

    GK.pager(document.getElementById('dPager'), {
      page: meta.page, pages: meta.pages, total: meta.total, pageSize: meta.page_size,
      onChange: p => { st.page = p; this.load(); },
      onSize: n => { st.size = n; st.page = 1; this.load(); }
    });
  },

  /* 留存天数设置 */
  retention () {
    GK.modal({
      title: '审计留存策略',
      body: '<div class="loading-box" style="padding:20px"><div class="big-spinner"></div></div>',
      hideFoot: true
    });
    // 先加载当前值
    GK.api('/settings/retention').then(d => {
      // 关闭加载弹窗，打开编辑弹窗
      document.querySelectorAll('.modal-mask').forEach(m => m.remove());
      GK.modal({
        title: '审计留存策略',
        body:
          '<div class="form-row"><label class="form-label">留存天数</label>' +
            '<input class="form-control" id="mDays" type="number" min="' + d.min_days + '" value="' + d.current_days + '">' +
            '<div class="form-hint">超过留存期的审计日志将被自动清理；下限 ' + d.min_days + ' 天（由服务端配置决定）</div></div>',
        onOk: async () => {
          const days = parseInt(document.getElementById('mDays').value, 10);
          if (!days || days < d.min_days) {
            GK.toast('留存天数不能小于 ' + d.min_days, 'warning');
            return false;
          }
          await GK.api('/settings/retention', { method: 'POST', body: { days: days } });
          GK.toast('留存策略已更新', 'success');
        }
      });
    }).catch(e => GK.toast(e.message, 'error'));
  }
};
