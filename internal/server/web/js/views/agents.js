/* ============================================================
 * agents.js — 主机管理（搜索 / 分页 / 批量 / 编辑 / 删除）
 * ============================================================ */
GK.views.agents = {
  title: '主机管理',

  state: { page: 1, size: 10, q: '', selected: new Set(), total: 0 },

  async render (el) {
    const st = this.state;
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.server + '主机管理</div>' +
          '<div class="page-desc">管理所有纳管主机，支持搜索、批量救援与批量打标签</div></div>' +
        '<div class="page-actions">' +
          '<button class="btn" id="aRefresh">' + GK.icons.refresh + '刷新</button>' +
          '<button class="btn" id="aBatchTag">' + GK.icons.tag + '批量打标签</button>' +
          '<button class="btn btn-primary" id="aBatchRescue">' + GK.icons.rescue + '批量救援</button>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="card-head">' +
          '<h3>被管主机</h3>' +
          '<div class="card-tools">' +
            '<div class="search-bar">' +
              '<input class="form-control" id="aSearch" maxlength="64" placeholder="按主机名 / IP / 标签搜索">' +
              '<button class="btn btn-sm" id="aSearchBtn">搜索</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="table-wrap">' +
          '<table class="tbl"><thead><tr>' +
            '<th style="width:38px"><input type="checkbox" id="aAll"></th>' +
            '<th>主机</th><th>IP</th><th>系统</th><th>标签</th><th>备注</th>' +
            '<th>状态</th><th>最近心跳</th><th class="col-actions">操作</th>' +
          '</tr></thead><tbody id="aBody"></tbody></table>' +
        '</div>' +
        '<div id="aPager"></div>' +
      '</div>';

    document.getElementById('aSearch').value = st.q;

    document.getElementById('aRefresh').onclick = () => this.load(true);
    document.getElementById('aSearchBtn').onclick = () => {
      st.q = document.getElementById('aSearch').value.trim();
      st.page = 1;
      this.load();
    };
    document.getElementById('aSearch').addEventListener('keydown', e => {
      if (e.key === 'Enter') document.getElementById('aSearchBtn').click();
    });
    document.getElementById('aBatchRescue').onclick = () => this.batchRescue();
    document.getElementById('aBatchTag').onclick = () => this.batchTag();
    document.getElementById('aAll').onchange = e => this.toggleAll(e.target.checked);

    await this.load();
  },

  async load (forceCache) {
    const st = this.state;
    const tb = document.getElementById('aBody');
    GK.tblSkeleton(tb, 9, 7);
    try {
      const j = await GK.api('/agents' + GK.qs({
        page: st.page, page_size: st.size, q: st.q
      }));
      const items = GK.items(j);
      const meta = GK.pageMeta(j);
      st.total = meta.total;
      await GK.loadAgentsAll(forceCache === true);
      this.draw(items, meta);
    } catch (e) {
      GK.toast(e.message || '加载失败', 'error');
      tb.innerHTML = '<tr><td colspan="9"><div class="state-box">' +
        '<div class="state-title">加载失败：' + GK.esc(e.message) + '</div></div></td></tr>';
    }
  },

  draw (items, meta) {
    const st = this.state;
    const tb = document.getElementById('aBody');
    if (!items.length) {
      tb.innerHTML = '<tr><td colspan="9" id="aEmpty"></td></tr>';
      GK.empty(document.getElementById('aEmpty'), '没有匹配的主机', '调整搜索条件或稍后刷新');
    } else {
      tb.innerHTML = items.map(a => {
        const id = a.agent_id;
        const tags = (a.tags || []).map(t => '<span class="tag-chip">' + GK.esc(t) + '</span>').join('') || '<span class="cell-sub">—</span>';
        return '<tr data-id="' + GK.esc(id) + '">' +
          '<td><input type="checkbox" class="a-chk" ' + (st.selected.has(id) ? 'checked' : '') + '></td>' +
          '<td><div class="cell-main"><b>' + GK.esc(a.hostname || '-') + '</b></div>' +
            '<div class="cell-sub mono">' + GK.esc(id) + '</div></td>' +
          '<td class="nowrap">' + GK.esc(a.ip || '-') + '</td>' +
          '<td class="nowrap">' + GK.esc(a.os || '-') + '</td>' +
          '<td>' + tags + '</td>' +
          '<td style="max-width:160px;overflow:hidden;text-overflow:ellipsis" class="cell-sub" title="' + GK.esc(a.notes || '') + '">' + GK.esc(a.notes || '—') + '</td>' +
          '<td><span class="status-dot"><i class="s-dot ' + (a.online ? 'green pulse' : 'gray') + '"></i>' + (a.online ? '在线' : '离线') + '</span></td>' +
          '<td class="nowrap cell-sub">' + (a.online ? GK.relTime(a.last_seen) : GK.fmtTime(a.last_seen)) + '</td>' +
          '<td class="col-actions">' +
            '<button class="act-link" data-act="rescue">' + GK.icons.rescue + '救援</button>' +
            '<button class="act-link muted" data-act="edit">' + GK.icons.edit + '编辑</button>' +
            '<button class="act-link muted" data-act="clearfail">' + GK.icons.check + '清失败</button>' +
            '<button class="act-link danger" data-act="del">' + GK.icons.trash + '删除</button>' +
          '</td>' +
        '</tr>';
      }).join('');

      tb.querySelectorAll('tr').forEach(tr => {
        const id = tr.dataset.id;
        tr.querySelector('.a-chk').onchange = e => {
          e.stopPropagation();
          if (e.target.checked) st.selected.add(id);
          else st.selected.delete(id);
        };
        tr.querySelectorAll('.act-link').forEach(b =>
          b.onclick = e => {
            e.stopPropagation();
            this.rowAction(b.dataset.act, id);
          });
        tr.querySelector('td:nth-child(2)').onclick = () =>
          { location.hash = '#/rescue?agent=' + encodeURIComponent(id); };
      });
    }

    // 全选框状态（仅当前页）
    const pageIds = items.map(a => a.agent_id);
    const allOn = pageIds.length > 0 && pageIds.every(id => st.selected.has(id));
    document.getElementById('aAll').checked = allOn;

    GK.pager(document.getElementById('aPager'), {
      page: meta.page, pages: meta.pages, total: meta.total, pageSize: meta.page_size,
      onChange: p => { st.page = p; this.load(); },
      onSize: n => { st.size = n; st.page = 1; this.load(); }
    });
  },

  toggleAll (on) {
    const st = this.state;
    document.querySelectorAll('#aBody .a-chk').forEach((c, i) => {
      c.checked = on;
      const tr = c.closest('tr');
      if (on) st.selected.add(tr.dataset.id);
      else st.selected.delete(tr.dataset.id);
    });
  },

  async rowAction (act, id) {
    if (act === 'rescue') {
      location.hash = '#/rescue?agent=' + encodeURIComponent(id);
    } else if (act === 'edit') {
      this.editAgent(id);
    } else if (act === 'clearfail') {
      await this.clearFail(id);
    } else if (act === 'del') {
      await this.deleteAgent(id);
    }
  },

  /* 编辑标签与备注 */
  editAgent (id) {
    const a = GK.cache.agents.find(x => x.agent_id === id) || {};
    GK.modal({
      title: '编辑主机：' + (a.hostname || id),
      size: 'lg',
      body:
        '<div class="form-row"><label class="form-label">标签（逗号分隔，覆盖写入）</label>' +
          '<input class="form-control" id="mTags" maxlength="200" placeholder="如：web,生产环境">' +
          '<div class="form-hint">最多 20 个标签</div></div>' +
        '<div class="form-row"><label class="form-label">备注</label>' +
          '<textarea class="form-control" id="mNotes" maxlength="256" placeholder="主机用途、负责人等"></textarea></div>',
      onOk: async () => {
        const tags = document.getElementById('mTags').value.split(',').map(x => x.trim()).filter(Boolean);
        const notes = document.getElementById('mNotes').value;
        if (tags.length > 20) { GK.toast('标签最多 20 个', 'warning'); return false; }
        await GK.api('/agents', {
          method: 'POST',
          body: { agent_id: id, tags: tags, notes: notes }
        });
        GK.toast('主机信息已更新', 'success');
        this.load(true);
      }
    });
    document.getElementById('mTags').value = (a.tags || []).join(',');
    document.getElementById('mNotes').value = a.notes || '';
  },

  async clearFail (id) {
    try {
      await GK.api('/dispatch', {
        method: 'POST',
        body: { agent_id: id, action: 'clear_fail', user: 'root' }
      });
      GK.toast('清失败计数指令已下发', 'success');
    } catch (e) {
      GK.toast(e.message || '下发失败', 'error');
    }
  },

  async deleteAgent (id) {
    const ok = await GK.confirm('确定硬删除主机 <b>' + GK.esc(GK.hostname(id)) + '</b> 吗？', {
      okText: '确认删除',
      sub: '仅离线主机允许删除；同时清除其全部历史指令，操作不可恢复'
    });
    if (!ok) return;
    try {
      await GK.api('/agents?id=' + encodeURIComponent(id), { method: 'DELETE' });
      GK.toast('主机已删除', 'success');
      this.state.selected.delete(id);
      this.load(true);
    } catch (e) {
      GK.toast(e.message || '删除失败', 'error');
    }
  },

  batchRescue () {
    const st = this.state;
    if (!st.selected.size) { GK.toast('请先勾选主机', 'warning'); return; }
    GK.pendingBatch = [...st.selected];
    location.hash = '#/rescue';
  },

  batchTag () {
    const st = this.state;
    if (!st.selected.size) { GK.toast('请先勾选主机', 'warning'); return; }
    GK.modal({
      title: '批量打标签（' + st.selected.size + ' 台主机）',
      body:
        '<div class="form-row"><label class="form-label"><span class="req">*</span>标签（逗号分隔，覆盖写入）</label>' +
          '<input class="form-control" id="mBatchTags" maxlength="200" placeholder="如：web,生产环境"></div>',
      onOk: async () => {
        const tags = document.getElementById('mBatchTags').value.split(',').map(x => x.trim()).filter(Boolean);
        if (!tags.length) { GK.toast('请填写至少一个标签', 'warning'); return false; }
        if (tags.length > 20) { GK.toast('标签最多 20 个', 'warning'); return false; }
        let fail = 0;
        for (const id of st.selected) {
          try {
            await GK.api('/agent/' + encodeURIComponent(id), {
              method: 'POST',
              body: { tags: tags }
            });
          } catch (e) { fail++; }
        }
        if (fail) GK.toast('部分主机更新失败（' + fail + ' 台）', 'warning');
        else GK.toast('已为 ' + st.selected.size + ' 台主机打标签', 'success');
        this.load(true);
      }
    });
  }
};
