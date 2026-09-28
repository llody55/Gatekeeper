/* ============================================================
 * tokens.js — Token 管理（生成 / 绑定 / 撤销 / 删除）
 * ============================================================ */
GK.views.tokens = {
  title: 'Token 管理',

  state: { page: 1, size: 10, items: [] },

  async render (el) {
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.token + 'Token 管理</div>' +
          '<div class="page-desc">Agent 接入凭据；数据库仅存哈希，明文仅在生成时展示一次</div></div>' +
        '<div class="page-actions">' +
          '<button class="btn" id="tRefresh">' + GK.icons.refresh + '刷新</button>' +
          '<button class="btn btn-primary" id="tCreate">' + GK.icons.plus + '生成 Token</button>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="table-wrap">' +
          '<table class="tbl"><thead><tr>' +
            '<th>Token 前缀</th><th>备注</th><th>绑定主机</th>' +
            '<th>创建时间</th><th>状态</th><th class="col-actions">操作</th>' +
          '</tr></thead><tbody id="tBody"></tbody></table>' +
        '</div>' +
        '<div id="tPager"></div>' +
      '</div>';

    document.getElementById('tRefresh').onclick = () => this.load();
    document.getElementById('tCreate').onclick = () => this.create();

    await this.load();
  },

  async load () {
    const tb = document.getElementById('tBody');
    GK.tblSkeleton(tb, 6, 6);
    try {
      await GK.loadAgentsAll(true);
      const j = await GK.api('/tokens' + GK.qs({ page: this.state.page, page_size: this.state.size }));
      this.state.items = GK.items(j);
      this.draw(GK.pageMeta(j));
    } catch (e) {
      GK.toast(e.message || '加载失败', 'error');
    }
  },

  draw (meta) {
    const st = this.state;
    const tb = document.getElementById('tBody');
    if (!st.items.length) {
      tb.innerHTML = '<tr><td colspan="6" id="tEmpty"></td></tr>';
      GK.empty(document.getElementById('tEmpty'), '还没有 Token', '点击右上角"生成 Token"创建');
    } else {
      tb.innerHTML = st.items.map((t, i) => {
        let bound;
        if (t.bound_agent_id) {
          bound = '<b>' + GK.esc(t.bound_hostname || GK.hostname(t.bound_agent_id)) + '</b>' +
            '<div class="cell-sub mono">' + GK.esc(t.bound_agent_id) + '</div>';
        } else {
          bound = '<span class="cell-sub">未绑定（开放注册）</span>';
        }
        let actions;
        if (t.revoked) {
          actions =
            '<button class="act-link" data-act="bind" data-i="' + i + '">改绑定</button>' +
            '<button class="act-link danger" data-act="delete" data-i="' + i + '">删除</button>';
        } else {
          actions =
            '<button class="act-link muted" data-act="bind" data-i="' + i + '">绑定</button>' +
            '<button class="act-link danger" data-act="revoke" data-i="' + i + '">撤销</button>';
        }
        return '<tr>' +
          '<td class="mono">' + GK.esc((t.prefix || '????????')) + '…</td>' +
          '<td>' + GK.esc(t.note || '—') + '</td>' +
          '<td>' + bound + '</td>' +
          '<td class="nowrap cell-sub">' + GK.fmtTime(t.created_at) + '</td>' +
          '<td class="nowrap">' + (t.revoked
            ? '<span class="badge b-red">已撤销</span>'
            : '<span class="badge b-green"><span class="bd-dot"></span>有效</span>') + '</td>' +
          '<td class="col-actions">' + actions + '</td>' +
        '</tr>';
      }).join('');

      tb.querySelectorAll('.act-link').forEach(b =>
        b.onclick = () => this.action(b.dataset.act, parseInt(b.dataset.i, 10)));
    }

    GK.pager(document.getElementById('tPager'), {
      page: meta.page, pages: meta.pages, total: meta.total, pageSize: meta.page_size,
      onChange: p => { st.page = p; this.load(); },
      onSize: n => { st.size = n; st.page = 1; this.load(); }
    });
  },

  /* 生成：第一步收集信息，第二步展示明文 */
  create () {
    GK.modal({
      title: '生成 Agent Token',
      body:
        '<div class="form-row"><label class="form-label">备注</label>' +
          '<input class="form-control" id="mNote" maxlength="256" placeholder="如：web-01 / 2026 批次"></div>' +
        '<div class="form-row"><label class="form-label">绑定主机（可选）</label>' +
          '<select class="form-control" id="mBind"><option value="">不绑定，走自动绑定</option></select>' +
          '<div class="form-hint">创建即绑定后，该 Token 只能注册指定主机，防止冒名</div></div>',
      onOk: async () => {
        const note = document.getElementById('mNote').value;
        const bind = document.getElementById('mBind').value;
        const r = await GK.api('/tokens', {
          method: 'POST',
          body: { note: note, bind_agent_id: bind }
        });
        this.showPlainToken(r);
        this.state.page = 1;
        this.load();
      }
    });
    // 填充可绑定主机
    GK.loadAgentsAll(true).then(agents => {
      const sel = document.getElementById('mBind');
      if (!sel) return;
      agents.forEach(a => {
        const o = document.createElement('option');
        o.value = a.agent_id;
        o.textContent = (a.hostname || a.agent_id) + '（' + a.agent_id + '）';
        sel.appendChild(o);
      });
    });
  },

  /* 明文仅展示一次 */
  showPlainToken (r) {
    GK.modal({
      title: 'Token 生成成功',
      size: 'lg',
      okText: '我已妥善保存',
      body:
        '<div class="token-alert">' + GK.icons.warn +
          '<span>该 Token 仅展示这一次，关闭后无法再次查看，请立即复制保存</span></div>' +
        '<div class="token-box"><span class="token-txt" id="mFullTok"></span>' +
          '<button class="btn btn-sm" id="mCopyTok">复制</button></div>' +
        '<div class="form-hint" style="margin:10px 0 4px">Agent 安装命令：</div>' +
        '<pre class="output-pre" id="mInstall"></pre>',
      onOk: () => {}
    });
    document.getElementById('mFullTok').textContent = r.token;
    document.getElementById('mCopyTok').onclick = async () => {
      if (await GK.copy(r.token)) {
        GK.toast('已复制到剪贴板', 'success');
      } else GK.toast('复制失败，请手动选择', 'warning');
    };
    const install = 'gatekeeper-agent -server <SERVER_URL> -token ' + r.token;
    document.getElementById('mInstall').textContent = install;
  },

  async action (act, i) {
    const t = this.state.items[i];
    if (act === 'revoke') {
      const ok = await GK.confirm('确定撤销 Token <b>' + GK.esc(t.prefix) + '…</b> 吗？', {
        okText: '确认撤销',
        sub: '撤销后其关联 Agent 将立即下线且无法重连'
      });
      if (!ok) return;
      await GK.api('/tokens/revoke', { method: 'POST', body: { token: t.token } });
      GK.toast('Token 已撤销', 'success');
      this.load();
    } else if (act === 'delete') {
      const ok = await GK.confirm('硬删除 Token <b>' + GK.esc(t.prefix) + '…</b> 吗？', {
        okText: '确认删除',
        sub: '删除后不可恢复'
      });
      if (!ok) return;
      await GK.api('/tokens/delete', { method: 'POST', body: { token: t.token } });
      GK.toast('Token 已删除', 'success');
      this.load();
    } else if (act === 'bind') {
      this.bind(t);
    }
  },

  /* 设置 / 修改绑定 */
  bind (t) {
    GK.modal({
      title: '绑定 Token 到主机',
      body:
        '<div class="form-row"><label class="form-label"><span class="req">*</span>目标主机</label>' +
          '<select class="form-control" id="mBindSel"></select></div>',
      onOk: async () => {
        const agentID = document.getElementById('mBindSel').value;
        if (!agentID) { GK.toast('请选择目标主机', 'warning'); return false; }
        await GK.api('/tokens/bind', {
          method: 'POST',
          body: { token: t.token, agent_id: agentID }
        });
        GK.toast('绑定关系已更新', 'success');
        this.load();
      }
    });
    GK.loadAgentsAll(true).then(agents => {
      const sel = document.getElementById('mBindSel');
      if (!sel) return;
      agents.forEach(a => {
        const o = document.createElement('option');
        o.value = a.agent_id;
        o.textContent = (a.hostname || a.agent_id) + '（' + a.agent_id + '）';
        if (a.agent_id === t.bound_agent_id) o.selected = true;
        sel.appendChild(o);
      });
    });
  }
};
