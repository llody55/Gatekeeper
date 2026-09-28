/* ============================================================
 * users.js — 用户管理（新增 / 改密 / 启停 / 删除）
 * ============================================================ */
GK.views.users = {
  title: '用户管理',

  async render (el) {
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.users + '用户管理</div>' +
          '<div class="page-desc">基于三角色 RBAC 的平台账户管理</div></div>' +
        '<div class="page-actions">' +
          '<button class="btn" id="uRefresh">' + GK.icons.refresh + '刷新</button>' +
          '<button class="btn btn-primary" id="uCreate">' + GK.icons.plus + '新增用户</button>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="card-head"><h3>角色说明</h3></div>' +
        '<div class="card-body role-desc" style="padding-top:16px">' +
          '<div><span class="badge b-red">管理员</span><span>全部权限，含 Token、用户与策略管理</span></div>' +
          '<div><span class="badge b-orange">操作员</span><span>可下发救援指令、查看审计</span></div>' +
          '<div><span class="badge b-blue">审计员</span><span>只读，仅可查看工作台与审计日志</span></div>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="table-wrap">' +
          '<table class="tbl"><thead><tr>' +
            '<th>用户名</th><th>角色</th><th>邮箱</th><th>状态</th>' +
            '<th>创建时间</th><th class="col-actions">操作</th>' +
          '</tr></thead><tbody id="uBody"></tbody></table>' +
        '</div>' +
      '</div>';

    document.getElementById('uRefresh').onclick = () => this.load();
    document.getElementById('uCreate').onclick = () => this.create();

    await this.load();
  },

  async load () {
    const tb = document.getElementById('uBody');
    GK.tblSkeleton(tb, 5, 5);
    try {
      const r = await GK.api('/users');
      this.draw(r || []);
    } catch (e) {
      GK.toast(e.message || '加载失败', 'error');
    }
  },

  draw (users) {
    const tb = document.getElementById('uBody');
    if (!users.length) {
      tb.innerHTML = '<tr><td colspan="6" id="uEmpty"></td></tr>';
      GK.empty(document.getElementById('uEmpty'), '暂无用户', '点击右上角"新增用户"');
      return;
    }
    const roleBadge = r => {
      const m = { admin: 'b-red', operator: 'b-orange', auditor: 'b-blue' };
      const t = { admin: '管理员', operator: '操作员', auditor: '审计员' };
      return '<span class="badge ' + (m[r] || 'b-gray') + '">' + (t[r] || r) + '</span>';
    };
    tb.innerHTML = users.map((u, i) =>
      '<tr>' +
        '<td class="nowrap"><div class="cell-main">' +
          '<span class="mini-avatar">' + GK.esc((u.username || '?').slice(0, 2)) + '</span>' +
          '<b>' + GK.esc(u.username) + '</b></div></td>' +
        '<td class="nowrap">' + roleBadge(u.role) + '</td>' +
        '<td class="nowrap cell-sub" title="' + GK.esc(u.email || '') + '">' +
          (u.email ? GK.esc(u.email) : '<span class="muted">未绑定</span>') + '</td>' +
        '<td class="nowrap">' + (u.disabled
          ? '<span class="badge b-red">已禁用</span>'
          : '<span class="badge b-green"><span class="bd-dot"></span>正常</span>') + '</td>' +
        '<td class="nowrap cell-sub">' + GK.fmtTime(u.created_at) + '</td>' +
        '<td class="col-actions">' +
          '<button class="act-link muted" data-act="email" data-i="' + i + '">邮箱</button>' +
          '<button class="act-link muted" data-act="pw" data-i="' + i + '">' + GK.icons.lock + '改密</button>' +
          '<button class="act-link muted" data-act="toggle" data-i="' + i + '">' +
            (u.disabled ? '启用' : '禁用') + '</button>' +
          '<button class="act-link danger" data-act="delete" data-i="' + i + '">删除</button>' +
        '</td>' +
      '</tr>').join('');

    tb.querySelectorAll('.act-link').forEach(b =>
      b.onclick = () => this.action(b.dataset.act, users[parseInt(b.dataset.i, 10)]));
  },

  create () {
    GK.modal({
      title: '新增用户',
      body:
        '<div class="form-row"><label class="form-label"><span class="req">*</span>用户名</label>' +
          '<input class="form-control" id="mName" maxlength="64" placeholder="字母、数字、下划线、连字符"></div>' +
        '<div class="form-row"><label class="form-label"><span class="req">*</span>初始口令</label>' +
          '<input class="form-control" id="mPw" type="password" maxlength="128" placeholder="至少8位，含大小写/数字/特殊字符中3类"></div>' +
        '<div class="form-row"><label class="form-label">角色</label>' +
          '<select class="form-control" id="mRole">' +
            '<option value="operator">操作员</option>' +
            '<option value="auditor">审计员</option>' +
            '<option value="admin">管理员</option>' +
          '</select></div>' +
        '<div class="form-row"><label class="form-label">邮箱（选填）</label>' +
          '<input class="form-control" id="mEmail" maxlength="254" placeholder="user@example.com">' +
          '<div class="form-hint">绑定后可接收告警通知邮件</div></div>',
      onOk: async () => {
        const username = document.getElementById('mName').value.trim();
        const password = document.getElementById('mPw').value;
        const role = document.getElementById('mRole').value;
        const email = document.getElementById('mEmail').value.trim();
        if (!username || !password) { GK.toast('用户名和口令必填', 'warning'); return false; }
        await GK.api('/users', {
          method: 'POST',
          body: { username: username, password: password, role: role, email: email }
        });
        GK.toast('用户已创建', 'success');
        this.load();
      }
    });
  },

  async action (act, u) {
    if (act === 'email') {
      GK.modal({
        title: '修改邮箱：' + u.username,
        body:
          '<div class="form-row"><label class="form-label">邮箱</label>' +
            '<input class="form-control" id="mEmailEdit" maxlength="254" value="' + GK.esc(u.email || '') + '" placeholder="留空则解绑">' +
            '<div class="form-hint">admin 角色绑定的邮箱将自动接收告警通知</div></div>',
        onOk: async () => {
          const email = document.getElementById('mEmailEdit').value.trim();
          await GK.api('/users/email', {
            method: 'POST',
            body: { username: u.username, email: email }
          });
          GK.toast('邮箱已更新', 'success');
          this.load();
        }
      });
    } else if (act === 'pw') {
      GK.modal({
        title: '修改口令：' + u.username,
        body:
          '<div class="form-row"><label class="form-label"><span class="req">*</span>新口令</label>' +
            '<input class="form-control" id="mNewPw" type="password" maxlength="128" placeholder="至少8位，含大小写/数字/特殊字符中3类">' +
            '<div class="form-hint">改密后该用户所有会话将被吊销，需重新登录</div></div>',
        onOk: async () => {
          const pw = document.getElementById('mNewPw').value;
          if (!pw) { GK.toast('请输入新口令', 'warning'); return false; }
          await GK.api('/users/password', {
            method: 'POST',
            body: { username: u.username, password: pw }
          });
          GK.toast('口令已更新', 'success');
        }
      });
    } else if (act === 'toggle') {
      const disable = !u.disabled;
      let msg;
      if (disable) msg = '禁用用户 <b>' + GK.esc(u.username) + '</b>？';
      else msg = '启用用户 <b>' + GK.esc(u.username) + '</b>？';
      const ok = await GK.confirm(msg, { danger: disable });
      if (!ok) return;
      await GK.api('/users/disable', {
        method: 'POST',
        body: { username: u.username, disabled: disable }
      });
      GK.toast(disable ? '用户已禁用' : '用户已启用', 'success');
      this.load();
    } else if (act === 'delete') {
      const ok = await GK.confirm('确定删除用户 <b>' + GK.esc(u.username) + '</b> 吗？', {
        okText: '确认删除',
        sub: '硬删除且不可恢复，该用户所有会话将立即失效'
      });
      if (!ok) return;
      await GK.api('/users/delete', {
        method: 'POST',
        body: { username: u.username }
      });
      GK.toast('用户已删除', 'success');
      this.load();
    }
  }
};
