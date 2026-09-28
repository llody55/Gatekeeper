/* ============================================================
 * shell.js — Shell 策略（全局策略 + 黑白名单规则）
 * ============================================================ */
GK.views.shell = {
  title: 'Shell 策略',

  rules: [],

  async render (el) {
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.shield + 'Shell 策略</div>' +
          '<div class="page-desc">控制自定义命令下发的开关、执行限制与黑白名单</div></div>' +
        '<div class="page-actions">' +
          '<button class="btn btn-primary" id="hSavePolicy">' + GK.icons.check + '保存策略</button>' +
        '</div>' +
      '</div>' +

      '<div class="card">' +
        '<div class="card-head"><h3>全局策略</h3></div>' +
        '<div class="card-body">' +
          '<div class="policy-row">' +
            '<div class="policy-item"><span class="form-label">Shell 下发开关</span>' +
              '<label class="switch"><input type="checkbox" id="hEnabled"><span class="slider-sw"></span></label></div>' +
            '<div class="policy-item"><span class="form-label">执行超时（秒）</span>' +
              '<input class="form-control" id="hTimeout" type="number" min="1" max="600" style="max-width:120px"></div>' +
            '<div class="policy-item"><span class="form-label">输出截断（字节）</span>' +
              '<input class="form-control" id="hMaxOutput" type="number" min="1024" max="1048576" style="max-width:140px"></div>' +
            '<div class="policy-item"><span class="form-label">匹配模式</span>' +
              '<select class="form-control" id="hMatchMode" style="max-width:200px">' +
                '<option value="legacy">legacy（* 匹配任意）</option>' +
                '<option value="permissive">permissive（允许所有）</option>' +
                '<option value="strict_chars">strict_chars（拒绝元字符）</option>' +
                '<option value="strict_glob">strict_glob（严格通配）</option>' +
              '</select></div>' +
          '</div>' +
          '<div class="mode-hint"><b>legacy</b>：* 可匹配任意字符；<b>permissive</b>：跳过黑白名单；' +
            '<b>strict_chars</b>：含元字符即拒；<b>strict_glob</b>：* 不匹配元字符，精确规则允许管道</div>' +
        '</div>' +
      '</div>' +

      '<div class="split-2">' +
        '<div class="card">' +
          '<div class="card-head"><h3>白名单</h3></div>' +
          '<div class="card-body" style="padding-bottom:14px">' +
            '<div class="rule-add">' +
              '<input class="form-control" id="wlPattern" maxlength="500" placeholder="模式，如 systemctl *">' +
              '<input class="form-control" id="wlNote" maxlength="256" placeholder="说明（可选）">' +
              '<button class="btn btn-primary btn-sm" id="wlAdd">添加</button>' +
            '</div>' +
          '</div>' +
          '<div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th>模式</th><th>说明</th><th style="width:58px">启用</th><th class="col-actions">操作</th>' +
          '</tr></thead><tbody id="wlBody"></tbody></table></div>' +
        '</div>' +
        '<div class="card">' +
          '<div class="card-head"><h3>黑名单</h3></div>' +
          '<div class="card-body" style="padding-bottom:14px">' +
            '<div class="rule-add">' +
              '<input class="form-control" id="blPattern" maxlength="500" placeholder="模式，如 rm -rf /*">' +
              '<input class="form-control" id="blNote" maxlength="256" placeholder="说明（可选）">' +
              '<button class="btn btn-danger-solid btn-sm" id="blAdd">添加</button>' +
            '</div>' +
          '</div>' +
          '<div class="table-wrap"><table class="tbl"><thead><tr>' +
            '<th>模式</th><th>说明</th><th style="width:58px">启用</th><th class="col-actions">操作</th>' +
          '</tr></thead><tbody id="blBody"></tbody></table></div>' +
        '</div>' +
      '</div>';

    document.getElementById('hSavePolicy').onclick = () => this.savePolicy();
    document.getElementById('wlAdd').onclick = () => this.addRule('whitelist');
    document.getElementById('blAdd').onclick = () => this.addRule('blacklist');

    await Promise.allSettled([this.loadPolicy(), this.loadRules()]);
  },

  async loadPolicy () {
    try {
      const d = await GK.api('/shell/policy');
      document.getElementById('hEnabled').checked = !!d.enabled;
      document.getElementById('hTimeout').value = d.timeout;
      document.getElementById('hMaxOutput').value = d.max_output;
      document.getElementById('hMatchMode').value = d.match_mode || 'legacy';
    } catch (e) {
      GK.toast('策略加载失败：' + e.message, 'error');
    }
  },

  async savePolicy () {
    const body = {
      enabled: document.getElementById('hEnabled').checked,
      timeout: parseInt(document.getElementById('hTimeout').value, 10),
      max_output: parseInt(document.getElementById('hMaxOutput').value, 10),
      match_mode: document.getElementById('hMatchMode').value
    };
    if (!body.timeout || body.timeout < 1 || body.timeout > 600) {
      GK.toast('超时必须在 1~600 秒之间', 'warning');
      return;
    }
    if (!body.max_output || body.max_output < 1024 || body.max_output > 1048576) {
      GK.toast('输出截断必须在 1024~1048576 字节之间', 'warning');
      return;
    }
    try {
      await GK.api('/shell/policy', { method: 'POST', body: body });
      GK.toast('策略已保存并即时生效', 'success');
    } catch (e) {
      GK.toast(e.message || '保存失败', 'error');
    }
  },

  async loadRules () {
    try {
      const r = await GK.api('/shell/rules');
      this.rules = Array.isArray(r) ? r : [];
      this.drawRules();
    } catch (e) {
      GK.toast('规则加载失败：' + e.message, 'error');
    }
  },

  drawRules () {
    const wl = this.rules.filter(r => r.type === 'whitelist');
    const bl = this.rules.filter(r => r.type === 'blacklist');
    this.drawTable('wlBody', wl);
    this.drawTable('blBody', bl);
  },

  drawTable (tbId, rules) {
    const tb = document.getElementById(tbId);
    if (!rules.length) {
      tb.innerHTML = '<tr><td colspan="4" class="cell-sub" style="text-align:center;padding:22px">暂无规则</td></tr>';
      return;
    }
    tb.innerHTML = rules.map(r =>
      '<tr data-id="' + r.id + '">' +
        '<td class="mono">' + GK.esc(r.pattern) + '</td>' +
        '<td class="cell-sub">' + GK.esc(r.note || '—') + '</td>' +
        '<td><label class="switch"><input type="checkbox" ' + (r.enabled ? 'checked' : '') +
          ' data-id="' + r.id + '"><span class="slider-sw"></span></label></td>' +
        '<td class="col-actions">' +
          '<button class="act-link muted" data-act="edit" data-id="' + r.id + '">编辑</button>' +
          '<button class="act-link danger" data-act="del" data-id="' + r.id + '">删除</button>' +
        '</td>' +
      '</tr>').join('');

    tb.querySelectorAll('.switch input').forEach(c =>
      c.onchange = () => this.toggleRule(c.dataset.id, c.checked));
    tb.querySelectorAll('.act-link').forEach(b =>
      b.onclick = () => {
        const id = parseInt(b.dataset.id, 10);
        if (b.dataset.act === 'edit') this.editRule(id);
        else this.deleteRule(id);
      });
  },

  async addRule (type) {
    const pre = type === 'whitelist' ? 'wl' : 'bl';
    const pattern = document.getElementById(pre + 'Pattern').value.trim();
    const note = document.getElementById(pre + 'Note').value.trim();
    if (!pattern) { GK.toast('请输入模式', 'warning'); return; }
    try {
      await GK.api('/shell/rules', {
        method: 'POST',
        body: { type: type, pattern: pattern, note: note }
      });
      GK.toast('规则已添加', 'success');
      document.getElementById(pre + 'Pattern').value = '';
      document.getElementById(pre + 'Note').value = '';
      this.loadRules();
    } catch (e) {
      GK.toast(e.message || '添加失败', 'error');
    }
  },

  editRule (id) {
    const r = this.rules.find(x => x.id === id);
    if (!r) return;
    GK.modal({
      title: '编辑规则',
      body:
        '<div class="form-row"><label class="form-label"><span class="req">*</span>模式</label>' +
          '<input class="form-control mono" id="mPattern" maxlength="500"></div>' +
        '<div class="form-row"><label class="form-label">说明</label>' +
          '<input class="form-control" id="mNote" maxlength="256"></div>',
      onOk: async () => {
        const pattern = document.getElementById('mPattern').value.trim();
        const note = document.getElementById('mNote').value.trim();
        if (!pattern) { GK.toast('模式不能为空', 'warning'); return false; }
        await GK.api('/shell/rules/update', {
          method: 'POST',
          body: { id: id, pattern: pattern, note: note, enabled: r.enabled }
        });
        GK.toast('规则已更新', 'success');
        this.loadRules();
      }
    });
    document.getElementById('mPattern').value = r.pattern;
    document.getElementById('mNote').value = r.note || '';
  },

  async toggleRule (id, enabled) {
    try {
      await GK.api('/shell/rules/update', {
        method: 'POST',
        // pattern 留空 -> 服务端保留原模式与说明，仅切换启用状态
        body: { id: parseInt(id, 10), pattern: '', note: '', enabled: enabled }
      });
      GK.toast(enabled ? '规则已启用' : '规则已停用', 'success');
      this.loadRules();
    } catch (e) {
      GK.toast(e.message || '更新失败', 'error');
      this.loadRules();
    }
  },

  async deleteRule (id) {
    const ok = await GK.confirm('确定删除该规则吗？', { okText: '确认删除' });
    if (!ok) return;
    await GK.api('/shell/rules/delete', {
      method: 'POST',
      body: { id: id }
    });
    GK.toast('规则已删除', 'success');
    this.loadRules();
  }
};
