/* ============================================================
 * rescue.js — 账户救援（单发 / 批量 / 组合救援 / 自定义命令）
 * ============================================================ */
GK.views.rescue = {
  title: '账户救援',

  async render (el, params) {
    // 模式判定：批量优先，其次 ?agent= 预选
    let batchIDs = null;
    if (Array.isArray(GK.pendingBatch) && GK.pendingBatch.length) {
      batchIDs = GK.pendingBatch;
      GK.pendingBatch = null;
    }
    const preAgent = (params && params.agent) || '';
    const isBatch = !!batchIDs;

    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.rescue + '账户救援</div>' +
          '<div class="page-desc">选择救援动作并下发到在线主机；密码仅在内存中传递，不落库</div></div>' +
        '<div class="page-actions">' +
          (isBatch ? '<button class="btn" id="rExitBatch">退出批量模式</button>' : '') +
        '</div>' +
      '</div>' +
      (isBatch ?
        '<div class="batch-banner"><span class="bb-ico">' + GK.icons.users + '</span>' +
          '<span>批量模式：将同时下发到 <b id="rBatchN"></b> 台主机</span></div>' : '') +
      '<div class="card">' +
        '<div class="card-body">' +
          '<div class="form-grid" style="grid-template-columns:2fr 1fr 1.6fr">' +
            '<div class="form-row"><label class="form-label">目标主机</label>' +
              '<select class="form-control" id="rAgent" ' + (isBatch ? 'disabled' : '') + '></select>' +
              (isBatch ? '<div class="form-hint">批量模式下主机由勾选列表确定</div>' : '') +
            '</div>' +
            '<div class="form-row"><label class="form-label">账户</label>' +
              '<input class="form-control" id="rUser" maxlength="64" value="root" placeholder="默认 root"></div>' +
            '<div class="form-row"><label class="form-label">救援动作</label>' +
              '<select class="form-control" id="rAction"></select></div>' +
          '</div>' +

          // 组合救援选项
          '<div class="combo-box" id="rComboOpts">' +
            '<div class="combo-title">组合项（按顺序执行）</div>' +
            '<div class="combo-chks">' +
              '<label class="chk"><input type="checkbox" id="cbFail" checked>清除失败计数</label>' +
              '<label class="chk"><input type="checkbox" id="cbUnlock" checked>解锁账户</label>' +
              '<label class="chk"><input type="checkbox" id="cbExpire" checked>关闭密码过期</label>' +
              '<label class="chk"><input type="checkbox" id="cbForce">下次登录强制改密</label>' +
            '</div>' +
          '</div>' +

          // 自定义命令
          '<div class="form-row hidden" id="rShellOpts">' +
            '<label class="form-label">命令内容</label>' +
            '<textarea class="form-control mono" id="rShellCmd" rows="3" maxlength="2000" placeholder="systemctl restart nginx"></textarea>' +
            '<div class="form-hint">通过 bash -c 执行，受 Shell 黑白名单策略限制</div>' +
          '</div>' +

          // 新密码（组合救援 / 重置密码）
          '<div class="form-row" id="rPwRow">' +
            '<label class="form-label">新密码（可选，留空不改密）</label>' +
            '<div class="pw-wrap"><input class="form-control" id="rPw" type="password" maxlength="128" placeholder="输入新密码">' +
              '<label class="chk pw-show"><input type="checkbox" id="cbShowPw">显示</label></div>' +
          '</div>' +

          '<div class="dispatch-bar">' +
            '<button class="btn btn-primary btn-lg" id="rDispatch">' + GK.icons.bolt + '<span>立即下发</span></button>' +
            '<span class="dispatch-hint">下发前自动校验主机在线状态与命令策略</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="card hidden" id="rResultCard">' +
        '<div class="card-head"><h3>下发结果</h3>' +
          '<button class="act-link" id="rGoCmds">查看指令历史</button></div>' +
        '<div class="card-body"><pre class="output-pre" id="rOutput"></pre></div>' +
      '</div>';

    // 主机下拉
    const agents = await GK.loadAgentsAll(true);
    const sel = document.getElementById('rAgent');
    GK.fillSelect(sel, agents.map(a => ({
      v: a.agent_id,
      t: (a.hostname || a.agent_id) + '（' + (a.online ? '在线' : '离线') + '）'
    })), { placeholder: '请选择目标主机' });
    const saved = localStorage.getItem('gk_rescue_agent');
    if (preAgent) sel.value = preAgent;
    else if (saved && [...sel.options].some(o => o.value === saved)) sel.value = saved;

    // 动作下拉
    const actSel = document.getElementById('rAction');
    GK.fillSelect(actSel, GK.ACTIONS.map(a => ({ v: a.v, t: a.t })), { selected: 'combo' });
    actSel.onchange = () => this.toggleSections();
    this.toggleSections();

    document.getElementById('cbShowPw').onchange = e => {
      document.getElementById('rPw').type = e.target.checked ? 'text' : 'password';
    };
    if (isBatch) document.getElementById('rBatchN').textContent = batchIDs.length;
    if (isBatch) {
      document.getElementById('rExitBatch').onclick = () => { location.hash = '#/agents'; };
    }
    document.getElementById('rGoCmds').onclick = () => { location.hash = '#/commands'; };

    document.getElementById('rDispatch').onclick = () =>
      this.dispatch(sel, isBatch ? batchIDs : null);
  },

  toggleSections () {
    const a = document.getElementById('rAction').value;
    document.getElementById('rComboOpts').classList.toggle('hidden', a !== 'combo');
    document.getElementById('rShellOpts').classList.toggle('hidden', a !== 'shell');
    document.getElementById('rPwRow').classList.toggle('hidden',
      a !== 'combo' && a !== 'reset_password');
  },

  buildParams (action) {
    const p = {};
    if (action === 'reset_password') {
      const pw = document.getElementById('rPw').value;
      if (!pw) { GK.toast('请填写新密码', 'warning'); return null; }
      p.password = pw;
      p.force_change = 'false';
    } else if (action === 'combo') {
      if (document.getElementById('cbFail').checked) p.clear_fail_count = 'true';
      if (document.getElementById('cbUnlock').checked) p.unlock_account = 'true';
      if (document.getElementById('cbExpire').checked) p.expire_never = 'true';
      if (document.getElementById('cbForce').checked) p.force_change = 'true';
      const pw = document.getElementById('rPw').value;
      if (pw) p.password = pw;
      if (!Object.keys(p).length) {
        GK.toast('请至少勾选一个组合项或填写密码', 'warning');
        return null;
      }
    }
    return p;
  },

  async dispatch (sel, batchIDs) {
    const action = document.getElementById('rAction').value;
    const user = document.getElementById('rUser').value.trim() || 'root';

    let params;
    if (action === 'shell') {
      const cmd = document.getElementById('rShellCmd').value.trim();
      if (!cmd) { GK.toast('请输入命令内容', 'warning'); return; }
      params = { command: cmd };
    } else {
      params = this.buildParams(action);
      if (params === null) return;
    }

    const btn = document.getElementById('rDispatch');
    btn.classList.add('loading');
    try {
      let out;
      if (batchIDs) {
        const r = await GK.api('/dispatch_batch', {
          method: 'POST',
          body: { agent_ids: batchIDs, action: action, user: user, params: params }
        });
        const okN = r.filter(x => x.sent).length;
        out = '批量下发完成：成功 ' + okN + ' / 共 ' + r.length + ' 台\n\n' + JSON.stringify(r, null, 2);
      } else {
        const agentID = sel.value;
        if (!agentID) { GK.toast('请选择目标主机', 'warning'); return; }
        localStorage.setItem('gk_rescue_agent', agentID);
        const r = await GK.api('/dispatch', {
          method: 'POST',
          body: { agent_id: agentID, action: action, user: user, params: params }
        });
        out = JSON.stringify(r, null, 2);
      }
      document.getElementById('rResultCard').classList.remove('hidden');
      document.getElementById('rOutput').textContent = out;
      GK.toast('指令已下发', 'success');
      document.getElementById('rResultCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (e) {
      GK.toast(e.message || '下发失败', 'error');
    } finally {
      btn.classList.remove('loading');
    }
  }
};
