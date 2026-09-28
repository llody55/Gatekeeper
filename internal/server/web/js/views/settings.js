/* ============================================================
 * settings.js — 系统设置（告警通知运行时配置）
 * 运行时可变配置存 settings 表, Web 端热更, 无需重启 server。
 * 基础设施(SMTP 服务器/认证)仍在配置文件中。
 * ============================================================ */
GK.views.settings = {
  title: '系统设置',

  async render (el) {
    el.innerHTML =
      '<div class="page-head">' +
        '<div><div class="page-title">' + GK.icons.shield + '系统设置</div>' +
          '<div class="page-desc">运行时可变配置（告警通知、邮件收件人等），保存后立即生效，无需重启</div></div>' +
        '<div class="page-actions">' +
          '<button class="btn btn-primary" id="sSave">' + GK.icons.check + '保存设置</button>' +
        '</div>' +
      '</div>' +

      '<div class="card">' +
        '<div class="card-head"><h3>告警通知</h3>' +
          '<span class="card-sub">agent 离线 / 账户过期时通过 webhook 或邮件推送</span></div>' +
        '<div class="card-body">' +
          '<div class="policy-row">' +
            '<div class="policy-item"><span class="form-label">告警总开关</span>' +
              '<label class="switch"><input type="checkbox" id="sEnabled"><span class="slider-sw"></span></label></div>' +
          '</div>' +
          '<div class="policy-row">' +
            '<div class="policy-item" style="flex:2"><span class="form-label">Webhook 地址</span>' +
              '<input class="form-control" id="sWebhook" placeholder="https://oapi.dingtalk.com/robot/send?access_token=...">' +
              '<div class="form-hint">POST JSON，留空则不发 webhook。可在配置文件 alerts.webhook_url 设默认值</div></div>' +
          '</div>' +
          '<div class="policy-row">' +
            '<div class="policy-item" style="flex:2"><span class="form-label">邮件收件人</span>' +
              '<input class="form-control" id="sEmailTo" placeholder="ops@example.com, oncall@example.com">' +
              '<div class="form-hint">多个地址用逗号分隔。SMTP 服务器/认证在配置文件 alerts.email 中配置</div>' +
              '<div id="sAdminEmails" class="form-hint" style="margin-top:6px"></div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="card">' +
        '<div class="card-head"><h3>账户过期告警</h3>' +
          '<span class="card-sub">巡检发现账户过期或即将过期时推送通知</span></div>' +
        '<div class="card-body">' +
          '<div class="policy-row">' +
            '<div class="policy-item"><span class="form-label">启用账户过期告警</span>' +
              '<label class="switch"><input type="checkbox" id="sAcctEnabled"><span class="slider-sw"></span></label></div>' +
            '<div class="policy-item"><span class="form-label">提前预警天数</span>' +
              '<input class="form-control" id="sWarnDays" type="number" min="0" max="365" style="max-width:120px"></div>' +
          '</div>' +
          '<div class="mode-hint">状态为 <b>expired</b> / <b>password_expired</b> 的账户立即告警；' +
            '状态为 <b>active</b> 但距密码过期 ≤ 预警天数的账户也会告警</div>' +
        '</div>' +
      '</div>';

    document.getElementById('sSave').onclick = () => this.save();
    await this.load();
  },

  async load () {
    try {
      const j = await GK.api('/settings');
      const a = j.alerts || {};
      document.getElementById('sEnabled').checked = !!a.enabled;
      document.getElementById('sWebhook').value = a.webhook_url || '';
      document.getElementById('sEmailTo').value = a.email_to || '';
      const adminEmails = a.admin_emails || [];
      const ae = document.getElementById('sAdminEmails');
      if (adminEmails.length) {
        ae.innerHTML = '管理员已绑定邮箱（自动接收告警）：<b>' + adminEmails.map(GK.esc).join('</b>, <b>') + '</b>';
      } else {
        ae.innerHTML = '<span class="muted">暂无管理员绑定邮箱，可在「用户管理」中为 admin 设置邮箱</span>';
      }
      document.getElementById('sAcctEnabled').checked = !!a.account_expired_enabled;
      document.getElementById('sWarnDays').value = a.warn_days != null ? a.warn_days : 7;
    } catch (e) {
      GK.toast('加载设置失败: ' + e.message, 'error');
    }
  },

  async save () {
    const body = {
      alerts: {
        enabled: document.getElementById('sEnabled').checked,
        webhook_url: document.getElementById('sWebhook').value.trim(),
        email_to: document.getElementById('sEmailTo').value.trim(),
        account_expired_enabled: document.getElementById('sAcctEnabled').checked,
        warn_days: parseInt(document.getElementById('sWarnDays').value, 10) || 0
      }
    };
    try {
      await GK.api('/settings', { method: 'POST', body: body });
      GK.toast('设置已保存', 'success');
    } catch (e) {
      GK.toast('保存失败: ' + e.message, 'error');
    }
  }
};
