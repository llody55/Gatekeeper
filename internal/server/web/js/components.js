/* ============================================================
 * components.js — 统一 UI 组件库
 * 图标 / Toast / Modal / Confirm / Pager / 状态框 / 复制
 * ============================================================ */
(function () {

  /* ---------- SVG 图标集（currentColor 着色） ---------- */
  const svg = (p) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + p + '</svg>';
  GK.icons = {
    dashboard: svg('<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>'),
    server: svg('<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><circle cx="7" cy="7.5" r="1" fill="currentColor"/><circle cx="7" cy="16.5" r="1" fill="currentColor"/>'),
    rescue: svg('<path d="M14.7 6.3a4.5 4.5 0 0 0-6.4 6.4l-5 5 3 3 5-5a4.5 4.5 0 0 0 6.4-6.4l-2.8 2.8-2.2-.8-.8-2.2z"/>'),
    history: svg('<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 4v4h4"/><path d="M12 8v4l3 2"/>'),
    audit: svg('<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>'),
    scan: svg('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/><path d="M8 11h6M11 8v6"/>'),
    token: svg('<rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'),
    users: svg('<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.6-3.4 3.2-5 6.5-5s5.9 1.6 6.5 5"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8"/><path d="M18 15.2c2 .8 3.2 2.4 3.5 4.8"/>'),
    shield: svg('<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>'),
    plus: svg('<path d="M12 5v14M5 12h14"/>'),
    refresh: svg('<path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 3v6h-6"/>'),
    edit: svg('<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>'),
    trash: svg('<path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>'),
    check: svg('<path d="M20 6L9 17l-5-5"/>'),
    warn: svg('<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 17.5v.5"/>'),
    info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7.5v.5"/>'),
    error: svg('<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>'),
    empty: svg('<path d="M20 7H4a1 1 0 0 0-1 1v9a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V8a1 1 2 0 0-1-1z"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/>'),
    copy: svg('<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
    logout: svg('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>'),
    tag: svg('<path d="M20.6 13.4l-7.2 7.2a2 2 0 0 1-2.8 0l-6.6-6.6A2 2 0 0 1 3.4 12.6V5a2 2 0 0 1 2-2h7.6a2 2 0 0 1 1.4.6l6.2 6.2a2 2 0 0 1 0 2.6z"/><circle cx="7.5" cy="7.5" r="1"/>'),
    bolt: svg('<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>'),
    inbox: svg('<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.1L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.7 4H7.3a2 2 0 0 0-1.8 1.1z"/>'),
    clock: svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
    terminal: svg('<path d="M4 17l6-5-6-5"/><path d="M12 19h8"/>'),
    user: svg('<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4.5 4.5-6.5 8-6.5s7 2 8 6.5"/>'),
    lock: svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v4"/>')
  };

  /* ---------- Toast ---------- */
  const stack = () => document.getElementById('toastStack');
  GK.toast = function (msg, type, duration) {
    type = type || 'info';
    duration = duration || 2600;
    const ico = { success: 'check', error: 'error', warning: 'warn', info: 'info' }[type] || 'info';
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.innerHTML = '<span class="toast-ico" style="-webkit-mask-image:none">' +
      '<span class="ti-svg">' + GK.icons[ico] + '</span></span>' +
      '<span class="toast-msg"></span>';
    el.querySelector('.toast-msg').textContent = msg;
    stack().appendChild(el);
    setTimeout(() => {
      el.classList.add('out');
      setTimeout(() => el.remove(), 260);
    }, duration);
  };

  /* ---------- Modal ----------
   * GK.modal({ title, body(HTML|Node), size:'sm'|'md'|'lg',
   *           okText, cancelText, onOk(async), hideFoot, hideClose })
   * 返回 { close, el }
   */
  GK.modal = function (opt) {
    opt = opt || {};
    const root = document.getElementById('modalRoot');
    const mask = document.createElement('div');
    mask.className = 'modal-mask';
    const sizeCls = opt.size === 'lg' ? 'lg' : (opt.size === 'sm' ? 'sm' : '');
    mask.innerHTML =
      '<div class="modal ' + sizeCls + '">' +
        '<div class="modal-head">' +
          '<h3></h3>' +
          (opt.hideClose ? '' : '<button class="modal-close">&times;</button>') +
        '</div>' +
        '<div class="modal-body"></div>' +
        (opt.hideFoot ? '' :
          '<div class="modal-foot">' +
            '<button class="btn modal-cancel"></button>' +
            '<button class="btn btn-primary modal-ok"><span class="btn-label"></span><span class="spinner"></span></button>' +
          '</div>') +
      '</div>';
    const modal = mask.querySelector('.modal');
    mask.querySelector('h3').textContent = opt.title || '';
    const body = mask.querySelector('.modal-body');
    if (opt.body instanceof Node) body.appendChild(opt.body);
    else body.innerHTML = opt.body || '';

    let closed = false, notified = false;
    const notify = function (reason) {
      if (!notified) { notified = true; if (opt.onClose) opt.onClose(reason); }
    };
    const close = function (reason) {
      if (closed) return;
      closed = true;
      notify(reason || 'close');
      mask.classList.remove('show');
      setTimeout(() => { mask.remove(); }, 220);
      document.removeEventListener('keydown', onKey);
    };

    if (!opt.hideClose) {
      mask.querySelector('.modal-close').onclick = () => close('x');
    }
    mask.addEventListener('mousedown', e => { if (e.target === mask && opt.maskClose !== false) close('mask'); });
    function onKey (e) {
      if (e.key === 'Escape' && opt.maskClose !== false) close('esc');
    }
    document.addEventListener('keydown', onKey);

    if (!opt.hideFoot) {
      const okBtn = mask.querySelector('.modal-ok');
      const cancelBtn = mask.querySelector('.modal-cancel');
      okBtn.querySelector('.btn-label').textContent = opt.okText || '确 定';
      cancelBtn.textContent = opt.cancelText || '取 消';
      cancelBtn.onclick = () => close('cancel');
      okBtn.onclick = async function () {
        if (opt.onOk) {
          okBtn.classList.add('loading');
          try {
            const r = await opt.onOk(modal, close);
            if (r !== false) close('ok');
          } catch (e) {
            GK.toast(e.message || '操作失败', 'error');
          } finally {
            okBtn.classList.remove('loading');
          }
        } else close('ok');
      };
    }

    root.appendChild(mask);
    requestAnimationFrame(() => requestAnimationFrame(() => mask.classList.add('show')));
    // 自动聚焦首个可编辑元素
    setTimeout(() => {
      if (opt.noFocus) return;
      const f = modal.querySelector('input:not([type=hidden]),select,textarea') ||
        modal.querySelector('button');
      if (f) f.focus();
    }, 130);

    return { close: close, el: modal, mask: mask };
  };

  /* ---------- Confirm（Promise<boolean>） ---------- */
  GK.confirm = function (message, opts) {
    opts = opts || {};
    const danger = opts.danger !== false;
    return new Promise(resolve => {
      const m = GK.modal({
        title: opts.title || '操作确认',
        size: 'sm',
        okText: opts.okText || '确认',
        cancelText: '取消',
        body:
          '<div class="confirm-body">' +
            '<span class="confirm-ico ' + (danger ? 'danger' : 'warn') + '">' +
              GK.icons[danger ? 'warn' : 'info'] + '</span>' +
            '<div><div class="confirm-txt"></div>' +
              (opts.sub ? '<div class="confirm-sub"></div>' : '') + '</div>' +
          '</div>',
        onClose: (reason) => resolve(reason === 'ok')
      });
      m.el.querySelector('.confirm-txt').innerHTML = message;
      if (opts.sub) m.el.querySelector('.confirm-sub').textContent = opts.sub;
    });
  };

  /* ---------- 分页器 ----------
   * GK.pager(el, { page, pages, total, pageSize, onChange, onSize })
   */
  GK.pager = function (el, st) {
    el.className = 'pager';
    el.innerHTML = '';
    const info = document.createElement('span');
    info.className = 'pager-info';
    info.textContent = st.total > 0 ? ('共 ' + st.total + ' 条记录' + (st.pages > 1 ? '，第 ' + st.page + ' / ' + st.pages + ' 页' : '')) : '';
    el.appendChild(info);

    const right = document.createElement('div');
    right.className = 'pager-pages';
    el.appendChild(right);
    if (st.pages > 1) {
      const addBtn = (label, p, active) => {
        const b = document.createElement('button');
        b.className = 'pg-btn' + (active ? ' active' : '');
        b.textContent = label;
        b.onclick = () => st.onChange(p);
        right.appendChild(b);
        return b;
      };
      const addE = () => { const s = document.createElement('span'); s.className = 'pg-ellipsis'; s.textContent = '…'; right.appendChild(s); };
      addBtn('‹', Math.max(1, st.page - 1));
      const win = 1;
      for (let p = 1; p <= st.pages; p++) {
        if (p === 1 || p === st.pages || Math.abs(p - st.page) <= win) addBtn(p, p, p === st.page);
        else if (Math.abs(p - st.page) === win + 1) addE();
      }
      addBtn('›', Math.min(st.pages, st.page + 1));
    }

    const sz = document.createElement('select');
    sz.className = 'form-control pg-size';
    [10, 20, 50, 100, 200].forEach(n => {
      const o = document.createElement('option');
      o.value = n; o.textContent = n + ' 条/页';
      if (n === st.pageSize) o.selected = true;
      sz.appendChild(o);
    });
    sz.onchange = () => { st.onSize(parseInt(sz.value, 10)); };
    right.appendChild(sz);
  };

  /* ---------- 状态框 ---------- */
  GK.empty = function (el, title, desc) {
    el.innerHTML =
      '<div class="state-box">' +
        '<div class="state-ico">' + GK.icons.empty + '</div>' +
        '<div class="state-title"></div>' +
        (desc ? '<div class="state-desc"></div>' : '') +
      '</div>';
    el.querySelector('.state-title').textContent = title || '暂无数据';
    if (desc) el.querySelector('.state-desc').textContent = desc;
  };

  GK.loading = function (el, text) {
    el.innerHTML =
      '<div class="loading-box"><div class="big-spinner"></div><div></div></div>';
    el.querySelector('div:last-child').textContent = text || '数据加载中…';
  };

  /* 表格骨架屏 */
  GK.tblSkeleton = function (tb, cols, rows) {
    let h = '';
    for (let i = 0; i < (rows || 6); i++) {
      h += '<tr>';
      for (let c = 0; c < cols; c++) h += '<td><div class="skeleton" style="height:13px;width:' + (55 + ((i + c) % 4) * 9) + '%"></div></td>';
      h += '</tr>';
    }
    tb.innerHTML = h;
  };

  /* ---------- 复制到剪贴板 ---------- */
  GK.copy = async function (text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (e2) {}
      ta.remove();
      return ok;
    }
  };

  /* ---------- 小工具：填充 select ---------- */
  GK.fillSelect = function (sel, items, opt) {
    opt = opt || {};
    const cur = sel.value;
    sel.innerHTML = '';
    if (opt.placeholder) {
      const o = document.createElement('option');
      o.value = opt.valueKey ? '' : (opt.allValue || '');
      o.textContent = opt.placeholder;
      sel.appendChild(o);
    }
    items.forEach(it => {
      const o = document.createElement('option');
      if (typeof it === 'string') { o.value = it; o.textContent = it; }
      else { o.value = it[opt.valueKey || 'v']; o.textContent = it[opt.textKey || 't']; }
      sel.appendChild(o);
    });
    if (cur && [...sel.options].some(o => o.value === cur)) sel.value = cur;
    else if (opt.selected) sel.value = opt.selected;
  };

})();
