/*
 * bindconsole — UI 基础组件
 * 所有动态文本只用 textContent / text node 渲染，禁止 innerHTML 拼接（防 XSS）。
 */
(function () {
  'use strict';

  var BC = (window.BC = window.BC || {});
  var fieldIdSeq = 0;

  /* ---------- DOM ---------- */

  var PROPERTY_KEYS = {
    value: 1, checked: 1, disabled: 1, selected: 1, readOnly: 1,
    required: 1, multiple: 1, autofocus: 1, indeterminate: 1
  };

  function appendChildren(node, children) {
    if (children === undefined || children === null || children === false) return;
    if (Array.isArray(children)) {
      for (var i = 0; i < children.length; i++) appendChildren(node, children[i]);
      return;
    }
    if (children instanceof Node) { node.appendChild(children); return; }
    node.appendChild(document.createTextNode(String(children)));
  }

  /**
   * 创建元素。attrs 中的字符串一律走属性 / textContent，绝不解析 HTML。
   * 友情提示：不要在 attrs 里传 innerHTML（会被忽略并抛错）。
   */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === undefined || value === null || value === false) return;
        if (key === 'text') { node.textContent = String(value); return; }
        if (key === 'class' || key === 'className') { node.className = String(value); return; }
        if (key === 'html' || key === 'innerHTML') {
          throw new Error('bindconsole UI: innerHTML is forbidden, use textContent');
        }
        if (key === 'dataset') {
          Object.keys(value).forEach(function (k) {
            if (value[k] !== undefined && value[k] !== null) node.dataset[k] = String(value[k]);
          });
          return;
        }
        if (key === 'style' && typeof value === 'object') {
          Object.keys(value).forEach(function (k) { node.style[k] = value[k]; });
          return;
        }
        if (key.indexOf('on') === 0 && typeof value === 'function') {
          node.addEventListener(key.slice(2).toLowerCase(), value);
          return;
        }
        if (PROPERTY_KEYS[key]) { node[key] = value; return; }
        if (value === true) { node.setAttribute(key, ''); return; }
        node.setAttribute(key, String(value));
      });
    }
    appendChildren(node, children);
    return node;
  }

  function clear(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function setText(node, value) {
    node.textContent = (value === undefined || value === null) ? '' : String(value);
    return node;
  }

  function button(opts) {
    opts = opts || {};
    var cls = 'btn';
    if (opts.variant === 'primary') cls += ' btn-primary';
    else if (opts.variant === 'danger') cls += ' btn-danger';
    else if (opts.variant === 'ghost') cls += ' btn-ghost';
    if (opts.small) cls += ' btn-sm';
    var btn = el('button', {
      type: opts.type || 'button',
      'class': cls + (opts.className ? ' ' + opts.className : ''),
      text: opts.label || '',
      disabled: opts.disabled || false,
      'data-testid': opts.testid,
      form: opts.form
    });
    if (opts.onClick) btn.addEventListener('click', opts.onClick);
    return btn;
  }

  function btnLink(label, opts) {
    opts = opts || {};
    return el('button', {
      type: 'button',
      'class': 'btn-link' + (opts.danger ? ' danger' : '') + (opts.className ? ' ' + opts.className : ''),
      text: label,
      disabled: opts.disabled || false,
      'data-testid': opts.testid
    }, null);
  }

  /* ---------- 格式化 ---------- */

  function pad2(n) { return n < 10 ? '0' + n : String(n); }

  function parseTime(value) {
    if (!value) return null;
    var t = Date.parse(value);
    if (isNaN(t)) return null;
    return t;
  }

  function fmtDateTime(value) {
    var t = parseTime(value);
    if (t === null) return value ? String(value) : '—';
    var d = new Date(t);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
      ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }

  function fmtTime(value) {
    var t = parseTime(value);
    if (t === null) return value ? String(value) : '—';
    var d = new Date(t);
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }

  function countdown(value, now) {
    var t = parseTime(value);
    if (t === null) return { text: '—', state: 'unknown' };
    now = now || Date.now();
    var ms = t - now;
    if (ms <= 0) return { text: '已过期', state: 'expired', ms: ms };
    var s = Math.floor(ms / 1000);
    var d = Math.floor(s / 86400); s -= d * 86400;
    var h = Math.floor(s / 3600); s -= h * 3600;
    var m = Math.floor(s / 60); var sec = s - m * 60;
    var text;
    if (d > 0) text = '剩 ' + d + '天' + h + '小时';
    else if (h > 0) text = '剩 ' + h + '小时' + m + '分';
    else if (m > 0) text = '剩 ' + m + '分' + pad2(sec) + '秒';
    else text = '剩 ' + sec + '秒';
    return { text: text, state: ms < 60000 ? 'urgent' : 'normal', ms: ms };
  }

  function truncate(text, max) {
    var s = text === undefined || text === null ? '' : String(text);
    if (s.length <= max) return s;
    return s.slice(0, Math.max(0, max - 1)) + '…';
  }

  /* ---------- 徽章 / 小件 ---------- */

  function badge(text, tone, opts) {
    opts = opts || {};
    var cls = 'badge';
    if (tone) cls += ' badge-' + tone;
    if (opts.plain) cls += ' badge-plain';
    var node = el('span', { 'class': cls });
    node.textContent = text;
    if (opts.title) node.title = opts.title;
    return node;
  }

  function chip(text, title) {
    var node = el('span', { 'class': 'chip', text: text });
    if (title) node.title = title;
    return node;
  }

  function flag(value, yes, no) {
    if (value === true) return el('span', { 'class': 'flag flag-yes', text: yes || '✓' });
    if (value === false) return el('span', { 'class': 'flag flag-no', text: no || '✗' });
    return el('span', { 'class': 'flag flag-unknown', text: '—' });
  }

  /* ---------- 表单 ---------- */

  function bindLabel(wrap, labelText, control, required) {
    var id = control.id || ('bc-field-' + (++fieldIdSeq));
    if (!control.id) control.id = id;
    var label = el('label', { 'class': 'field-label', 'for': id });
    label.appendChild(document.createTextNode(labelText));
    if (required) label.appendChild(el('span', { 'class': 'req', text: ' *' }));
    wrap.appendChild(label);
    wrap.appendChild(control);
    return wrap;
  }

  function field(labelText, control, opts) {
    opts = opts || {};
    var wrap = el('div', { 'class': 'field' + (opts.className ? ' ' + opts.className : '') });
    bindLabel(wrap, labelText, control, opts.required);
    if (opts.help) wrap.appendChild(el('div', { 'class': 'field-help' + (opts.helpWarn ? ' warn' : ''), text: opts.help }));
    return wrap;
  }

  function textInput(opts) {
    opts = opts || {};
    var input = el('input', {
      type: opts.type || 'text',
      'class': 'input',
      name: opts.name,
      placeholder: opts.placeholder,
      autocomplete: opts.autocomplete || 'off',
      inputmode: opts.inputmode,
      min: opts.min,
      max: opts.max,
      step: opts.step,
      maxlength: opts.maxlength,
      readonly: opts.readonly || false,
      disabled: opts.disabled || false,
      'data-testid': opts.testid,
      spellcheck: opts.spellcheck === undefined ? 'false' : String(opts.spellcheck)
    });
    if (opts.value !== undefined && opts.value !== null) input.value = String(opts.value);
    return input;
  }

  function textareaInput(opts) {
    opts = opts || {};
    var area = el('textarea', {
      'class': 'textarea',
      name: opts.name,
      placeholder: opts.placeholder,
      rows: opts.rows || 4,
      'data-testid': opts.testid,
      spellcheck: 'false',
      autocomplete: 'off'
    });
    if (opts.value !== undefined && opts.value !== null) area.value = String(opts.value);
    return area;
  }

  function selectInput(opts) {
    opts = opts || {};
    var select = el('select', {
      'class': 'select',
      name: opts.name,
      'data-testid': opts.testid,
      disabled: opts.disabled || false
    });
    (opts.options || []).forEach(function (opt) {
      var o = el('option', { value: opt.value, text: opt.label });
      if (String(opt.value) === String(opts.value)) o.selected = true;
      select.appendChild(o);
    });
    return select;
  }

  function checkboxInput(labelText, opts) {
    opts = opts || {};
    var input = el('input', {
      type: 'checkbox',
      name: opts.name,
      'data-testid': opts.testid
    });
    input.checked = !!opts.checked;
    var label = el('label', { 'class': 'check-item' }, [input, el('span', { text: labelText })]);
    return { wrap: label, input: input };
  }

  function formError() {
    var msgEl = el('div', { 'class': 'error-msg' });
    var hintEl = el('div', { 'class': 'error-hint' });
    var box = el('div', { 'class': 'error-banner', hidden: true, 'data-testid': 'form-error' }, [
      el('div', { 'class': 'error-body' }, [msgEl, hintEl])
    ]);
    return {
      el: box,
      show: function (err) {
        var message = err && err.message ? err.message : String(err || '操作失败');
        var hint = err && err.hint ? err.hint : '';
        if (err && err.code) message += '（' + err.code + '）';
        msgEl.textContent = message;
        hintEl.textContent = hint;
        hintEl.hidden = !hint;
        box.hidden = false;
      },
      hide: function () { box.hidden = true; }
    };
  }

  /* ---------- Toast ---------- */

  function toast(message, opts) {
    opts = opts || {};
    var root = document.getElementById('toasts');
    if (!root) return function () {};
    var tone = opts.tone || 'info';
    var box = el('div', { 'class': 'toast toast-' + tone, role: 'status' });
    var body = el('div', { 'class': 'toast-body' }, [
      el('div', { 'class': 'toast-msg', text: message })
    ]);
    if (opts.hint) body.appendChild(el('div', { 'class': 'toast-hint', text: opts.hint }));
    var closeBtn = el('button', { type: 'button', 'class': 'toast-close', 'aria-label': '关闭', text: '×' });
    box.appendChild(body);
    box.appendChild(closeBtn);

    var timer = null;
    var removed = false;
    function remove() {
      if (removed) return;
      removed = true;
      if (timer) clearTimeout(timer);
      if (box.parentNode) box.parentNode.removeChild(box);
    }
    closeBtn.addEventListener('click', remove);
    root.appendChild(box);
    timer = setTimeout(remove, opts.duration || 4600);
    return remove;
  }

  function errorToast(err) {
    if (!err) return;
    toast(err.message || '操作失败', {
      tone: 'error',
      hint: err.hint || '',
      duration: 7000
    });
  }

  function successToast(message) { toast(message, { tone: 'success' }); }

  /* ---------- Modal ---------- */

  function openModal(opts) {
    opts = opts || {};
    var root = document.getElementById('modal-root');
    var overlay = el('div', { 'class': 'modal-overlay' });
    var dialog = el('div', {
      'class': 'modal' + (opts.narrow ? ' narrow' : ''),
      role: 'dialog',
      'aria-modal': 'true'
    });
    var titleId = 'bc-modal-title-' + (++fieldIdSeq);
    dialog.setAttribute('aria-labelledby', titleId);

    var titleEl = el('h2', { 'class': 'modal-title', id: titleId, text: opts.title || '' });
    var titleWrap = el('div', { 'class': 'modal-title-wrap' }, [titleEl]);
    if (opts.subtitle) titleWrap.appendChild(el('div', { 'class': 'modal-sub', text: opts.subtitle }));
    var closeBtn = el('button', { type: 'button', 'class': 'modal-close', 'aria-label': '关闭', text: '×' });
    var head = el('div', { 'class': 'modal-head' }, [titleWrap, closeBtn]);
    var bodyEl = el('div', { 'class': 'modal-body' });
    appendChildren(bodyEl, opts.body);

    dialog.appendChild(head);
    dialog.appendChild(bodyEl);

    var footerEl = null;
    if (opts.footer) {
      footerEl = el('div', { 'class': 'modal-foot' });
      appendChildren(footerEl, opts.footer);
      dialog.appendChild(footerEl);
    }
    overlay.appendChild(dialog);
    root.appendChild(overlay);

    var previousFocus = document.activeElement;
    var closed = false;
    var onClose = opts.onClose;

    function focusables() {
      return Array.prototype.slice.call(dialog.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])'
      )).filter(function (node) { return node.offsetParent !== null || node === document.activeElement; });
    }

    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
        return;
      }
      if (e.key === 'Tab') {
        var nodes = focusables();
        if (!nodes.length) return;
        var first = nodes[0];
        var last = nodes[nodes.length - 1];
        if (e.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
          e.preventDefault(); last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault(); first.focus();
        }
      }
    }
    document.addEventListener('keydown', onKeyDown, true);
    closeBtn.addEventListener('click', function () { close(); });

    function close(result) {
      if (closed) return;
      closed = true;
      document.removeEventListener('keydown', onKeyDown, true);
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      if (previousFocus && typeof previousFocus.focus === 'function' && document.contains(previousFocus)) {
        try { previousFocus.focus(); } catch (e) { /* ignore */ }
      }
      if (typeof onClose === 'function') onClose(result);
    }

    // 初始焦点：优先第一个输入控件，否则第一个按钮。
    setTimeout(function () {
      if (closed) return;
      var target = dialog.querySelector('input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled])');
      if (!target) target = dialog.querySelector('button.btn-primary, button.btn-danger, button');
      if (target) target.focus();
    }, 0);

    return {
      dialog: dialog,
      body: bodyEl,
      footer: footerEl,
      close: close,
      isClosed: function () { return closed; }
    };
  }

  /**
   * 表单弹窗：body 里放字段，footer 自动生成「取消 / 提交」。
   * onSubmit(formApi) 返回 Promise；抛错时自动把 error.message + hint 显示在表单顶部。
   */
  function openFormModal(opts) {
    var errBar = formError();
    var fieldNodes = opts.body || [];
    var form = el('form', { 'class': 'form', novalidate: true });
    form.appendChild(errBar.el);
    appendChildren(form, fieldNodes);

    var formId = 'bc-form-' + (++fieldIdSeq);
    form.id = formId;

    var cancelBtn = button({
      label: opts.cancelLabel || '取消',
      variant: 'ghost',
      onClick: function () { modal.close(); }
    });
    var submitBtn = button({
      label: opts.submitLabel || '保存',
      variant: opts.danger ? 'danger' : 'primary',
      type: 'submit',
      form: formId,
      testid: 'modal-submit'
    });
    var footer = [];
    if (opts.footLeft) footer.push(opts.footLeft);
    footer.push(cancelBtn, submitBtn);

    var modal = openModal({
      title: opts.title,
      subtitle: opts.subtitle,
      body: form,
      footer: footer,
      narrow: opts.narrow,
      onClose: opts.onClose
    });

    var busy = false;
    var api = {
      form: form,
      modal: modal,
      close: function (result) { modal.close(result); },
      setError: function (err) {
        if (err) errBar.show(err); else errBar.hide();
      },
      setBusy: function (flag) {
        busy = flag;
        submitBtn.disabled = flag;
        cancelBtn.disabled = flag;
        submitBtn.textContent = flag ? (opts.busyLabel || '处理中…') : (opts.submitLabel || '保存');
      },
      isBusy: function () { return busy; }
    };

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (busy) return;
      if (typeof opts.validate === 'function') {
        var validation = opts.validate();
        if (validation) { errBar.show(validation); return; }
      }
      errBar.hide();
      api.setBusy(true);
      Promise.resolve()
        .then(function () { return opts.onSubmit(api); })
        .catch(function (err) { api.setError(err); })
        .then(function () {
          if (!modal.isClosed()) api.setBusy(false);
        });
    });

    if (typeof opts.afterOpen === 'function') opts.afterOpen(api);
    return api;
  }

  /* ---------- 状态块 ---------- */

  function loadingBlock(message) {
    return el('div', { 'class': 'state-block', 'data-testid': 'state-loading' }, [
      el('div', { 'class': 'loading-inline' }, [el('span', { 'class': 'spinner' }), el('span', { text: message || '正在加载…' })])
    ]);
  }

  function emptyBlock(opts) {
    opts = opts || {};
    var block = el('div', { 'class': 'state-block', 'data-testid': 'state-empty' }, [
      el('div', { 'class': 'state-icon', text: opts.icon || '∅' }),
      el('div', { 'class': 'state-title', text: opts.title || '暂无数据' })
    ]);
    if (opts.hint) block.appendChild(el('div', { 'class': 'state-hint', text: opts.hint }));
    if (opts.action) block.appendChild(el('div', { 'class': 'mt-8' }, [opts.action]));
    return block;
  }

  function errorBanner(err, retry) {
    var message = err && err.message ? err.message : String(err || '请求失败');
    var hint = err && err.hint ? err.hint : '';
    var body = el('div', { 'class': 'error-body' }, [
      el('div', { 'class': 'error-msg', text: message })
    ]);
    if (err && err.code) body.firstChild.appendChild(el('span', { 'class': 'error-code', text: err.code }));
    if (hint) body.appendChild(el('div', { 'class': 'error-hint', text: hint }));
    var box = el('div', { 'class': 'error-banner' }, [body]);
    if (retry) {
      box.appendChild(button({ label: '重试', small: true, onClick: retry }));
    }
    return box;
  }

  function errorBlock(err, retry) {
    return el('div', { 'class': 'state-block', 'data-testid': 'state-error' }, [
      el('div', { 'class': 'state-icon', text: '!' }),
      el('div', { 'class': 'state-title', text: '加载失败' }),
      errorBanner(err),
      retry ? button({ label: '重试', onClick: retry }) : null
    ]);
  }

  /* ---------- 页面头 / 表格 ---------- */

  function pageHeader(opts) {
    var countEl = el('span', { 'class': 'count-pill', text: '0' });
    var titleRow = el('div', { 'class': 'page-title-row' }, [
      el('h1', { 'class': 'page-title', text: opts.title, 'data-testid': 'page-title' }),
      countEl
    ]);
    var left = el('div', {}, [titleRow]);
    if (opts.sub) left.appendChild(el('div', { 'class': 'page-sub', text: opts.sub }));
    var actions = el('div', { 'class': 'page-actions' });
    appendChildren(actions, opts.actions);
    var head = el('div', { 'class': 'page-head' }, [left, actions]);
    return {
      el: head,
      countEl: countEl,
      setCount: function (n) {
        countEl.textContent = String(n);
        countEl.hidden = n === null || n === undefined;
      }
    };
  }

  /**
   * columns: [{label, render(row)->Node|string, className, mobileLabel}]
   */
  function dataTable(columns, rows) {
    var thead = el('thead');
    var tr = el('tr');
    columns.forEach(function (col) {
      tr.appendChild(el('th', { 'class': col.className || '', text: col.label }));
    });
    thead.appendChild(tr);

    var tbody = el('tbody');
    if (!rows.length) {
      var td = el('td', { colspan: String(columns.length), 'class': 'cell-muted', text: '暂无数据' });
      var emptyRow = el('tr');
      emptyRow.appendChild(td);
      tbody.appendChild(emptyRow);
    } else {
      rows.forEach(function (row) {
        var rowEl = el('tr', row.attrs || null);
        columns.forEach(function (col) {
          var content = col.render ? col.render(row) : row[col.key];
          var td = el('td', {
            'class': col.className || '',
            'data-label': col.mobileLabel || col.label
          });
          appendChildren(td, content);
          rowEl.appendChild(td);
        });
        tbody.appendChild(rowEl);
      });
    }
    var table = el('table', { 'class': 'data-table' }, [thead, tbody]);
    return { el: el('div', { 'class': 'table-wrap' }, [table]), table: table, tbody: tbody };
  }

  /* ---------- 确认框 ---------- */

  /**
   * 二次确认。返回 Promise<{confirmed, checked}>。
   * opts: {title, message, detail, warn, confirmLabel, cancelLabel, danger, checkbox}
   */
  function confirmAction(opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      var settled = false;
      function finish(value) {
        if (settled) return;
        settled = true;
        resolve(value);
      }

      var body = [];
      if (opts.message) body.push(el('p', { 'class': 'text-2', text: opts.message }));
      if (opts.detail) {
        body.push(el('div', { 'class': 'confirm-detail' }, [el('span', { 'class': 'mono', text: opts.detail })]));
      }
      if (opts.warn) body.push(el('div', { 'class': 'warn-banner confirm-warn', text: opts.warn }));
      var checkbox = null;
      if (opts.checkbox) {
        checkbox = checkboxInput(opts.checkbox, { name: 'confirm-option', testid: 'confirm-checkbox' });
        checkbox.input.checked = !!opts.checkboxChecked;
        body.push(el('div', { 'class': 'mt-16' }, [checkbox.wrap]));
      }

      var cancelBtn = button({ label: opts.cancelLabel || '取消', variant: 'ghost' });
      var okBtn = button({
        label: opts.confirmLabel || '确认',
        variant: opts.danger === false ? 'primary' : 'danger',
        testid: 'confirm-ok'
      });
      var modal = openModal({
        title: opts.title || '请确认',
        body: body,
        footer: [cancelBtn, okBtn],
        narrow: true,
        onClose: function () { finish({ confirmed: false, checked: false }); }
      });
      cancelBtn.addEventListener('click', function () {
        finish({ confirmed: false, checked: false });
        modal.close();
      });
      okBtn.addEventListener('click', function () {
        finish({ confirmed: true, checked: checkbox ? checkbox.input.checked : false });
        modal.close();
      });
    });
  }

  BC.ui = {
    el: el,
    clear: clear,
    setText: setText,
    appendChildren: appendChildren,
    button: button,
    btnLink: btnLink,
    field: field,
    textInput: textInput,
    textareaInput: textareaInput,
    selectInput: selectInput,
    checkboxInput: checkboxInput,
    formError: formError,
    badge: badge,
    chip: chip,
    flag: flag,
    fmtDateTime: fmtDateTime,
    fmtTime: fmtTime,
    countdown: countdown,
    truncate: truncate,
    toast: toast,
    errorToast: errorToast,
    successToast: successToast,
    openModal: openModal,
    openFormModal: openFormModal,
    loadingBlock: loadingBlock,
    emptyBlock: emptyBlock,
    errorBanner: errorBanner,
    errorBlock: errorBlock,
    pageHeader: pageHeader,
    dataTable: dataTable,
    confirmAction: confirmAction
  };
})();
