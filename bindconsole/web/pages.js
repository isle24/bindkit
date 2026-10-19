/*
 * bindconsole — 页面
 * 所有用户/服务端数据均通过 UI.el / textContent 渲染，绝不使用 innerHTML。
 */
(function () {
  'use strict';

  var BC = window.BC;
  var UI = BC.ui;
  var net = BC.net;

  function app() { return BC.app; }
  function state() { return BC.app.state; }

  var SOURCE_LABELS = {
    generated: '自动生成密钥',
    imported: '导入',
    adopted: '纳管已有密钥'
  };

  var ENGINE_LABELS = {
    mysql: 'MySQL',
    postgres: 'PostgreSQL',
    sqlite: 'SQLite'
  };

  var DECISION_TONES = {
    allow: 'green',
    deny: 'red',
    ask: 'amber',
    approve: 'blue',
    reject: 'red',
    consume: 'purple',
    error: 'red'
  };

  var ACTION_LABELS = {
    sudo: 'sudo',
    write: '写入',
    ddl: 'DDL'
  };

  var COUNTDOWN_ATTR = 'data-countdown-expires';

  /* ---------- 通用小工具 ---------- */

  function listOf(data, key) {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (Array.isArray(data.items)) return data.items;
    if (key && Array.isArray(data[key])) return data[key];
    return [];
  }

  function pick() {
    for (var i = 0; i < arguments.length; i++) {
      if (arguments[i] !== undefined && arguments[i] !== null) return arguments[i];
    }
    return undefined;
  }

  // 与 pick 不同：null 是有效值（例如 allowed_databases: null = 不限），只跳过 undefined。
  function firstDefined() {
    for (var i = 0; i < arguments.length; i++) {
      if (arguments[i] !== undefined) return arguments[i];
    }
    return undefined;
  }

  function enc(value) { return encodeURIComponent(String(value)); }

  function resourcePath(name, suffix) {
    var base = '/api/' + state().resource + '/' + enc(name);
    return suffix ? base + '/' + suffix : base;
  }

  function parseList(text) {
    if (text === undefined || text === null) return null;
    var s = String(text).trim();
    if (!s) return null;
    var parts = s.split(/[,，\s]+/).filter(function (part) { return part.length > 0; });
    return parts.length ? parts : null;
  }

  function formatWhitelist(value) {
    if (value === null || value === undefined) return null;
    if (Array.isArray(value)) return value.length ? value.map(String) : null;
    return parseList(String(value));
  }

  function whitelistCell(dbValue, tableValue, schemaValue) {
    var dbs = formatWhitelist(dbValue);
    var tables = formatWhitelist(tableValue);
    var schemas = formatWhitelist(schemaValue);
    if (!dbs && !tables && !schemas) return UI.chip('不限', '库 / 表 / schema 均不限制');
    var box = UI.el('span', { 'class': 'badge-stack' });
    if (dbs) {
      var dbText = '库: ' + dbs.join(', ');
      var dbChip = UI.chip(dbs.length > 2 ? '库: ' + dbs.slice(0, 2).join(', ') + ' +' + (dbs.length - 2) : dbText, dbText);
      box.appendChild(dbChip);
    }
    if (tables) {
      var tableText = '表: ' + tables.join(', ');
      var tableChip = UI.chip(tables.length > 2 ? '表: ' + tables.slice(0, 2).join(', ') + ' +' + (tables.length - 2) : tableText, tableText);
      box.appendChild(tableChip);
    }
    if (schemas) {
      var schemaText = 'schema: ' + schemas.join(', ');
      var schemaChip = UI.chip(schemas.length > 2 ? 'schema: ' + schemas.slice(0, 2).join(', ') + ' +' + (schemas.length - 2) : schemaText, schemaText);
      box.appendChild(schemaChip);
    }
    return box;
  }

  function approvalSwitchCell(writeOn, ddlOn) {
    var box = UI.el('span', { 'class': 'badge-stack' });
    box.appendChild(UI.badge('write', writeOn ? 'amber' : 'gray', {
      plain: true,
      title: writeOn ? '写数据需要审批' : '写数据不需要审批'
    }));
    box.appendChild(UI.badge('ddl', ddlOn ? 'red' : 'gray', {
      plain: true,
      title: ddlOn ? 'DDL 需要审批' : 'DDL 不需要审批'
    }));
    return box;
  }

  function levelBadge(level) {
    var tone = level === 'ddl' ? 'red' : (level === 'write' ? 'amber' : 'blue');
    return UI.badge(level || 'read', tone);
  }

  function sudoBadge(sudo) {
    var tone = sudo === 'allow' ? 'green' : (sudo === 'deny' ? 'red' : 'amber');
    var label = sudo === 'allow' ? 'allow' : (sudo === 'deny' ? 'deny' : 'ask');
    return UI.badge(label, tone);
  }

  function emptyPage(title, hint, action) {
    return UI.emptyBlock({ icon: '∅', title: title, hint: hint, action: action });
  }

  function loadPage(body, loader, renderer, ctx) {
    UI.clear(body);
    body.appendChild(UI.loadingBlock('正在加载…'));
    return loader().then(function (data) {
      if (!app().isCurrent(ctx.epoch)) return;
      UI.clear(body);
      renderer(data);
    }, function (err) {
      if (!app().isCurrent(ctx.epoch)) return;
      UI.clear(body);
      body.appendChild(UI.errorBlock(err, function () { loadPage(body, loader, renderer, ctx); }));
    });
  }

  /* ================================================================
   * 认证页
   * ================================================================ */

  function setupPage(view, ctx) {
    var info = app().toolInfo();
    view.appendChild(UI.el('h1', { 'class': 'auth-title', text: '设置管理密码' }));
    view.appendChild(UI.el('p', {
      'class': 'auth-sub',
      text: '首次使用，请为 ' + info.product + ' 控制台设置管理密码。sshbind 与 dbbind 共用同一份密码。'
    }));

    var error = UI.formError();
    var pw = UI.textInput({
      type: 'password', name: 'password', autocomplete: 'new-password',
      placeholder: '至少 8 位', testid: 'setup-password'
    });
    var pw2 = UI.textInput({
      type: 'password', name: 'password_confirm', autocomplete: 'new-password',
      placeholder: '再输入一次', testid: 'setup-confirm'
    });
    // 局域网模式（--host 0.0.0.0）下首次设置密码必须带终端打印的一次性口令。
    var token = UI.textInput({
      type: 'password', name: 'setup_token', autocomplete: 'off',
      placeholder: '终端打印的一次性口令', testid: 'setup-token'
    });
    var tokenField = UI.field('一次性口令', token, {
      required: true,
      help: '局域网模式下首次设置需要启动控制台的终端里打印的一次性口令（区分大小写，只显示这一次）。'
    });
    tokenField.hidden = !app().state.setupRequiresToken;

    var submit = UI.button({ label: '设置密码', variant: 'primary', type: 'submit', testid: 'setup-submit' });

    var form = UI.el('form', { 'class': 'form' }, [
      error.el,
      UI.field('管理密码', pw, { required: true, help: '至少 8 个字符。密码只保存 PBKDF2 哈希，遗忘后需删除 ~/.bindconsole/secret.json 重新设置。' }),
      UI.field('确认密码', pw2, { required: true }),
      tokenField,
      submit
    ]);
    view.appendChild(form);

    var busy = false;
    function setBusy(flag) {
      busy = flag;
      submit.disabled = flag;
      submit.textContent = flag ? '设置中…' : '设置密码';
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (busy) return;
      error.hide();
      if (!pw.value) { error.show({ message: '请填写管理密码' }); return; }
      if (pw.value.length < 8) { error.show({ message: '管理密码至少 8 个字符' }); return; }
      if (pw.value !== pw2.value) { error.show({ message: '两次输入的密码不一致' }); return; }
      if (!tokenField.hidden && !token.value.trim()) {
        error.show({ message: '请输入终端显示的一次性口令', hint: '口令打印在启动控制台的终端输出里（局域网模式）。' });
        token.focus();
        return;
      }
      setBusy(true);
      var body = { password: pw.value };
      if (!tokenField.hidden || token.value.trim()) body.setup_token = token.value.trim();
      net.post('/api/setup', body).then(function () {
        pw.value = '';
        pw2.value = '';
        token.value = '';
        return app().refreshStatus();
      }).then(function (status) {
        if (status.setupRequired) {
          error.show({ message: '设置未生效，请重试' });
          return;
        }
        UI.successToast('管理密码已设置，请登录');
        app().navigate('#/login', { replace: true });
        app().render();
      }).catch(function (err) {
        if (err && err.status === 403) {
          // 服务端要求 setup token（或 token 不对）：把输入框显出来并给出明确指引。
          tokenField.hidden = false;
          app().state.setupRequiresToken = true;
          error.show({
            message: '口令不正确，请查看启动控制台的终端',
            hint: err.hint || '一次性口令只打印在启动控制台的终端里，请复制粘贴后重试。'
          });
          token.focus();
        } else {
          error.show(err);
        }
        setBusy(false);
      });
    });

    setTimeout(function () { pw.focus(); }, 0);
    void ctx;
  }

  function loginPage(view, ctx) {
    var info = app().toolInfo();
    view.appendChild(UI.el('h1', { 'class': 'auth-title', text: '登录' }));
    view.appendChild(UI.el('p', {
      'class': 'auth-sub',
      text: '输入管理密码以进入 ' + info.product + ' 控制台。仅限本机 127.0.0.1 访问。'
    }));

    var error = UI.formError();
    var pw = UI.textInput({
      type: 'password', name: 'password', autocomplete: 'current-password',
      placeholder: '管理密码', testid: 'login-password'
    });
    var submit = UI.button({ label: '登录', variant: 'primary', type: 'submit', testid: 'login-submit' });

    var form = UI.el('form', { 'class': 'form' }, [
      error.el,
      UI.field('管理密码', pw, { required: true }),
      submit
    ]);
    view.appendChild(form);

    var busy = false;
    var lockedTimer = null;

    function stopLockTimer() {
      if (lockedTimer) { clearInterval(lockedTimer); lockedTimer = null; }
    }

    function startLockCountdown(seconds) {
      stopLockTimer();
      var remaining = Math.max(1, Number(seconds) || 60);
      busy = true;
      submit.disabled = true;
      var tick = function () {
        if (remaining <= 0) {
          stopLockTimer();
          busy = false;
          submit.disabled = false;
          submit.textContent = '登录';
          return;
        }
        submit.textContent = '请等待 ' + remaining + ' 秒';
        remaining -= 1;
      };
      tick();
      lockedTimer = setInterval(tick, 1000);
      app().registerCleanup(stopLockTimer);
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (busy) return;
      error.hide();
      if (!pw.value) { error.show({ message: '请输入管理密码' }); return; }
      busy = true;
      submit.disabled = true;
      submit.textContent = '登录中…';
      net.post('/api/login', { password: pw.value }).then(function () {
        pw.value = '';
        return app().refreshStatus();
      }).then(function (status) {
        if (status.setupRequired) { app().navigate('#/setup', { replace: true }); return; }
        if (!status.authenticated) {
          error.show({ message: '登录状态未生效，请重试' });
          return;
        }
        app().navigate(app().defaultRoute(), { replace: true });
        app().render();
      }).catch(function (err) {
        error.show(err);
        if (err && err.status === 429 && err.retryAfter) {
          startLockCountdown(err.retryAfter);
        }
      }).then(function () {
        if (!lockedTimer) {
          busy = false;
          submit.disabled = false;
          submit.textContent = '登录';
        }
      });
    });

    setTimeout(function () { pw.focus(); }, 0);
    void ctx;
  }

  /* ================================================================
   * sshbind — 服务器
   * ================================================================ */

  function normalizeServer(raw) {
    var name = raw.name || raw.alias || '';
    var entry = app().policyEntry(name);
    var defaults = app().policyDefaults();
    var sudo = pick(raw.sudo, entry.sudo, defaults.sudo, 'ask');
    var ttl = pick(raw.approval_ttl_s, entry.approval_ttl_s, defaults.approval_ttl_s);
    return {
      name: name,
      user: raw.user || '',
      host: raw.host || '',
      port: pick(raw.port, 22),
      source: raw.source || '',
      installed: (raw.installed === true) ? true : (raw.installed === false ? false : null),
      usable: (raw.usable === true) ? true : (raw.usable === false ? false : null),
      usableReason: raw.usable_reason || raw.reason || '',
      hasKey: raw.has_key === true || !!raw.key_path,
      hasPassword: raw.has_password === true,
      fingerprint: raw.fingerprint || '',
      keyPath: raw.key_path || '',
      sudo: (sudo === 'allow' || sudo === 'ask' || sudo === 'deny') ? sudo : 'ask',
      approvalTtl: (ttl === undefined || ttl === null || ttl === '') ? null : Number(ttl),
      note: raw.note || '',
      lastTest: raw.last_test || null,
      raw: raw
    };
  }

  function sourceCell(source) {
    if (!source) return UI.el('span', { 'class': 'cell-muted', text: '—' });
    var chip = UI.chip(source, SOURCE_LABELS[source] || source);
    return chip;
  }

  function serversPage(view, ctx) {
    var pageRoot = UI.el('div');
    view.appendChild(pageRoot);

    var head = UI.pageHeader({
      title: '服务器',
      sub: '管理 sshbind 别名：导入密码或私钥、配置 sudo 提权审批策略、测试连通性。',
      actions: [
        UI.button({ label: '刷新', variant: 'ghost', small: true, testid: 'btn-refresh', onClick: function () { load(false); } }),
        UI.button({ label: '添加服务器', variant: 'primary', testid: 'btn-add', onClick: function () { openAddServer(); } })
      ]
    });
    pageRoot.appendChild(head.el);
    var body = UI.el('div');
    pageRoot.appendChild(body);

    var current = [];
    var loading = false;

    function load(initial) {
      if (loading) return Promise.resolve();
      loading = true;
      if (initial) {
        UI.clear(body);
        body.appendChild(UI.loadingBlock('正在加载服务器…'));
      }
      return app().ensurePolicy().then(function () {
        return net.get('/api/servers');
      }).then(function (data) {
        if (!app().isCurrent(ctx.epoch)) return;
        current = listOf(data, 'servers').map(normalizeServer);
        renderList();
      }).catch(function (err) {
        if (!app().isCurrent(ctx.epoch)) return;
        if (initial) {
          UI.clear(body);
          body.appendChild(UI.errorBlock(err, function () { load(true); }));
        }
      }).then(function () {
        loading = false;
      });
    }

    function rowFor(server) {
      var lastTestCell = UI.el('span', { 'class': 'cell-muted', text: '—', 'data-testid': 'last-test-' + server.name });
      return { server: server, lastTestCell: lastTestCell };
    }

    function renderList() {
      UI.clear(body);
      head.setCount(current.length);
      if (!current.length) {
        body.appendChild(emptyPage(
          '还没有服务器',
          '用「添加服务器」导入一台机器：可以粘贴登录密码，也可以直接粘贴私钥内容。',
          UI.button({ label: '添加第一台服务器', variant: 'primary', onClick: function () { openAddServer(); } })
        ));
        return;
      }
      var rows = current.map(rowFor);
      var table = UI.dataTable([
        {
          label: '名称',
          render: function (row) { return UI.el('div', { 'class': 'cell-name', text: row.server.name }); }
        },
        {
          label: '连接',
          render: function (row) {
            var s = row.server;
            return UI.el('span', {
              'class': 'cell-mono',
              text: s.user + '@' + s.host + ':' + s.port,
              title: s.user + '@' + s.host + ':' + s.port
            });
          }
        },
        {
          label: '来源',
          render: function (row) { return sourceCell(row.server.source); }
        },
        {
          label: '已安装',
          render: function (row) { return UI.flag(row.server.installed, '✓', '✗'); }
        },
        {
          label: '可用',
          mobileLabel: '可用',
          render: function (row) {
            var s = row.server;
            var box = UI.el('div');
            box.appendChild(UI.flag(s.usable));
            if (s.usable === false && s.usableReason) {
              box.appendChild(UI.el('div', { 'class': 'usable-reason', text: s.usableReason }));
            }
            return box;
          }
        },
        {
          label: 'sudo 策略',
          render: function (row) { return sudoBadge(row.server.sudo); }
        },
        {
          label: '最近测试',
          render: function (row) { return row.lastTestCell; }
        },
        {
          label: '操作',
          className: 'cell-actions',
          render: function (row) {
            var s = row.server;
            var testBtn = UI.btnLink('测试', { testid: 'test-' + s.name });
            testBtn.addEventListener('click', function () { runTest(s, row, testBtn); });
            var editBtn = UI.btnLink('编辑', { testid: 'edit-' + s.name });
            editBtn.addEventListener('click', function () { openEditServer(s); });
            var delBtn = UI.btnLink('删除', { danger: true, testid: 'delete-' + s.name });
            delBtn.addEventListener('click', function () { deleteServer(s); });
            return UI.el('span', {}, [testBtn, editBtn, delBtn]);
          }
        }
      ], rows);
      body.appendChild(table.el);
    }

    function runTest(server, row, btn) {
      if (btn.disabled) return;
      btn.disabled = true;
      btn.textContent = '测试中…';
      row.lastTestCell.textContent = '…';
      row.lastTestCell.className = 'cell-muted';

      net.post(resourcePath(server.name, 'test'), {}).then(function (data) {
        var ok = !(data && data.ok === false);
        var message = (data && (data.message || data.usable_reason)) || (ok ? '连接正常' : '连接失败');
        row.lastTestCell.textContent = ok ? '✓ 正常' : '✗ 失败';
        row.lastTestCell.className = ok ? 'flag flag-yes' : 'flag flag-no';
        UI.toast((ok ? '测试通过：' : '测试失败：') + server.name, {
          tone: ok ? 'success' : 'error',
          hint: message
        });
      }).catch(function (err) {
        row.lastTestCell.textContent = '✗ 失败';
        row.lastTestCell.className = 'flag flag-no';
        UI.errorToast(err);
      }).then(function () {
        btn.disabled = false;
        btn.textContent = '测试';
        setTimeout(function () {
          if (row.lastTestCell.isConnected) {
            row.lastTestCell.textContent = '—';
            row.lastTestCell.className = 'cell-muted';
          }
        }, 4000);
      });
    }

    function openAddServer() {
      var name = UI.textInput({ placeholder: '例如 demo-server', testid: 'f-name' });
      var host = UI.textInput({ placeholder: 'IP 或域名', testid: 'f-host' });
      var port = UI.textInput({ type: 'number', value: '22', min: '1', max: '65535', testid: 'f-port' });
      var user = UI.textInput({ placeholder: '登录用户', testid: 'f-user' });

      var authPassword = UI.el('input', { type: 'radio', name: 'auth-method', value: 'password', checked: true, 'data-testid': 'auth-password' });
      var authKey = UI.el('input', { type: 'radio', name: 'auth-method', value: 'key', 'data-testid': 'auth-key' });
      var radios = UI.el('div', { 'class': 'radio-row' }, [
        UI.el('label', { 'class': 'radio-card' }, [authPassword, UI.el('span', { text: '密码导入' })]),
        UI.el('label', { 'class': 'radio-card' }, [authKey, UI.el('span', { text: '粘贴私钥内容' })])
      ]);

      var password = UI.textInput({
        type: 'password', autocomplete: 'new-password',
        placeholder: '服务器登录密码（仅本次导入，不会回显）', testid: 'f-password'
      });
      var privateKey = UI.textareaInput({
        placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----',
        rows: 5, testid: 'f-private-key'
      });

      var passwordField = UI.field('密码', password, {
        help: '经 stdin 导入，不会出现在命令行或日志里。', required: true
      });
      var keyField = UI.field('私钥内容', privateKey, {
        help: '写入临时 0600 文件后导入，成功后立即删除。', required: true
      });
      keyField.hidden = true;

      var sudo = UI.selectInput({
        name: 'sudo', testid: 'f-sudo', value: 'ask',
        options: [
          { value: 'allow', label: 'allow — 直接放行' },
          { value: 'ask', label: 'ask — 需要审批（默认）' },
          { value: 'deny', label: 'deny — 一律拒绝' }
        ]
      });
      var note = UI.textareaInput({ rows: 2, placeholder: '可选，例如用途说明', testid: 'f-note' });

      function syncAuth() {
        var keyMode = authKey.checked;
        passwordField.hidden = keyMode;
        keyField.hidden = !keyMode;
      }
      authPassword.addEventListener('change', syncAuth);
      authKey.addEventListener('change', syncAuth);

      UI.openFormModal({
        title: '添加服务器',
        subtitle: '凭证只写不读：提交后立即清空输入框，接口与页面都不会回显。',
        submitLabel: '添加',
        body: [
          UI.field('名称', name, { required: true, help: '仅允许字母、数字、点、下划线、连字符（[A-Za-z0-9_.-]），例如 demo-server' }),
          UI.el('div', { 'class': 'form-grid' }, [
            UI.field('主机', host, { required: true }),
            UI.field('端口', port)
          ]),
          UI.field('用户', user, { required: true }),
          UI.field('认证方式', radios),
          passwordField,
          keyField,
          UI.field('sudo 策略', sudo, { help: '命中 sudo/su 等提权命令时按此策略判定。' }),
          UI.field('备注', note)
        ],
        validate: function () {
          var n = name.value.trim();
          if (!n) return { message: '请填写名称' };
          if (!/^[A-Za-z0-9_.-]+$/.test(n) || n.indexOf('..') >= 0) {
            return { message: '名称只能包含字母、数字、点、下划线、连字符，且不能含 ".."' };
          }
          if (!host.value.trim()) return { message: '请填写主机地址' };
          if (!user.value.trim()) return { message: '请填写登录用户' };
          var p = parseInt(port.value, 10);
          if (!(p >= 1 && p <= 65535)) return { message: '端口需在 1–65535 之间' };
          if (!authKey.checked && !password.value) return { message: '请填写密码，或切换到「粘贴私钥内容」' };
          if (authKey.checked && !privateKey.value.trim()) return { message: '请粘贴私钥内容，或切换到「密码导入」' };
          return null;
        },
        onSubmit: function (api) {
          var bodyData = {
            name: name.value.trim(),
            host: host.value.trim(),
            port: parseInt(port.value, 10),
            user: user.value.trim(),
            sudo: sudo.value,
            note: note.value.trim()
          };
          if (authKey.checked) bodyData.private_key = privateKey.value.trim();
          else bodyData.password = password.value;

          function clearSecrets() {
            password.value = '';
            privateKey.value = '';
          }

          return net.post('/api/servers', bodyData).then(function () {
            clearSecrets();
            api.close();
            UI.successToast('已添加服务器 ' + bodyData.name);
            return load(false);
          }, function (err) {
            clearSecrets();
            throw err;
          });
        }
      });
    }

    function openEditServer(server) {
      var subtitleParts = [server.user + '@' + server.host + ':' + server.port];
      if (server.source) subtitleParts.push('来源 ' + server.source);
      if (server.hasKey) subtitleParts.push('密钥认证');
      else if (server.hasPassword) subtitleParts.push('密码认证');

      var sudo = UI.selectInput({
        name: 'sudo', testid: 'f-sudo', value: server.sudo,
        options: [
          { value: 'allow', label: 'allow — 直接放行' },
          { value: 'ask', label: 'ask — 需要审批（默认）' },
          { value: 'deny', label: 'deny — 一律拒绝' }
        ]
      });
      var ttl = UI.textInput({
        type: 'number', min: '60', max: '86400',
        value: server.approvalTtl === null ? '' : String(server.approvalTtl),
        placeholder: '留空 = 使用默认（600 秒）', testid: 'f-approval-ttl'
      });
      var note = UI.textareaInput({ rows: 3, value: server.note, testid: 'f-note' });

      UI.openFormModal({
        title: '编辑服务器 · ' + server.name,
        subtitle: subtitleParts.join(' · '),
        submitLabel: '保存',
        body: [
          UI.field('sudo 策略', sudo),
          UI.field('审批有效期（秒）', ttl, { help: '留空 = 使用策略默认值；范围 60–86400。' }),
          UI.field('备注', note)
        ],
        validate: function () {
          if (ttl.value.trim() !== '') {
            var v = parseInt(ttl.value, 10);
            if (!(v >= 60 && v <= 86400)) return { message: '审批有效期需在 60–86400 秒之间（或留空）' };
          }
          return null;
        },
        onSubmit: function (api) {
          var bodyData = { sudo: sudo.value, note: note.value.trim() };
          if (ttl.value.trim() !== '') bodyData.approval_ttl_s = parseInt(ttl.value, 10);
          return net.put(resourcePath(server.name), bodyData).then(function () {
            api.close();
            UI.successToast('已保存 ' + server.name);
            return load(false);
          });
        }
      });
    }

    function deleteServer(server) {
      UI.confirmAction({
        title: '删除服务器',
        message: '确定删除服务器「' + server.name + '」吗？删除后 sshbind 别名将不可用，此操作不可撤销。',
        detail: server.user + '@' + server.host + ':' + server.port,
        warn: '如果该服务器仍被 AI 或脚本使用，后续调用会失败。',
        confirmLabel: '删除',
        checkbox: '同时删除本地私钥文件',
        checkboxChecked: false
      }).then(function (result) {
        if (!result.confirmed) return;
        // delete_key 仅在勾选时发送（body + query 双保险，内核会合并 query）。
        var bodyData = result.checked ? { delete_key: true } : {};
        var query = result.checked ? { delete_key: 'true' } : undefined;
        return net.del(resourcePath(server.name), bodyData, query)
          .then(function () {
            UI.successToast('已删除 ' + server.name);
            return load(false);
          }, function (err) {
            UI.errorToast(err);
          });
      });
    }

    app().registerSilentRefresher(function () { return load(false); });
    load(true);
  }

  /* ================================================================
   * dbbind — 数据库
   * ================================================================ */

  function normalizeDatabase(raw) {
    var alias = raw.alias || raw.name || '';
    var entry = app().policyEntry(alias);
    var defaults = app().policyDefaults();
    var rawApproval = (raw.approval && typeof raw.approval === 'object') ? raw.approval : {};
    var entryApproval = (entry.approval && typeof entry.approval === 'object') ? entry.approval : {};
    var defaultApproval = (defaults.approval && typeof defaults.approval === 'object') ? defaults.approval : {};
    return {
      alias: alias,
      engine: raw.engine || '',
      host: raw.host || '',
      port: pick(raw.port, ''),
      user: raw.user || '',
      database: raw.database || raw.default_db || '',
      file: raw.file || '',
      hasPassword: raw.has_password === true,
      usable: (raw.usable === true) ? true : (raw.usable === false ? false : null),
      usableReason: raw.usable_reason || raw.reason || '',
      origin: raw.origin || '',
      available: raw.available,
      maxLevel: pick(raw.max_level, entry.max_level, defaults.max_level, 'read'),
      allowedDatabases: firstDefined(raw.allowed_databases, entry.allowed_databases, defaults.allowed_databases, null),
      allowedTables: firstDefined(raw.allowed_tables, entry.allowed_tables, defaults.allowed_tables, null),
      allowedSchemas: firstDefined(raw.allowed_schemas, entry.allowed_schemas, defaults.allowed_schemas, null),
      allowMetadata: pick(raw.allow_metadata, entry.allow_metadata, defaults.allow_metadata, true),
      approvalWrite: pick(rawApproval.write, entryApproval.write, defaultApproval.write, false),
      approvalDdl: pick(rawApproval.ddl, entryApproval.ddl, defaultApproval.ddl, true),
      approvalTtl: pick(raw.approval_ttl_s, entry.approval_ttl_s, defaults.approval_ttl_s, 600),
      note: raw.note || '',
      raw: raw
    };
  }

  function dbConnectionCell(db) {
    if (db.engine === 'sqlite') {
      return UI.el('span', {
        'class': 'cell-mono',
        text: db.file || '—',
        title: db.file || ''
      });
    }
    var text = db.host ? db.host + ':' + db.port : '—';
    var node = UI.el('span', { 'class': 'cell-mono cell-nowrap', text: text, title: db.user ? db.user + '@' + text : text });
    return node;
  }

  function databasesPage(view, ctx) {
    var pageRoot = UI.el('div');
    view.appendChild(pageRoot);

    var head = UI.pageHeader({
      title: '数据库',
      sub: '管理 dbbind 别名：连接参数、授权等级、库表白名单、审批开关。',
      actions: [
        UI.button({ label: '刷新', variant: 'ghost', small: true, testid: 'btn-refresh', onClick: function () { load(false); } }),
        UI.button({ label: '添加数据库', variant: 'primary', testid: 'btn-add', onClick: function () { openAddDatabase(); } })
      ]
    });
    pageRoot.appendChild(head.el);
    var body = UI.el('div');
    pageRoot.appendChild(body);

    var current = [];
    var loading = false;

    function load(initial) {
      if (loading) return Promise.resolve();
      loading = true;
      if (initial) {
        UI.clear(body);
        body.appendChild(UI.loadingBlock('正在加载数据库…'));
      }
      return app().ensurePolicy().then(function () {
        return net.get('/api/databases');
      }).then(function (data) {
        if (!app().isCurrent(ctx.epoch)) return;
        current = listOf(data, 'databases').map(normalizeDatabase);
        renderList();
      }).catch(function (err) {
        if (!app().isCurrent(ctx.epoch)) return;
        if (initial) {
          UI.clear(body);
          body.appendChild(UI.errorBlock(err, function () { load(true); }));
        }
      }).then(function () {
        loading = false;
      });
    }

    function rowFor(db) {
      return { db: db, lastTestCell: UI.el('span', { 'class': 'cell-muted', text: '—', 'data-testid': 'last-test-' + db.alias }) };
    }

    function renderList() {
      UI.clear(body);
      head.setCount(current.length);
      if (!current.length) {
        body.appendChild(emptyPage(
          '还没有数据库',
          '用「添加数据库」导入连接：MySQL / PostgreSQL 填连接参数，SQLite 填文件路径。',
          UI.button({ label: '添加第一个数据库', variant: 'primary', onClick: function () { openAddDatabase(); } })
        ));
        return;
      }
      var rows = current.map(rowFor);
      var table = UI.dataTable([
        {
          label: '别名',
          render: function (row) {
            var box = UI.el('div');
            box.appendChild(UI.el('div', { 'class': 'cell-name', text: row.db.alias }));
            if (row.db.origin) box.appendChild(UI.el('div', { 'class': 'usable-reason', text: '来源 ' + row.db.origin }));
            return box;
          }
        },
        {
          label: '引擎',
          render: function (row) {
            return UI.badge(row.db.engine || '—', 'gray', { plain: true });
          }
        },
        {
          label: '连接',
          render: function (row) { return dbConnectionCell(row.db); }
        },
        {
          label: '数据库',
          render: function (row) {
            if (row.db.engine === 'sqlite') return UI.el('span', { 'class': 'cell-muted', text: '文件' });
            return UI.el('span', { 'class': 'cell-db-name', text: row.db.database || '—' });
          }
        },
        {
          label: '可用',
          render: function (row) {
            var db = row.db;
            var box = UI.el('div');
            box.appendChild(UI.flag(db.usable));
            if (db.usable === false && db.usableReason) {
              box.appendChild(UI.el('div', { 'class': 'usable-reason', text: db.usableReason }));
            }
            return box;
          }
        },
        {
          label: 'max_level',
          render: function (row) { return levelBadge(row.db.maxLevel); }
        },
        {
          label: '白名单',
          render: function (row) { return whitelistCell(row.db.allowedDatabases, row.db.allowedTables, row.db.allowedSchemas); }
        },
        {
          label: '审批开关',
          mobileLabel: '审批',
          render: function (row) { return approvalSwitchCell(row.db.approvalWrite, row.db.approvalDdl); }
        },
        {
          label: '最近测试',
          render: function (row) { return row.lastTestCell; }
        },
        {
          label: '操作',
          className: 'cell-actions',
          render: function (row) {
            var db = row.db;
            var testBtn = UI.btnLink('测试', { testid: 'test-' + db.alias });
            testBtn.addEventListener('click', function () { runTest(db, row, testBtn); });
            var editBtn = UI.btnLink('编辑', { testid: 'edit-' + db.alias });
            editBtn.addEventListener('click', function () { openEditDatabase(db); });
            var delBtn = UI.btnLink('删除', { danger: true, testid: 'delete-' + db.alias });
            delBtn.addEventListener('click', function () { deleteDatabase(db); });
            return UI.el('span', {}, [testBtn, editBtn, delBtn]);
          }
        }
      ], rows);
      body.appendChild(table.el);
    }

    function runTest(db, row, btn) {
      if (btn.disabled) return;
      btn.disabled = true;
      btn.textContent = '测试中…';
      row.lastTestCell.textContent = '…';
      row.lastTestCell.className = 'cell-muted';
      net.post(resourcePath(db.alias, 'test'), {}).then(function (data) {
        var ok = !(data && data.ok === false);
        var message = (data && (data.message || data.usable_reason)) || (ok ? '连接正常' : '连接失败');
        row.lastTestCell.textContent = ok ? '✓ 正常' : '✗ 失败';
        row.lastTestCell.className = ok ? 'flag flag-yes' : 'flag flag-no';
        UI.toast((ok ? '测试通过：' : '测试失败：') + db.alias, {
          tone: ok ? 'success' : 'error',
          hint: message
        });
      }).catch(function (err) {
        row.lastTestCell.textContent = '✗ 失败';
        row.lastTestCell.className = 'flag flag-no';
        UI.errorToast(err);
      }).then(function () {
        btn.disabled = false;
        btn.textContent = '测试';
        setTimeout(function () {
          if (row.lastTestCell.isConnected) {
            row.lastTestCell.textContent = '—';
            row.lastTestCell.className = 'cell-muted';
          }
        }, 4000);
      });
    }

    function engineDefaults(engine) {
      return engine === 'postgres' ? '5432' : (engine === 'mysql' ? '3306' : '');
    }

    function buildPolicyFields(init) {
      init = init || {};
      var initialEngine = init.engine || 'mysql';
      var maxLevel = UI.selectInput({
        name: 'max_level', testid: 'f-max-level', value: init.maxLevel || 'read',
        options: [
          { value: 'read', label: 'read — 只读' },
          { value: 'write', label: 'write — 可改数据' },
          { value: 'ddl', label: 'ddl — 可改结构' }
        ]
      });
      var allowedDatabases = UI.textInput({
        placeholder: '逗号分隔；留空 = 不限制',
        value: init.allowedDatabases ? init.allowedDatabases.join(', ') : '',
        testid: 'f-allowed-databases'
      });
      var allowedTables = UI.textInput({
        placeholder: '逗号分隔；留空 = 不限制',
        value: init.allowedTables ? init.allowedTables.join(', ') : '',
        testid: 'f-allowed-tables'
      });
      var allowedSchemas = UI.textInput({
        placeholder: '逗号分隔；留空 = 不限制',
        value: init.allowedSchemas ? init.allowedSchemas.join(', ') : '',
        testid: 'f-allowed-schemas'
      });
      var schemaField = UI.field('允许的 schema（可选，PG 专用）', allowedSchemas, {
        help: '逗号分隔，例如 public, reporting。留空 = null = 不限（不是禁止）。',
        required: false
      });
      schemaField.hidden = initialEngine !== 'postgres';
      var allowMetadata = UI.checkboxInput('允许读取元数据（information_schema / pg_catalog 等）', {
        name: 'allow_metadata', testid: 'f-allow-metadata', checked: init.allowMetadata !== false
      });
      var approvalWrite = UI.checkboxInput('写数据（INSERT/UPDATE/DELETE）需要审批', {
        name: 'approval_write', testid: 'f-approval-write', checked: !!init.approvalWrite
      });
      var approvalDdl = UI.checkboxInput('DDL（CREATE/ALTER/DROP 等）需要审批', {
        name: 'approval_ddl', testid: 'f-approval-ddl', checked: init.approvalDdl !== false
      });
      var approvalTtl = UI.textInput({
        type: 'number', min: '60', max: '86400',
        value: init.approvalTtl ? String(init.approvalTtl) : '600',
        testid: 'f-approval-ttl'
      });
      return {
        maxLevel: maxLevel,
        allowedDatabases: allowedDatabases,
        allowedTables: allowedTables,
        allowedSchemas: allowedSchemas,
        schemaField: schemaField,
        setEngine: function (engine) { schemaField.hidden = engine !== 'postgres'; },
        allowMetadata: allowMetadata,
        approvalWrite: approvalWrite,
        approvalDdl: approvalDdl,
        approvalTtl: approvalTtl,
        nodes: [
          UI.el('div', { 'class': 'form-grid' }, [
            UI.field('max_level', maxLevel, { help: '策略上限：即使 AI 传 --write/--unsafe 也不会超过该等级。' }),
            UI.field('审批有效期（秒）', approvalTtl, { help: '60–86400，默认 600。' })
          ]),
          UI.el('div', { 'class': 'form-grid' }, [
            UI.field('允许的库', allowedDatabases, { help: '库级白名单，例如 appdb, analytics。PG 的库白名单不限制 schema；要限制 schema 请用 allowed_schemas。' }),
            UI.field('允许的表', allowedTables, { help: '表级白名单（启发式，防误触）。' })
          ]),
          schemaField,
          UI.field('元数据', allowMetadata.wrap, { help: '关闭后 read 等级也不允许查询 information_schema 等元数据模式。' }),
          UI.field('审批开关', UI.el('div', { 'class': 'check-grid' }, [approvalWrite.wrap, approvalDdl.wrap]))
        ]
      };
    }

    function validatePolicy(fields) {
      var ttl = parseInt(fields.approvalTtl.value, 10);
      if (!(ttl >= 60 && ttl <= 86400)) return { message: '审批有效期需在 60–86400 秒之间' };
      return null;
    }

    function policyBody(fields) {
      return {
        max_level: fields.maxLevel.value,
        allowed_databases: parseList(fields.allowedDatabases.value),
        allowed_tables: parseList(fields.allowedTables.value),
        allowed_schemas: parseList(fields.allowedSchemas.value),
        allow_metadata: fields.allowMetadata.input.checked,
        approval: {
          write: fields.approvalWrite.input.checked,
          ddl: fields.approvalDdl.input.checked
        },
        approval_ttl_s: parseInt(fields.approvalTtl.value, 10)
      };
    }

    function openAddDatabase() {
      var alias = UI.textInput({ placeholder: '例如 demo-mysql', testid: 'f-alias' });
      var engine = UI.selectInput({
        name: 'engine', testid: 'f-engine', value: 'mysql',
        options: [
          { value: 'mysql', label: 'mysql' },
          { value: 'postgres', label: 'postgres' },
          { value: 'sqlite', label: 'sqlite' }
        ]
      });
      var host = UI.textInput({ placeholder: 'IP 或域名', testid: 'f-host' });
      var port = UI.textInput({ type: 'number', value: '3306', min: '1', max: '65535', testid: 'f-port' });
      var user = UI.textInput({ placeholder: '数据库用户', testid: 'f-user' });
      var password = UI.textInput({
        type: 'password', autocomplete: 'new-password',
        placeholder: '数据库密码（仅本次导入，不会回显）', testid: 'f-password'
      });
      var database = UI.textInput({ placeholder: '默认库，可选', testid: 'f-database' });
      var file = UI.textInput({ placeholder: '/path/to/database.sqlite', testid: 'f-file' });
      var note = UI.textareaInput({ rows: 2, placeholder: '可选', testid: 'f-note' });

      var fields = buildPolicyFields({ engine: engine.value });

      var serverFields = UI.el('div', {}, [
        UI.el('div', { 'class': 'form-grid' }, [
          UI.field('主机', host, { required: true }),
          UI.field('端口', port)
        ]),
        UI.el('div', { 'class': 'form-grid' }, [
          UI.field('用户', user, { required: true }),
          UI.field('密码', password, { help: '留空表示无需密码；密码只写不读。' })
        ]),
        UI.field('默认库（database）', database, { help: '可选；SQL 中未指定库时使用。' })
      ]);
      var fileField = UI.field('SQLite 文件路径', file, {
        required: true,
        help: '本机上 .sqlite / .db 文件的绝对路径。'
      });
      fileField.hidden = true;

      var lastDefault = engineDefaults(engine.value);
      engine.addEventListener('change', function () {
        var isSqlite = engine.value === 'sqlite';
        serverFields.hidden = isSqlite;
        fileField.hidden = !isSqlite;
        fields.setEngine(engine.value);
        if (!isSqlite) {
          var nextDefault = engineDefaults(engine.value);
          if (!port.value || port.value === lastDefault) port.value = nextDefault;
          lastDefault = nextDefault;
        }
      });

      UI.openFormModal({
        title: '添加数据库',
        subtitle: 'MySQL / PostgreSQL 填连接参数；SQLite 填本机文件路径。',
        submitLabel: '添加',
        body: [
          UI.field('别名', alias, { required: true, help: '仅允许字母、数字、点、下划线、连字符（[A-Za-z0-9_.-]）' }),
          UI.el('div', { 'class': 'form-grid' }, [
            UI.field('引擎', engine),
            UI.field('备注', note)
          ]),
          serverFields,
          fileField,
          fields.nodes
        ],
        validate: function () {
          var a = alias.value.trim();
          if (!a) return { message: '请填写别名' };
          if (!/^[A-Za-z0-9_.-]+$/.test(a) || a.indexOf('..') >= 0) {
            return { message: '别名只能包含字母、数字、点、下划线、连字符，且不能含 ".."' };
          }
          if (engine.value === 'sqlite') {
            if (!file.value.trim()) return { message: '请填写 SQLite 文件路径' };
          } else {
            if (!host.value.trim()) return { message: '请填写主机地址' };
            if (!user.value.trim()) return { message: '请填写数据库用户' };
            var p = parseInt(port.value, 10);
            if (!(p >= 1 && p <= 65535)) return { message: '端口需在 1–65535 之间' };
          }
          return validatePolicy(fields);
        },
        onSubmit: function (api) {
          var bodyData = {
            alias: alias.value.trim(),
            engine: engine.value,
            note: note.value.trim()
          };
          if (engine.value === 'sqlite') {
            bodyData.file = file.value.trim();
          } else {
            bodyData.host = host.value.trim();
            bodyData.port = parseInt(port.value, 10);
            bodyData.user = user.value.trim();
            if (database.value.trim()) bodyData.database = database.value.trim();
            if (password.value) bodyData.password = password.value;
          }
          var policy = policyBody(fields);
          Object.keys(policy).forEach(function (key) { bodyData[key] = policy[key]; });

          function clearSecrets() { password.value = ''; }

          return net.post('/api/databases', bodyData).then(function () {
            clearSecrets();
            api.close();
            UI.successToast('已添加数据库 ' + bodyData.alias);
            return load(false);
          }, function (err) {
            clearSecrets();
            throw err;
          });
        }
      });
    }

    function openEditDatabase(db) {
      var host = UI.textInput({ value: db.host, placeholder: '留空 = 不修改', testid: 'f-host' });
      var port = UI.textInput({
        type: 'number', value: db.port === '' ? '' : String(db.port),
        placeholder: '留空 = 不修改', testid: 'f-port'
      });
      var user = UI.textInput({ value: db.user, placeholder: '留空 = 不修改', testid: 'f-user' });
      var password = UI.textInput({
        type: 'password', autocomplete: 'new-password',
        placeholder: '留空 = 不修改', testid: 'f-password'
      });
      var database = UI.textInput({ value: db.database, placeholder: '留空 = 不修改', testid: 'f-database' });
      var file = UI.textInput({ value: db.file, placeholder: '留空 = 不修改', testid: 'f-file' });

      var fields = buildPolicyFields({
        engine: db.engine,
        maxLevel: db.maxLevel,
        allowedDatabases: formatWhitelist(db.allowedDatabases),
        allowedTables: formatWhitelist(db.allowedTables),
        allowedSchemas: formatWhitelist(db.allowedSchemas),
        allowMetadata: db.allowMetadata,
        approvalWrite: db.approvalWrite,
        approvalDdl: db.approvalDdl,
        approvalTtl: db.approvalTtl
      });

      var connectionFields;
      if (db.engine === 'sqlite') {
        connectionFields = UI.field('SQLite 文件路径', file, { help: '留空 = 不修改当前路径。' });
      } else {
        connectionFields = UI.el('div', {}, [
          UI.el('div', { 'class': 'form-grid' }, [
            UI.field('主机', host, { help: '留空 = 不修改' }),
            UI.field('端口', port, { help: '留空 = 不修改' })
          ]),
          UI.el('div', { 'class': 'form-grid' }, [
            UI.field('用户', user, { help: '留空 = 不修改' }),
            UI.field('密码', password, { help: '留空 = 不修改；不会回显已存密码。' })
          ]),
          UI.field('默认库（database）', database, { help: '留空 = 不修改' })
        ]);
      }

      UI.openFormModal({
        title: '编辑数据库 · ' + db.alias,
        subtitle: (ENGINE_LABELS[db.engine] || db.engine) + ' · 连接参数留空 = 不修改',
        submitLabel: '保存',
        body: [
          UI.el('div', { 'class': 'warn-banner', text: '连接参数留空表示保持原值；密码留空表示不修改。' }),
          connectionFields,
          fields.nodes
        ],
        validate: function () {
          if (db.engine !== 'sqlite') {
            if (port.value.trim() !== '') {
              var p = parseInt(port.value, 10);
              if (!(p >= 1 && p <= 65535)) return { message: '端口需在 1–65535 之间（或留空）' };
            }
          }
          return validatePolicy(fields);
        },
        onSubmit: function (api) {
          var bodyData = policyBody(fields);
          bodyData.note = db.note || '';

          function addIfPresent(value, key) {
            if (value !== undefined && value !== null && String(value).trim() !== '') {
              bodyData[key] = String(value).trim();
            }
          }
          if (db.engine === 'sqlite') {
            addIfPresent(file.value, 'file');
          } else {
            addIfPresent(host.value, 'host');
            if (port.value.trim() !== '') bodyData.port = parseInt(port.value, 10);
            addIfPresent(user.value, 'user');
            addIfPresent(database.value, 'database');
            if (password.value) bodyData.password = password.value;
          }

          return net.put(resourcePath(db.alias), bodyData).then(function () {
            password.value = '';
            api.close();
            UI.successToast('已保存 ' + db.alias);
            return load(false);
          }, function (err) {
            password.value = '';
            throw err;
          });
        }
      });
    }

    function deleteDatabase(db) {
      UI.confirmAction({
        title: '删除数据库',
        message: '确定删除数据库别名「' + db.alias + '」吗？删除后 dbbind 将无法用该别名执行 SQL，此操作不可撤销。',
        detail: db.engine + ' · ' + (db.engine === 'sqlite' ? db.file : db.host + ':' + db.port),
        warn: '如果该别名来自手写配置文件（origin=config），删除可能被拒绝，需要直接编辑配置文件。',
        confirmLabel: '删除'
      }).then(function (result) {
        if (!result.confirmed) return;
        return net.del(resourcePath(db.alias), {}).then(function () {
          UI.successToast('已删除 ' + db.alias);
          return load(false);
        }, function (err) {
          UI.errorToast(err);
        });
      });
    }

    app().registerSilentRefresher(function () { return load(false); });
    load(true);
  }

  /* ================================================================
   * 审批中心
   * ================================================================ */

  function normalizeApproval(raw) {
    return {
      id: raw.id || '',
      tool: raw.tool || '',
      alias: raw.alias || '',
      action: raw.action || '',
      target: raw.target || '',
      requester: raw.requester || '',
      createdAt: raw.created_at || '',
      expiresAt: raw.expires_at || '',
      status: raw.status || 'pending',
      decidedAt: raw.decided_at || '',
      decidedBy: raw.decided_by || '',
      consumesLeft: raw.consumes_left,
      note: raw.note || '',
      raw: raw
    };
  }

  function statusBadge(status) {
    var map = {
      pending: ['待审批', 'amber'],
      approved: ['已批准', 'green'],
      denied: ['已拒绝', 'red'],
      consumed: ['已消费', 'purple'],
      expired: ['已过期', 'gray']
    };
    var item = map[status] || [status, 'gray'];
    return UI.badge(item[0], item[1]);
  }

  function approvalsPage(view, ctx) {
    var pageRoot = UI.el('div');
    view.appendChild(pageRoot);

    var filterStatus = 'pending';
    var pendingTab = UI.el('button', { type: 'button', 'class': 'tab active', 'data-testid': 'tab-pending', text: '待审批' });
    var allTab = UI.el('button', { type: 'button', 'class': 'tab', 'data-testid': 'tab-all', text: '全部' });
    var tabs = UI.el('div', { 'class': 'tabs', role: 'tablist' }, [pendingTab, allTab]);

    var head = UI.pageHeader({
      title: '审批中心',
      sub: 'AI 发起的 sudo / 写入 / DDL 操作在这里人工放行。批准后 AI 重试同一命令即可执行；拒绝后需重新申请。',
      actions: [
        tabs,
        UI.button({ label: '刷新', variant: 'ghost', small: true, testid: 'btn-refresh', onClick: function () { load(true); } })
      ]
    });
    pageRoot.appendChild(head.el);
    var body = UI.el('div');
    pageRoot.appendChild(body);

    var current = [];
    var countdownTimer = null;
    var loading = false;

    function setActiveTab() {
      pendingTab.classList.toggle('active', filterStatus === 'pending');
      allTab.classList.toggle('active', filterStatus === 'all');
    }

    pendingTab.addEventListener('click', function () {
      if (filterStatus === 'pending') return;
      filterStatus = 'pending';
      setActiveTab();
      load(true);
    });
    allTab.addEventListener('click', function () {
      if (filterStatus === 'all') return;
      filterStatus = 'all';
      setActiveTab();
      load(true);
    });

    function load(initial) {
      if (loading) return Promise.resolve();
      loading = true;
      if (initial) {
        UI.clear(body);
        body.appendChild(UI.loadingBlock('正在加载审批单…'));
      }
      return net.get('/api/approvals', { status: filterStatus }).then(function (data) {
        if (!app().isCurrent(ctx.epoch)) return;
        current = listOf(data, 'approvals').map(normalizeApproval);
        renderList();
      }).catch(function (err) {
        if (!app().isCurrent(ctx.epoch)) return;
        if (initial) {
          UI.clear(body);
          body.appendChild(UI.errorBlock(err, function () { load(true); }));
        }
      }).then(function () {
        loading = false;
      });
    }

    function tickCountdowns() {
      var nodes = body.querySelectorAll('[' + COUNTDOWN_ATTR + ']');
      for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var result = UI.countdown(node.getAttribute(COUNTDOWN_ATTR));
        node.textContent = result.text;
        node.className = 'approval-countdown' + (result.state === 'urgent' ? ' urgent' : (result.state === 'expired' ? ' expired' : ''));
      }
    }

    function startCountdown() {
      if (countdownTimer) clearInterval(countdownTimer);
      countdownTimer = setInterval(tickCountdowns, 1000);
      app().registerCleanup(function () {
        if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
      });
    }

    function actionButtons(approval, card) {
      if (approval.status !== 'pending') return null;
      var row = UI.el('div', { 'class': 'approval-actions' });

      function makeBtn(label, testid, opts) {
        var btn = UI.button({ label: label, variant: 'primary', small: true, testid: testid });
        btn.addEventListener('click', function () {
          if (btn.disabled) return;
          var buttons = card.querySelectorAll('button');
          for (var i = 0; i < buttons.length; i++) buttons[i].disabled = true;
          net.post('/api/approvals/' + enc(approval.id) + '/approve', opts).then(function () {
            UI.successToast('已批准：' + approval.alias + ' / ' + approval.action);
            return Promise.all([load(false), app().refreshStatus()]);
          }).catch(function (err) {
            UI.errorToast(err);
          }).then(function () {
            if (card.isConnected) {
              for (var j = 0; j < buttons.length; j++) buttons[j].disabled = false;
            }
          });
        });
        return btn;
      }

      row.appendChild(makeBtn('批准（一次性）', 'approve-once-' + approval.id, { consumes: 1 }));
      row.appendChild(makeBtn('批准 5 分钟', 'approve-ttl-' + approval.id, { ttl_s: 300 }));
      row.appendChild(makeBtn('批准 10 次', 'approve-consumes-' + approval.id, { consumes: 10 }));
      row.appendChild(UI.el('span', { 'class': 'spacer' }));
      var rejectBtn = UI.button({ label: '拒绝', variant: 'danger', small: true, testid: 'reject-' + approval.id });
      rejectBtn.addEventListener('click', function () { openReject(approval); });
      row.appendChild(rejectBtn);
      return row;
    }

    function renderList() {
      UI.clear(body);
      head.setCount(current.length);

      if (!current.length) {
        body.appendChild(emptyPage(
          filterStatus === 'pending' ? '没有待审批的操作' : '还没有审批单',
          filterStatus === 'pending'
            ? '当 AI 触发了需要审批的 sudo / 写入 / DDL 操作时，这里会出现对应审批单。页面每 5 秒自动刷新。'
            : 'AI 触发审批后，审批单会出现在这里。'
        ));
        return;
      }

      var list = UI.el('div', { 'class': 'approval-list', 'data-testid': 'approvals-list' });
      current.forEach(function (approval) {
        var card = UI.el('div', {
          'class': 'approval-card',
          'data-status': approval.status,
          'data-id': approval.id,
          'data-testid': 'approval-card'
        });

        var top = UI.el('div', { 'class': 'approval-top' });
        if (approval.tool) top.appendChild(UI.badge(approval.tool, approval.tool === 'db' ? 'purple' : 'blue', { plain: true }));
        top.appendChild(UI.badge(approval.action || '—', approval.action === 'ddl' ? 'red' : (approval.action === 'write' ? 'amber' : 'blue'), {
          plain: true,
          title: ACTION_LABELS[approval.action] || approval.action
        }));
        top.appendChild(UI.el('span', { 'class': 'approval-alias', text: approval.alias || '—' }));
        if (approval.status !== 'pending') top.appendChild(statusBadge(approval.status));
        var countdownEl = UI.el('span', { 'class': 'approval-countdown' });
        countdownEl.setAttribute(COUNTDOWN_ATTR, approval.expiresAt);
        top.appendChild(countdownEl);
        card.appendChild(top);

        card.appendChild(UI.el('pre', { 'class': 'approval-target', text: approval.target || '—' }));

        var meta = UI.el('div', { 'class': 'approval-meta' });
        meta.appendChild(UI.el('span', { text: '创建 ' + UI.fmtDateTime(approval.createdAt) }));
        meta.appendChild(UI.el('span', { text: '过期 ' + UI.fmtDateTime(approval.expiresAt) }));
        if (approval.requester) meta.appendChild(UI.el('span', { text: '发起者 ' + approval.requester }));
        if (approval.consumesLeft !== undefined && approval.consumesLeft !== null) {
          meta.appendChild(UI.el('span', { text: '可用次数 ' + approval.consumesLeft }));
        }
        card.appendChild(meta);

        if (approval.note) card.appendChild(UI.el('div', { 'class': 'approval-note', text: '备注：' + approval.note }));

        var actions = actionButtons(approval, card);
        if (actions) card.appendChild(actions);

        list.appendChild(card);
      });
      body.appendChild(list);
      tickCountdowns();
      if (!countdownTimer) startCountdown();
    }

    function openReject(approval) {
      var note = UI.textareaInput({ rows: 3, placeholder: '可选：填写拒绝原因，会记录在审批单和审计里', testid: 'reject-note' });
      UI.openFormModal({
        title: '拒绝审批',
        subtitle: approval.alias + ' · ' + (ACTION_LABELS[approval.action] || approval.action),
        submitLabel: '确认拒绝',
        danger: true,
        body: [
          UI.el('p', { 'class': 'text-2', text: '拒绝后该请求立即失效，AI 需要用新的请求重新申请。' }),
          UI.field('备注（可选）', note)
        ],
        onSubmit: function (api) {
          var bodyData = {};
          var trimmed = note.value.trim();
          if (trimmed) bodyData.note = trimmed;
          return net.post('/api/approvals/' + enc(approval.id) + '/reject', bodyData).then(function () {
            api.close();
            UI.successToast('已拒绝：' + approval.alias + ' / ' + approval.action);
            return Promise.all([load(false), app().refreshStatus()]);
          });
        }
      });
    }

    app().registerSilentRefresher(function () { return load(false); });
    setActiveTab();
    load(true);
  }

  /* ================================================================
   * 审计
   * ================================================================ */

  function normalizeAudit(raw) {
    return {
      ts: raw.ts || raw.timestamp || '',
      tool: raw.tool || '',
      actor: raw.actor || '',
      alias: raw.alias || '',
      action: raw.action || '',
      decision: raw.decision || '',
      requestId: raw.request_id || '',
      target: raw.target || '',
      source: raw.source || '',
      note: raw.note || ''
    };
  }

  function auditPage(view, ctx) {
    var pageRoot = UI.el('div');
    view.appendChild(pageRoot);

    var head = UI.pageHeader({
      title: '审计',
      sub: '两个工具共写的操作记录（~/.bindconsole/audit.log）。按时间倒序，绝不记录密码与私钥。'
    });
    pageRoot.appendChild(head.el);

    var decisionSelect = UI.selectInput({
      name: 'decision', testid: 'audit-decision', value: '',
      options: [
        { value: '', label: '全部决策' },
        { value: 'allow', label: 'allow' },
        { value: 'deny', label: 'deny' },
        { value: 'ask', label: 'ask' },
        { value: 'approve', label: 'approve' },
        { value: 'reject', label: 'reject' },
        { value: 'consume', label: 'consume' },
        { value: 'error', label: 'error' }
      ]
    });
    var toolSelect = UI.selectInput({
      name: 'tool', testid: 'audit-tool', value: '',
      options: [
        { value: '', label: '当前控制台' },
        { value: 'all', label: '全部工具' }
      ]
    });
    var limitSelect = UI.selectInput({
      name: 'limit', testid: 'audit-limit', value: '100',
      options: [
        { value: '50', label: '50 条' },
        { value: '100', label: '100 条' },
        { value: '200', label: '200 条' },
        { value: '500', label: '500 条' }
      ]
    });
    var refreshBtn = UI.button({ label: '刷新', variant: 'ghost', small: true, testid: 'btn-refresh', onClick: function () { load(true); } });

    var filterBar = UI.el('div', { 'class': 'filter-bar' }, [
      UI.el('label', { 'class': 'field-label', 'for': decisionSelect.id, text: '决策' }),
      decisionSelect,
      UI.el('label', { 'class': 'field-label', 'for': toolSelect.id, text: '工具' }),
      toolSelect,
      UI.el('label', { 'class': 'field-label', 'for': limitSelect.id, text: '条数' }),
      limitSelect,
      UI.el('span', { 'class': 'filter-spacer' }),
      refreshBtn
    ]);
    pageRoot.appendChild(filterBar);

    var body = UI.el('div');
    pageRoot.appendChild(body);

    var loading = false;

    function load(initial) {
      if (loading) return Promise.resolve();
      loading = true;
      var query = {
        limit: limitSelect.value,
        decision: decisionSelect.value,
        tool: toolSelect.value || undefined
      };
      var hadEntries = body.querySelector('table') !== null;
      if (initial && !hadEntries) {
        UI.clear(body);
        body.appendChild(UI.loadingBlock('正在加载审计…'));
      }
      return net.get('/api/audit', query).then(function (data) {
        if (!app().isCurrent(ctx.epoch)) return;
        render(listOf(data, 'entries').map(normalizeAudit));
      }).catch(function (err) {
        if (!app().isCurrent(ctx.epoch)) return;
        if (initial) {
          UI.clear(body);
          body.appendChild(UI.errorBlock(err, function () { load(true); }));
        }
      }).then(function () {
        loading = false;
      });
    }

    function render(entries) {
      UI.clear(body);
      head.setCount(entries.length);
      if (!entries.length) {
        body.appendChild(emptyPage('暂无审计记录', '当 AI 或控制台执行操作、触发审批时，这里会出现记录。'));
        return;
      }
      var table = UI.dataTable([
        {
          label: '时间',
          render: function (row) {
            var node = UI.el('span', { 'class': 'nowrap mono-sm', text: UI.fmtDateTime(row.ts) });
            if (row.requestId) node.title = 'request_id: ' + row.requestId;
            return node;
          }
        },
        {
          label: '工具',
          render: function (row) {
            return row.tool ? UI.badge(row.tool, row.tool === 'db' ? 'purple' : 'blue', { plain: true }) : UI.el('span', { text: '—' });
          }
        },
        {
          label: '操作者',
          render: function (row) { return UI.el('span', { 'class': 'mono-sm', text: row.actor || '—' }); }
        },
        {
          label: '别名',
          render: function (row) { return UI.el('span', { 'class': 'cell-mono', text: row.alias || '—' }); }
        },
        {
          label: '动作',
          render: function (row) { return UI.el('span', { 'class': 'mono-sm', text: row.action || '—' }); }
        },
        {
          label: '决策',
          render: function (row) {
            return UI.badge(row.decision || '—', DECISION_TONES[row.decision] || 'gray', { plain: true });
          }
        },
        {
          label: '目标',
          render: function (row) {
            var cell = UI.el('span', {
              'class': 'target-cell',
              text: UI.truncate(row.target || '—', 160),
              title: row.target || ''
            });
            return cell;
          }
        },
        {
          label: '备注',
          render: function (row) {
            var parts = [];
            if (row.note) parts.push(row.note);
            if (row.source) parts.push('来源 ' + row.source);
            var text = parts.length ? parts.join(' · ') : '—';
            return UI.el('span', { 'class': 'mono-sm', text: UI.truncate(text, 60), title: text });
          }
        }
      ], entries);
      body.appendChild(table.el);
    }

    [decisionSelect, toolSelect, limitSelect].forEach(function (control) {
      control.addEventListener('change', function () { load(true); });
    });

    app().registerSilentRefresher(function () { return load(false); });
    load(true);
  }

  BC.pages = {
    setup: setupPage,
    login: loginPage,
    servers: serversPage,
    databases: databasesPage,
    approvals: approvalsPage,
    audit: auditPage
  };
})();
