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

  function showFormError(error, err) {
    error.show(err);
    error.el.setAttribute('role', 'alert');
    if (typeof error.el.scrollIntoView === 'function') error.el.scrollIntoView({ block: 'nearest' });
  }

  // Selected values survive searching and a temporarily unavailable discovery endpoint.
  function searchableChoices(initial, testid) {
    var selected = Object.create(null);
    (initial || []).forEach(function (name) { selected[String(name)] = true; });
    var choices = [];
    var search = UI.textInput({ placeholder: '搜索名称', testid: testid + '-search' });
    search.setAttribute('aria-label', '搜索名称');
    var list = UI.el('div', { 'class': 'choice-list', 'data-testid': testid });
    function draw() {
      UI.clear(list);
      var known = Object.create(null);
      choices.forEach(function (item) { known[item.name] = true; });
      var all = choices.concat(Object.keys(selected).filter(function (name) { return !known[name]; }).map(function (name) {
        return { name: name, label: name + '（已保存，暂未发现）' };
      }));
      var filtered = all.filter(function (item) { return String(item.label || item.name).toLowerCase().indexOf(search.value.toLowerCase()) >= 0; });
      if (!filtered.length) list.appendChild(UI.el('p', { 'class': 'field-help', text: choices.length ? '没有匹配项' : '暂无可选项' }));
      filtered.forEach(function (item) {
        var checkbox = UI.checkboxInput(item.label || item.name, { checked: !!selected[item.name] });
        checkbox.input.disabled = !!item.disabled && !selected[item.name];
        checkbox.input.addEventListener('change', function () {
          if (checkbox.input.checked) selected[item.name] = true; else delete selected[item.name];
        });
        list.appendChild(checkbox.wrap);
      });
    }
    search.addEventListener('input', draw);
    draw();
    return {
      el: UI.el('div', { 'class': 'choice-picker' }, [search, list]),
      values: function () { return Object.keys(selected).sort(); },
      update: function (items) { choices = items; draw(); }
    };
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
      verificationStatus: raw.verification_status || '',
      hasKey: raw.has_key === true || !!raw.key_path,
      hasPassword: raw.has_password === true,
      hasEncryptedLogin: raw.has_encrypted_login === true,
      sudoAuth: raw.sudo_auth || 'none',
      hasSudoCredential: raw.has_sudo_credential === true,
      keychain: raw.keychain || {},
      allowedUsers: raw.allowed_users || [],
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
        UI.button({ label: '导入连接', testid: 'btn-import', onClick: function () { openImportConnections(function () { return load(false); }); } }),
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
          render: function (row) {
            var box = UI.el('span', { 'class': 'badge-stack' }, [sourceCell(row.server.source)]);
            if (row.server.verificationStatus === 'pending') {
              var pending = UI.badge('待验证', 'amber', { title: '尚未验证连接，暂不可用于执行命令' });
              pending.setAttribute('data-testid', 'verification-' + row.server.name);
              box.appendChild(pending);
            }
            return box;
          }
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
          render: function (row) { return UI.el('div', {}, [sudoBadge(row.server.sudo), UI.el('div', { 'class': 'field-help', text: row.server.sudoAuth === 'keyring' ? (row.server.hasSudoCredential ? '钥匙串凭据已设置' : '钥匙串凭据未设置') : (row.server.sudoAuth === 'nopasswd' ? 'NOPASSWD' : '未配置认证') })]); }
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
            editBtn.addEventListener('click', function () {
              if (editBtn.disabled) return;
              editBtn.disabled = true; editBtn.textContent = '加载中…';
              openEditServer(s).then(function () { editBtn.disabled = false; editBtn.textContent = '编辑'; });
            });
            var delBtn = UI.btnLink('删除', { danger: true, testid: 'delete-' + s.name });
            delBtn.addEventListener('click', function () { deleteServer(s); });
            var actions = UI.el('span', {}, [testBtn, editBtn]);
            if (s.hasEncryptedLogin) {
              var unlockBtn = UI.btnLink('解锁 Xshell 密码', { testid: 'unlock-' + s.name });
              unlockBtn.addEventListener('click', function () { openUnlockServer(s); });
              actions.appendChild(unlockBtn);
            }
            actions.appendChild(delBtn);
            return actions;
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
        if (ok && server.verificationStatus === 'pending') load(false);
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

      function clearSecrets() { password.value = ''; privateKey.value = ''; }
      var addApi = UI.openFormModal({
        title: '添加服务器',
        onClose: clearSecrets,
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
      app().registerCleanup(function () { addApi.close(); });
    }

    function openEditServer(server) {
      return net.get(resourcePath(server.name)).then(function (data) {
        if (!app().isCurrent(ctx.epoch)) return;
        showEditServer(normalizeServer(data.server || data));
      }).catch(function (err) { UI.errorToast(err); });
    }

    function showEditServer(server) {
      var host = UI.textInput({ value: server.host, testid: 'f-host' });
      var user = UI.textInput({ value: server.user, testid: 'f-user' });
      var port = UI.textInput({ type: 'number', value: server.port, min: '1', max: '65535', testid: 'f-port' });
      var loginPassword = UI.textInput({ type: 'password', autocomplete: 'new-password', placeholder: '留空不修改', testid: 'f-login-password' });
      var privateKey = UI.textareaInput({ rows: 4, placeholder: '粘贴新私钥；留空不修改', testid: 'f-private-key' });
      var sudo = UI.selectInput({ name: 'sudo', testid: 'f-sudo', value: server.sudo, options: [
        { value: 'allow', label: 'allow — 直接放行' }, { value: 'ask', label: 'ask — 需要审批' }, { value: 'deny', label: 'deny — 一律拒绝' }
      ] });
      var sudoAuth = UI.selectInput({ value: server.sudoAuth, testid: 'f-sudo-auth', options: [
        { value: 'none', label: '未配置 sudo 认证' }, { value: 'keyring', label: '系统钥匙串密码' }, { value: 'nopasswd', label: '远端已配置 NOPASSWD' }
      ] });
      var sudoPassword = UI.textInput({ type: 'password', autocomplete: 'new-password', placeholder: '留空保留已存密码', testid: 'f-sudo-password' });
      var clearSudo = UI.checkboxInput('清除已保存的 sudo 密码', { testid: 'f-clear-sudo-password' });
      var keychain = server.keychain;
      var status = UI.el('div', { 'class': keychain.available ? 'field-help' : 'warn-banner', text:
        (server.hasSudoCredential ? 'sudo 密码已保存。' : '尚未保存 sudo 密码。') +
        (keychain.available ? ' 系统钥匙串可用' + (keychain.backend ? '：' + keychain.backend : '') : ' 系统钥匙串不可用：' + (keychain.reason || '请安装或解锁钥匙串后重试') + '。可运行 bash install.sh --with-integrations 安装集成依赖。')
      });
      sudoPassword.disabled = !keychain.available;
      var users = searchableChoices(server.allowedUsers, 'f-allowed-users');
      var usersStatus = UI.el('div', { 'class': 'field-help', 'aria-live': 'polite' });
      var discover = UI.button({ label: '刷新远端账号', small: true, testid: 'f-discover-users', onClick: discoverUsers });
      function discoverUsers() {
        if (discover.disabled) return;
        discover.disabled = true;
        usersStatus.textContent = '正在发现远端账号…';
        net.get(resourcePath(server.name, 'users')).then(function (data) {
          if (formApi.modal.isClosed()) return;
          var found = listOf(data, 'users');
          users.update(found.map(function (item) {
            var protectedUser = item.sensitive !== false || !Number.isInteger(Number(item.uid)) || Number(item.uid) <= 0;
            return { name: item.name, label: item.name + ' · UID ' + item.uid + (protectedUser ? ' · 敏感账号，仍需审批' : ''), disabled: protectedUser };
          }));
          usersStatus.textContent = found.length ? '只选择可信的普通账号；敏感或无法解析的身份仍需审批。' : '没有发现可选账号。可刷新重试，已保存选择会保留。';
        }).catch(function (err) {
          if (!formApi.modal.isClosed()) usersStatus.textContent = '发现账号失败：' + err.message + '。请检查连接后重试；已保存选择保留。';
        }).then(function () { discover.disabled = false; });
      }
      var ttl = UI.textInput({ type: 'number', min: '60', max: '86400', value: server.approvalTtl === null ? '' : String(server.approvalTtl), placeholder: '留空使用默认', testid: 'f-approval-ttl' });
      var note = UI.textareaInput({ rows: 2, value: server.note, testid: 'f-note' });
      function clearSecrets() { loginPassword.value = ''; privateKey.value = ''; sudoPassword.value = ''; }
      function invalid(message) { clearSecrets(); return { message: message }; }
      var formApi = UI.openFormModal({
        title: '编辑服务器 · ' + server.name,
        subtitle: '别名保持不变。凭据只写不读，留空不修改；替换前会验证连接。',
        submitLabel: '保存',
        onClose: clearSecrets,
        body: [
          UI.el('div', { 'class': 'form-grid' }, [UI.field('主机', host, { required: true }), UI.field('端口', port)]),
          UI.field('SSH 登录用户', user, { required: true }),
          UI.field('SSH 登录密码', loginPassword, { help: '仅用来重新绑定 SSH 密钥，不修改远端账户密码。它与 sudo 提权密码独立；密码和私钥只填写一种。' }),
          UI.field('替换 SSH 私钥', privateKey, { help: '仅粘贴密钥内容。验证通过后才替换；原密钥不会自动吊销。' }),
          UI.el('h3', { 'class': 'section-title', text: 'sudo 提权' }), status,
          UI.field('sudo 策略', sudo), UI.field('sudo 认证', sudoAuth),
          UI.field('sudo 密码', sudoPassword, { help: '仅保存到系统钥匙串，不会回填。NOPASSWD 需要在远端预先配置。' }), clearSudo.wrap,
          UI.field('允许免身份审批的普通账号', users.el), discover, usersStatus,
          UI.field('审批有效期（秒）', ttl, { help: '留空使用默认值；范围 60–86400。' }), UI.field('备注', note)
        ],
        validate: function () {
          if (!host.value.trim() || !user.value.trim()) return invalid('主机和 SSH 登录用户不能为空');
          if (!(Number(port.value) >= 1 && Number(port.value) <= 65535 && Number.isInteger(Number(port.value)))) return invalid('端口需为 1–65535 的整数');
          if (loginPassword.value && privateKey.value.trim()) return invalid('SSH 登录密码和新私钥请只填写一种');
          if (clearSudo.input.checked && sudoPassword.value) return invalid('不能同时设置和清除 sudo 密码');
          if (ttl.value.trim() && !(Number(ttl.value) >= 60 && Number(ttl.value) <= 86400 && Number.isInteger(Number(ttl.value)))) return invalid('审批有效期需在 60–86400 秒之间');
          return null;
        },
        onSubmit: function (api) {
          var bodyData = { host: host.value.trim(), user: user.value.trim(), port: Number(port.value), sudo: sudo.value, sudo_auth: sudoAuth.value, allowed_users: users.values(), note: note.value.trim() };
          if (ttl.value.trim()) bodyData.approval_ttl_s = Number(ttl.value);
          if (loginPassword.value) bodyData.login_password = loginPassword.value;
          if (privateKey.value.trim()) bodyData.private_key = privateKey.value.trim();
          if (sudoPassword.value) bodyData.sudo_password = sudoPassword.value;
          if (clearSudo.input.checked) bodyData.clear_sudo_password = true;
          return net.put(resourcePath(server.name), bodyData).then(function () {
            api.close(); UI.successToast('已保存 ' + server.name); return load(false);
          }).then(function () { clearSecrets(); }, function (err) { clearSecrets(); throw err; }).then(function () {
            delete bodyData.login_password; delete bodyData.private_key; delete bodyData.sudo_password;
          }, function (err) {
            delete bodyData.login_password; delete bodyData.private_key; delete bodyData.sudo_password; throw err;
          });
        }
      });
      app().registerCleanup(function () { formApi.close(); });
      discoverUsers();
    }

    function openUnlockServer(server) {
      var masterPassword = UI.textInput({ type: 'password', autocomplete: 'new-password', placeholder: '可选：Xshell 主密码', testid: 'unlock-master-password' });
      var sourceUsername = UI.textInput({ autocomplete: 'off', placeholder: '可选：源 Windows 用户名', testid: 'unlock-source-username' });
      var sourceSid = UI.textInput({ autocomplete: 'off', placeholder: '可选：源 Windows SID', testid: 'unlock-source-sid' });
      function clearSecret() { masterPassword.value = ''; }
      var formApi = UI.openFormModal({
        title: '解锁 Xshell 密码 · ' + server.name,
        subtitle: '使用已保存在系统钥匙串中的加密凭据恢复登录密码。解锁后可自行测试连接。',
        narrow: true, submitLabel: '解锁密码', busyLabel: '正在解锁…',
        body: [
          UI.field('Xshell 主密码', masterPassword, { help: '这是 Xshell 安全设置中的总密码，不是服务器登录密码；未设置过可留空。仅用于本次解锁，提交后清空。' }),
          UI.field('源 Windows 用户名', sourceUsername), UI.field('源 Windows SID', sourceSid),
          UI.el('p', { 'class': 'field-help', text: '没有主密码：在原 Windows 的 PowerShell 分别执行 $env:USERNAME 和 whoami /user，把第一条输出的用户名（保留大小写）和第二条的 SID 填入。解锁本身不连接服务器，成功后可点击「测试」。' })
        ],
        validate: function () {
          if (!masterPassword.value && !sourceUsername.value.trim() && !sourceSid.value.trim()) {
            clearSecret(); return { message: '请提供 Xshell 主密码或源 Windows 用户名 / SID' };
          }
          return null;
        },
        onClose: function () { clearSecret(); sourceUsername.value = ''; sourceSid.value = ''; },
        onSubmit: function (api) {
          var credentials = {};
          if (masterPassword.value) credentials.master_password = masterPassword.value;
          if (sourceUsername.value.trim()) credentials.source_username = sourceUsername.value.trim();
          if (sourceSid.value.trim()) credentials.source_sid = sourceSid.value.trim();
          clearSecret();
          return net.post(resourcePath(server.name, 'unlock'), { credentials: credentials }).then(function (data) {
            if (!data || data.ok !== true) throw { message: 'Xshell 密码解锁失败，请核对主密码或源 Windows 用户名 / SID 后重试。' };
            api.close(); UI.successToast('已解锁，可点击测试连接'); return load(false);
          }).then(function () {
            clearSecret(); Object.keys(credentials).forEach(function (key) { delete credentials[key]; });
          }, function (err) {
            clearSecret(); Object.keys(credentials).forEach(function (key) { delete credentials[key]; }); throw err;
          });
        }
      });
      app().registerCleanup(function () { formApi.close(); });
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
    var head = UI.pageHeader({ title: '审计', sub: '两个工具的操作记录，按时间倒序。翻页保留同一快照，刷新获取新记录。' });
    pageRoot.appendChild(head.el);
    var decisionSelect = UI.selectInput({ testid: 'audit-decision', value: '', options: [
      { value: '', label: '全部决策' }
    ].concat(['allow', 'deny', 'ask', 'approve', 'reject', 'consume', 'error'].map(function (value) { return { value: value, label: value }; })) });
    var toolSelect = UI.selectInput({ testid: 'audit-tool', value: state().tool, options: [
      { value: 'all', label: '全部工具' }, { value: 'ssh', label: 'SSH' }, { value: 'db', label: '数据库' }
    ] });
    var sizeSelect = UI.selectInput({ testid: 'audit-page-size', value: '50', options: [25, 50, 100, 200].map(function (n) { return { value: String(n), label: n + ' 条 / 页' }; }) });
    var actor = UI.textInput({ placeholder: '操作者', testid: 'audit-actor' });
    var alias = UI.textInput({ placeholder: '连接别名', testid: 'audit-alias' });
    var refreshBtn = UI.button({ label: '刷新', variant: 'ghost', small: true, testid: 'btn-refresh', onClick: reset });
    var applyBtn = UI.button({ label: '筛选', type: 'submit', testid: 'audit-apply' });
    var filters = UI.el('form', { 'class': 'filter-bar audit-filters' }, [
      UI.field('工具', toolSelect), UI.field('决策', decisionSelect), UI.field('操作者', actor), UI.field('别名', alias), applyBtn, refreshBtn
    ]);
    filters.addEventListener('submit', function (e) { e.preventDefault(); reset(); });
    pageRoot.appendChild(filters);
    var error = UI.formError(); pageRoot.appendChild(error.el);
    var notice = UI.el('p', { 'class': 'field-help', 'aria-live': 'polite' }); pageRoot.appendChild(notice);
    var body = UI.el('div'); pageRoot.appendChild(body);
    var page = 1, snapshot = '', sequence = 0, loading = false;
    var applied = { tool: state().tool, decision: '', actor: '', alias: '', page_size: 50 };
    var metadata = { page: 1, pages: 0, total: 0, has_prev: false, has_next: false };
    var prev = UI.button({ label: '上一页', testid: 'audit-prev', onClick: function () { if (!loading && metadata.has_prev) { page--; load(false); } } });
    var next = UI.button({ label: '下一页', testid: 'audit-next', onClick: function () { if (!loading && metadata.has_next) { page++; load(false); } } });
    var jump = UI.textInput({ type: 'number', value: '1', min: '1', testid: 'audit-page' });
    jump.setAttribute('aria-label', '页码');
    var pageInfo = UI.el('span', { 'class': 'pagination-info', 'data-testid': 'audit-page-info', 'aria-live': 'polite' });
    var jumpButton = UI.button({ label: '跳转', small: true, type: 'submit', testid: 'audit-jump' });
    var pager = UI.el('form', { 'class': 'pagination' }, [prev, pageInfo, next, UI.el('div', { 'class': 'pagination-jump' }, [jump, jumpButton]), UI.field('每页', sizeSelect)]);
    pager.addEventListener('submit', function (e) {
      e.preventDefault(); if (loading) return;
      var value = Number(jump.value);
      if (!Number.isInteger(value) || value < 1 || value > Math.max(1, metadata.pages)) { error.show({ message: '请输入有效页码' }); return; }
      page = value; load(false);
    });
    pageRoot.appendChild(pager);
    function updatePager() {
      prev.disabled = loading || !metadata.has_prev;
      next.disabled = loading || !metadata.has_next;
      jump.disabled = loading; jumpButton.disabled = loading; refreshBtn.disabled = loading;
      jump.value = String(metadata.page || 1); jump.max = String(Math.max(1, metadata.pages));
      pageInfo.textContent = '第 ' + (metadata.pages ? metadata.page : 0) + ' / ' + metadata.pages + ' 页 · 共 ' + metadata.total + ' 条';
    }
    function reset() {
      applied = { tool: toolSelect.value, decision: decisionSelect.value, actor: actor.value.trim(), alias: alias.value.trim(), page_size: Number(sizeSelect.value) };
      page = 1; snapshot = ''; notice.textContent = ''; return load(true);
    }
    function load(initial, recovered) {
      var request = ++sequence;
      loading = true; updatePager(); error.hide();
      var query = { page: page, page_size: applied.page_size, tool: applied.tool, decision: applied.decision, actor: applied.actor, alias: applied.alias };
      if (snapshot) query.snapshot = snapshot;
      if (initial && !body.children.length) body.appendChild(UI.loadingBlock('正在加载审计…'));
      return net.get('/api/audit', query).then(function (data) {
        if (!app().isCurrent(ctx.epoch) || request !== sequence) return;
        metadata = data; page = data.page; snapshot = data.snapshot || '';
        head.setCount(data.total); render(listOf(data, 'entries').map(normalizeAudit));
      }).catch(function (err) {
        if (!app().isCurrent(ctx.epoch) || request !== sequence) return;
        if (!recovered && (err.status === 409 || err.status === 413) && snapshot) {
          snapshot = ''; page = 1; notice.textContent = '审计快照已失效，已返回第一页获取最新记录。';
          return load(true, true);
        }
        page = metadata.page || 1;
        if (body.querySelector('[data-testid="state-loading"]')) UI.clear(body);
        error.show(err);
      }).then(function () { if (request === sequence) { loading = false; updatePager(); } });
    }
    function render(entries) {
      UI.clear(body);

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

    [decisionSelect, toolSelect, sizeSelect].forEach(function (control) { control.addEventListener('change', reset); });
    app().registerSilentRefresher(function () { if (!loading) return load(false); });
    updatePager(); load(true);
  }

  function openImportConnections(onImported) {
    var MAX_FILES = 1024, MAX_BYTES = 16 * 1024 * 1024, COMMIT_SIZE = 10;
    var files = UI.el('input', { type: 'file', multiple: true, accept: '.xsh,.zip,.xts,.json,.config,.conf,config', 'class': 'input', 'data-testid': 'import-files' });
    var directory = UI.el('input', { type: 'file', multiple: true, webkitdirectory: true, 'class': 'input', 'data-testid': 'import-directory' });
    var format = UI.selectInput({ value: 'auto', testid: 'import-format', options: [
      { value: 'auto', label: '自动识别' }, { value: 'xshell', label: 'Xshell' }, { value: 'finalshell', label: 'FinalShell' }, { value: 'openssh', label: 'OpenSSH config' }
    ] });
    var masterPassword = UI.textInput({ type: 'password', autocomplete: 'new-password', testid: 'import-master-password', placeholder: '可选：本批 Xshell 的主密码' });
    var sourceUsername = UI.textInput({ autocomplete: 'off', testid: 'import-source-username', placeholder: '可选：导出电脑上的 Windows 用户名' });
    var sourceSid = UI.textInput({ autocomplete: 'off', testid: 'import-source-sid', placeholder: '可选：导出电脑上的 Windows SID' });
    var unlock = UI.el('details', { 'class': 'import-bulk' }, [
      UI.el('summary', { text: '恢复 Xshell 保存的密码（可选）' }),
      UI.el('div', { 'class': 'form mt-16' }, [
      UI.field('Xshell 主密码', masterPassword, { help: '这是 Xshell 安全设置中的总密码，不是各台服务器的登录密码；没有设置过可留空。同一批只填一次，提交后清空。' }),
        UI.field('源 Windows 用户名', sourceUsername), UI.field('源 Windows SID', sourceSid),
      UI.el('p', { 'class': 'field-help', text: '没有主密码：在原 Windows 的 PowerShell 分别执行 $env:USERNAME 和 whoami /user，将第一条输出的用户名（保留大小写）及第二条的 SID 填入。无法恢复时会保留密文，可先添加待验证，稍后解锁。' })
      ])
    ]);
    var error = UI.formError();
    var source = UI.el('div', { 'class': 'form' }, [
      UI.field('格式', format),
      UI.field('连接文件（可多选）', files, { help: '支持 .xsh、ZIP / .xts、FinalShell JSON 与 OpenSSH config；文件和目录合计最多 1024 个文件、16 MiB，最多预览 1024 条连接。' }),
      UI.field('或选择连接目录', directory, { help: '可选择 Xshell 会话目录及其子目录；与上方文件一同预览。' }), unlock
    ]);
    var previewArea = UI.el('div');
    var status = UI.el('p', { 'class': 'field-help import-progress', 'aria-live': 'polite', 'data-testid': 'import-status' });
    var deferred = UI.el('section', { 'class': 'import-deferred', hidden: true, 'data-testid': 'import-deferred' });
    var rows = [], preview = null, busy = false, selectAll, bulkPassword, bulkKey, bulkApply;
    var previewBtn = UI.button({ label: '预览连接', testid: 'import-preview', onClick: previewFiles });
    var commitBtn = UI.button({ label: '验证并导入所选', variant: 'primary', testid: 'import-commit', disabled: true, onClick: function () { return commit(false); } });
    var closeBtn = UI.button({ label: '关闭', variant: 'ghost', testid: 'import-close', onClick: function () { modal.close(); } });
    var deferredConfirm = UI.button({ label: '先添加待验证连接', testid: 'import-deferred-confirm', disabled: true, onClick: function () { return commit(true); } });
    var deferredCancel = UI.button({ label: '暂不添加', variant: 'ghost', testid: 'import-deferred-cancel', onClick: function () {
      if (busy) return;
      hideDeferred(); status.textContent = '已取消添加待验证连接。失败条目仍保留，可补充信息后重试。';
    } });
    var modal = UI.openModal({
      title: '导入连接', subtitle: '恢复可用的登录凭据并验证连接；暂时无法验证时，可自行选择先添加为待验证。已有别名不会被覆盖。',
      body: [error.el, source, status, deferred, previewArea], footer: [closeBtn, previewBtn, commitBtn],
      onClose: function () { clearSecrets(); files.value = ''; directory.value = ''; sourceUsername.value = ''; sourceSid.value = ''; preview = null; rows = []; }
    });
    app().registerCleanup(function () { modal.close(); });
    function clearSecrets(targets) {
      (targets || rows).forEach(function (row) { row.password.value = ''; row.key.value = ''; });
      masterPassword.value = '';
      if (bulkPassword) bulkPassword.value = '';
      if (bulkKey) bulkKey.value = '';
    }
    function updateDeferredButton() {
      deferredConfirm.disabled = busy || !rows.some(function (row) { return !row.done && row.deferredChoice && row.deferredChoice.checked; });
    }
    function hideDeferred() {
      deferred.hidden = true;
      rows.forEach(function (row) { if (row.deferredChoice) row.deferredChoice.checked = false; });
      updateDeferredButton();
    }
    function setBusy(flag) {
      busy = flag; previewBtn.disabled = flag; closeBtn.disabled = flag; deferredCancel.disabled = flag;
      [files, directory, format, masterPassword, sourceUsername, sourceSid].forEach(function (field) { field.disabled = flag; });
      commitBtn.disabled = flag || !preview || !rows.some(function (row) { return !row.done; });
      if (selectAll) selectAll.disabled = flag;
      if (bulkApply) bulkApply.disabled = flag;
      [bulkPassword, bulkKey].forEach(function (field) { if (field) field.disabled = flag; });
      rows.forEach(function (row) {
        [row.selected, row.name, row.user, row.password, row.key, row.deferredChoice].forEach(function (field) { if (field) field.disabled = flag || row.done; });
      });
      updateDeferredButton();
    }
    function readFile(file) {
      return new Promise(function (resolve, reject) {
        var reader = new FileReader();
        reader.onload = function () { resolve({ name: file.webkitRelativePath || file.name, content: String(reader.result).split(',')[1] || '' }); };
        reader.onerror = function () { reject({ message: '无法读取文件：' + file.name }); };
        reader.readAsDataURL(file);
      });
    }
    function previewFiles() {
      if (busy) return;
      error.hide();
      var selectedFiles = Array.prototype.slice.call(files.files || []).concat(Array.prototype.slice.call(directory.files || []));
      if (!selectedFiles.length) { showFormError(error, { message: '请先选择连接文件或目录' }); return; }
      if (selectedFiles.length > MAX_FILES) { showFormError(error, { message: '一次最多选择 1024 个文件，请减少文件或分批导入' }); return; }
      if (selectedFiles.reduce(function (sum, file) { return sum + file.size; }, 0) > MAX_BYTES) {
        showFormError(error, { message: '文件总大小超过 16 MiB，请减少文件或分批导入' }); return;
      }
      var credentials = {};
      if (masterPassword.value) credentials.master_password = masterPassword.value;
      if (sourceUsername.value.trim()) credentials.source_username = sourceUsername.value.trim();
      if (sourceSid.value.trim()) credentials.source_sid = sourceSid.value.trim();
      clearSecrets(); hideDeferred(); preview = null; rows = []; UI.clear(previewArea); setBusy(true); status.textContent = '正在读取并预览连接…';
      return Promise.all(selectedFiles.map(readFile)).then(function (payload) {
        if (modal.isClosed()) return null;
        var request = { format: format.value, files: payload };
        if (Object.keys(credentials).length) request.credentials = credentials;
        return net.post('/api/imports/preview', request);
      }).then(function (data) {
        if (!data || modal.isClosed()) return;
        if (listOf(data, 'items').length > MAX_FILES) throw { message: '预览连接超过 1024 条，请减少文件或分批导入' };
        preview = data; renderPreview(data);
      }).catch(function (err) {
        if (!modal.isClosed()) { clearSecrets(); showFormError(error, err); status.textContent = '预览失败，文件未导入。保留原始文件选择，可补充解锁信息或更换格式后重试。'; }
      }).then(function () {
        Object.keys(credentials).forEach(function (key) { delete credentials[key]; });
        if (!modal.isClosed()) setBusy(false);
      });
    }
    function credentialText(item) {
      if (item.has_imported_password === true) return '已恢复登录密码 · 服务端暂存，留空即可复用，不回显。';
      var labels = {
        needs_context: '需要 Xshell 主密码或源 Windows 用户名 / SID。请保留原始文件，补充信息后重新预览。',
        invalid: '密码恢复校验失败。请核对解锁信息并保留原始文件，可重新预览或手动补充。',
        unsupported: '此版本的保存密码暂不支持恢复。请保留原始文件，可手动补充登录凭据。',
        missing: '文件中没有可恢复的登录密码，可补充登录密码或私钥。'
      };
      return labels[item.credential_status] || '可补充登录密码或私钥；暂缺凭据时，可在验证失败后确认添加待验证连接。';
    }
    function renderPreview(data) {
      UI.clear(previewArea); rows = [];
      var items = listOf(data, 'items');
      var expiresAt = typeof data.expires_at === 'number' ? new Date(data.expires_at < 1e12 ? data.expires_at * 1000 : data.expires_at).toISOString() : data.expires_at;
      status.textContent = '发现 ' + items.length + ' 条连接。预览凭据仅在服务端暂存 10 分钟，有效期至 ' + UI.fmtDateTime(expiresAt) + '。已恢复的密码无需重填。';
      (data.warnings || []).forEach(function (warning) { previewArea.appendChild(UI.el('div', { 'class': 'warn-banner', text: warning })); });
      if (!items.length) { previewArea.appendChild(emptyPage('没有可导入的连接', '请检查格式，或导出为单独 .xsh、ZIP / .xts、FinalShell JSON 或 OpenSSH config。')); return; }
      bulkPassword = UI.textInput({ type: 'password', autocomplete: 'new-password', testid: 'import-bulk-password', placeholder: '可选：替换所选条目的 SSH 登录密码' });
      bulkKey = UI.textareaInput({ rows: 3, testid: 'import-bulk-key', placeholder: '或粘贴用于所选条目的私钥内容' });
      bulkApply = UI.button({ label: '应用到所选条目', small: true, testid: 'import-bulk-apply', onClick: function () {
        if (busy) return;
        if (bulkPassword.value && bulkKey.value.trim()) { showFormError(error, { message: '批量登录密码与私钥只能填写一种' }); return; }
        var targets = rows.filter(function (row) { return row.selected.checked && !row.done; });
        if (!targets.length) { showFormError(error, { message: '请先勾选连接' }); return; }
        if (!bulkPassword.value && !bulkKey.value.trim()) { showFormError(error, { message: '请填写批量登录密码或私钥' }); return; }
        targets.forEach(function (row) { row.password.value = bulkPassword.value; row.key.value = bulkKey.value.trim(); });
        bulkPassword.value = ''; bulkKey.value = ''; error.hide();
        status.textContent = '已为 ' + targets.length + ' 条所选连接补充凭据，请检查后导入。';
      } });
      previewArea.appendChild(UI.el('details', { 'class': 'import-bulk' }, [UI.el('summary', { text: '批量补充同一份登录凭据（可选）' }), UI.el('div', { 'class': 'form mt-16' }, [UI.field('SSH 登录密码', bulkPassword), UI.field('私钥内容', bulkKey), bulkApply])]));
      var all = UI.checkboxInput('选择全部未导入连接', { checked: true, testid: 'import-select-all' });
      selectAll = all.input;
      selectAll.addEventListener('change', function () { if (!busy) rows.forEach(function (row) { if (!row.done) row.selected.checked = selectAll.checked; }); });
      previewArea.appendChild(all.wrap);
      items.forEach(function (item, index) {
        var selected = UI.checkboxInput('导入此连接', { checked: true, testid: 'import-select-' + index });
        var name = UI.textInput({ value: item.name, testid: 'import-name-' + index });
        var user = UI.textInput({ value: item.user || '', placeholder: '请明确填写 SSH 登录用户', testid: 'import-user-' + index });
        var password = UI.textInput({ type: 'password', autocomplete: 'new-password', placeholder: item.has_imported_password ? '留空使用已恢复密码；填写可替换' : '可选：填写登录密码，或使用下方私钥', testid: 'import-password-' + index });
        var key = UI.textareaInput({ rows: 3, placeholder: '可选：粘贴私钥内容；不会读取导出文件中的密钥路径', testid: 'import-key-' + index });
        var credential = UI.el('p', { 'class': 'field-help', text: credentialText(item), 'data-testid': 'import-credential-' + index });
        var outcome = UI.el('div', { 'class': 'import-outcome', 'aria-live': 'polite', 'data-testid': 'import-result-' + index });
        var row = { id: item.id, index: index, name: name, user: user, selected: selected.input, password: password, key: key, credential: credential, outcome: outcome, done: false, canAddUnverified: false };
        rows.push(row);
        var section = UI.el('section', { 'class': 'import-item' }, [
          UI.el('div', { 'class': 'import-item-head' }, [UI.el('h3', { 'class': 'section-title', text: (item.user || '未指定用户') + '@' + item.host + ':' + item.port }), selected.wrap]),
          UI.el('p', { 'class': 'field-help', text: '来源 ' + item.source + ' · 认证 ' + item.auth_type + (item.key_hint ? ' · 密钥提示 ' + item.key_hint : '') }), credential,
          UI.field('导入别名', name), UI.field('SSH 登录用户', user, { required: true, help: '请核对目标身份；导出文件未提供用户时必须补充，不会默认使用 root。' }), UI.field('SSH 登录密码（可选）', password), UI.field('私钥内容（可选）', key), outcome
        ]);
        (item.warnings || []).forEach(function (warning) { section.appendChild(UI.el('p', { 'class': 'field-help', text: warning })); });
        previewArea.appendChild(section);
      });
    }
    function showDeferred() {
      UI.clear(deferred);
      var eligible = rows.filter(function (row) { return !row.done && row.canAddUnverified; });
      if (!eligible.length) { hideDeferred(); return; }
      deferred.appendChild(UI.el('h3', { 'class': 'section-title', text: '选择要先添加的待验证连接' }));
      deferred.appendChild(UI.el('p', { 'class': 'field-help', text: '以下连接未能完成验证。勾选后只保存连接信息与可用凭据，不连接服务器、不标记为可用。之后可在服务器列表中「测试」；缺少凭据时可先「编辑」补充。' }));
      eligible.forEach(function (row) {
        var choice = UI.checkboxInput(row.name.value.trim() + ' · ' + row.user.value.trim() + ' · 待验证', { checked: false, testid: 'import-deferred-select-' + row.index });
        row.deferredChoice = choice.input;
        choice.input.addEventListener('change', updateDeferredButton);
        deferred.appendChild(choice.wrap);
      });
      deferred.appendChild(UI.el('div', { 'class': 'import-deferred-actions' }, [deferredCancel, deferredConfirm]));
      deferred.hidden = false;
      updateDeferredButton();
    }
    function rowItem(row, allowUnverified) {
      var item = { id: row.id, name: row.name.value.trim(), user: row.user.value.trim() };
      if (row.key.value.trim()) item.private_key = row.key.value.trim();
      else if (row.password.value) item.login_password = row.password.value;
      if (allowUnverified) item.allow_unverified = true;
      return item;
    }
    function commit(allowUnverified) {
      if (busy || !preview) return;
      error.hide();
      var selected = rows.filter(function (row) {
        return !row.done && (allowUnverified ? row.canAddUnverified && row.deferredChoice && row.deferredChoice.checked : row.selected.checked);
      });
      if (!selected.length) { showFormError(error, { message: allowUnverified ? '请勾选要添加的待验证连接' : '请至少选择一条尚未导入的连接' }); return; }
      var names = Object.create(null), validation = '';
      selected.forEach(function (row) {
        var name = row.name.value.trim(), user = row.user.value.trim();
        if (!/^[A-Za-z_][A-Za-z0-9_.@\\-]{0,127}$/.test(user)) validation = '请为连接 ' + name + ' 填写合法的 SSH 登录用户';
        if (!/^[A-Za-z0-9_.-]+$/.test(name) || name.indexOf('..') >= 0) validation = '别名只能包含字母、数字、点、下划线、连字符，且不能含 ..';
        if (names[name]) validation = '所选条目的别名重复：' + name;
        names[name] = true;
        if (row.password.value && row.key.value.trim()) validation = '连接 ' + name + ' 的登录密码和私钥只需填写一种';
      });
      if (validation) { showFormError(error, { message: validation }); return; }
      if (!allowUnverified) selected.forEach(function (row) { row.canAddUnverified = false; });
      hideDeferred(); setBusy(true);
      var processed = 0, verified = 0, pending = 0, failed = 0;
      function nextChunk() {
        if (modal.isClosed() || processed >= selected.length) return Promise.resolve();
        var chunk = selected.slice(processed, processed + COMMIT_SIZE);
        var items = chunk.map(function (row) { return rowItem(row, allowUnverified); });
        status.textContent = (allowUnverified ? '正在添加待验证连接 ' : '正在验证并导入 ') + processed + ' / ' + selected.length + '（每批最多 10 条）…';
        return net.post('/api/imports/commit', { preview_id: preview.preview_id, items: items }).then(function (data) {
          var results = listOf(data, 'results');
          chunk.forEach(function (row, index) {
            var result = results.filter(function (entry) { return entry.id === row.id; })[0];
            if (!allowUnverified) row.canAddUnverified = !!(result && result.ok !== true && result.can_add_unverified === true);
            if (result && result.ok === true) {
              row.done = true; row.selected.checked = false; row.canAddUnverified = false;
              if (result.pending === true || result.verified === false) {
                pending++; row.outcome.textContent = '已添加待验证：' + (result.name || row.name.value) + '。尚未连接成功，请稍后测试。'; row.outcome.className = 'import-outcome import-pending';
              } else {
                verified++; row.outcome.textContent = '已导入并验证：' + (result.name || row.name.value); row.outcome.className = 'import-outcome flag-yes';
              }
            } else {
              failed++;
              row.outcome.textContent = '导入失败：' + (result && result.error || '未收到该条目的结果，请检查连接列表后重试');
              row.outcome.className = 'import-outcome flag-no';
            }
            if (items[index].login_password || items[index].private_key) row.credential.textContent = '凭据已提交服务端暂存；已保留不回显，预览有效期内可直接重试。';
          });
          processed += chunk.length;
        }).then(function () {
          clearSecrets(chunk); items.forEach(function (item) { delete item.login_password; delete item.private_key; });
          return nextChunk();
        }, function (err) {
          chunk.forEach(function (row) {
            row.outcome.textContent = '请求未完成：' + (err.message || '请检查连接列表后重试');
            row.outcome.className = 'import-outcome flag-no';
          });
          clearSecrets(chunk); items.forEach(function (item) { delete item.login_password; delete item.private_key; });
          throw err;
        });
      }
      return nextChunk().then(function () {
        if (!modal.isClosed()) status.textContent = '已处理 ' + processed + ' / ' + selected.length + '：验证成功 ' + verified + ' 条，待验证 ' + pending + ' 条，失败 ' + failed + ' 条。失败条目的别名和选择已保留，可直接重试或补充凭据。';
      }).catch(function (err) {
        if (!modal.isClosed()) { showFormError(error, err); status.textContent = '导入请求中断，已处理 ' + processed + ' / ' + selected.length + '。未完成条目仍保留，请检查列表后重试。'; }
      }).then(function () {
        clearSecrets();
        if (!modal.isClosed()) { setBusy(false); showDeferred(); }
        if ((verified || pending) && onImported) return onImported();
      });
    }
  }

  function aiPage(view, ctx) {
    var head = UI.pageHeader({ title: 'AI 审批', sub: '仅对指定别名处理审批，现有权限与硬性拒绝始终生效。关闭此页面后，后台审批服务会继续运行。' });
    head.setCount(null); view.appendChild(head.el);
    var root = UI.el('div'); view.appendChild(root);
    var config = null, alive = true, busy = false;
    var controls = [], apiKey, clearKey, mode, baseUrl, model, ttl, scope, serviceStatus, serviceText;
    var error = UI.formError(), message = UI.el('p', { 'class': 'field-help', 'aria-live': 'polite', 'data-testid': 'ai-message' });
    app().registerCleanup(function () { alive = false; if (apiKey) apiKey.value = ''; });
    function current() { return alive && app().isCurrent(ctx.epoch); }
    function requestStatus() {
      return net.get('/api/ai/service/status').then(function (status) {
        if (!current()) return;
        serviceStatus = status;
        serviceText.textContent = status.running === true ? '后台服务运行中' + (status.pid ? ' · PID ' + status.pid : '') : '后台服务已停止';
      }, function (err) {
        serviceStatus = null;
        if (current() && serviceText) serviceText.textContent = '服务状态查询失败：' + err.message;
        throw err;
      });
    }
    function run(label, action) {
      if (busy || !current()) return Promise.resolve();
      busy = true; error.hide(); message.textContent = label + '…';
      controls.forEach(function (button) { button.disabled = true; });
      return Promise.resolve().then(action).catch(function (err) {
        if (current()) { showFormError(error, err); message.textContent = ''; }
      }).then(function () {
        if (apiKey) apiKey.value = '';
        if (clearKey) clearKey.input.checked = false;
        busy = false;
        if (current()) controls.forEach(function (button) { button.disabled = false; });
      });
    }
    function addButton(label, testid, fn, variant) {
      var button = UI.button({ label: label, testid: testid, variant: variant, onClick: fn }); controls.push(button); return button;
    }
    function readAliases() {
      return net.get('/api/' + state().resource).then(function (data) {
        if (!current()) return;
        var aliases = listOf(data, state().resource).map(function (item) { return item.name || item.alias; }).filter(Boolean);
        scope.update(aliases.map(function (name) { return { name: name }; }));
        return aliases.length ? '选择允许 AI 审批的连接；未选连接继续人工审批。' : '当前工具还没有连接。请先添加连接，再刷新别名。';
      });
    }
    // Read the latest config before every write so another console's scopes survive.
    function save(forcedMode) {
      var desired = {
        mode: forcedMode || mode.value, base_url: baseUrl.value.trim(), model: model.value.trim(), ttl_s: Number(ttl.value),
        scopes: scope.values(), api_key: apiKey.value, clear_api_key: clearKey.input.checked
      };
      if (!Number.isInteger(desired.ttl_s) || desired.ttl_s < 60 || desired.ttl_s > 300) return Promise.reject({ message: 'AI 审批有效期需为 60–300 秒的整数' });
      if (desired.api_key && desired.clear_api_key) return Promise.reject({ message: '不能同时设置和清除 API Key' });
      return net.get('/api/ai/config').then(function (latest) {
        var scopes = { ssh: (latest.scopes && latest.scopes.ssh || []).slice(), db: (latest.scopes && latest.scopes.db || []).slice() };
        scopes[state().tool] = desired.scopes;
        var body = { mode: desired.mode, base_url: desired.base_url, model: desired.model, ttl_s: desired.ttl_s, scopes: scopes };
        if (desired.api_key) body.api_key = desired.api_key;
        if (desired.clear_api_key) body.clear_api_key = true;
        desired.api_key = '';
        return net.put('/api/ai/config', body).then(function (result) {
          delete body.api_key; return result;
        }, function (err) { delete body.api_key; throw err; });
      }).then(function () {
        return net.get('/api/ai/config');
      }).then(function (saved) {
        config = saved;
        if (current()) {
          mode.value = saved.mode;
          keyStatus.textContent = saved.has_api_key ? 'API Key 已保存，内容不会回显。' : '尚未保存 API Key。';
        }
        if (desired.mode === 'off') {
          return net.post('/api/ai/service/stop', {}).then(requestStatus).then(function () {
            if (serviceStatus && serviceStatus.running) throw { message: '配置已关闭，但后台服务仍在运行，请重试停止服务' };
          });
        }
      }).then(function () { if (current()) message.textContent = desired.mode === 'off' ? '已保存关闭模式，后台服务已停止。' : '配置已保存。需要持续处理时，请启动后台服务。'; });
    }
    var keyStatus;
    function draw(data) {
      config = data;
      UI.clear(root);
      mode = UI.selectInput({ value: config.mode || 'off', testid: 'ai-mode', options: [
        { value: 'off', label: '关闭' }, { value: 'suggest', label: '建议 — 仍由人工决定' }, { value: 'auto', label: '自动审批 — 仅指定别名' }
      ] });
      baseUrl = UI.textInput({ value: config.base_url || '', placeholder: 'https://api.example.com/v1', testid: 'ai-base-url' });
      model = UI.textInput({ value: config.model || '', placeholder: '输入模型名称，或从获取结果中选择', testid: 'ai-model' });
      ttl = UI.textInput({ type: 'number', value: config.ttl_s || 120, min: '60', max: '300', testid: 'ai-ttl' });
      apiKey = UI.textInput({ type: 'password', autocomplete: 'new-password', placeholder: '留空保留已存密钥', testid: 'ai-api-key' });
      clearKey = UI.checkboxInput('清除已保存的 API Key', { testid: 'ai-clear-api-key' });
      keyStatus = UI.el('div', { 'class': 'field-help', text: config.has_api_key ? 'API Key 已保存，内容不会回显。' : '尚未保存 API Key。' });
      scope = searchableChoices((config.scopes && config.scopes[state().tool]) || [], 'ai-scopes');
      var scopeHelp = UI.el('p', { 'class': 'field-help', 'aria-live': 'polite', text: '正在加载连接别名…' });
      var modelChoices = UI.selectInput({ testid: 'ai-model-options', value: '', options: [{ value: '', label: '先获取模型列表（也可直接输入）' }] });
      modelChoices.disabled = true;
      modelChoices.setAttribute('aria-label', '可选模型列表');
      modelChoices.addEventListener('change', function () { if (modelChoices.value) model.value = modelChoices.value; });
      serviceText = UI.el('p', { 'class': 'service-state', 'data-testid': 'ai-service-state', 'aria-live': 'polite', text: '正在查询后台服务…' });
      var missing = config.sdk_available !== true || !config.vault || config.vault.available !== true;
      var dependencyNote = UI.el('div', { 'class': missing ? 'warn-banner' : 'field-help', text: missing
        ? 'AI 集成尚不可用：' + (config.sdk_available !== true ? '缺少模型 SDK。' : '') + (!config.vault || !config.vault.available ? '系统钥匙串不可用：' + (config.vault && config.vault.reason || '请安装或解锁系统钥匙串') + '。' : '') + ' 请运行 bash install.sh --with-integrations。'
        : '模型 SDK 与系统钥匙串可用。仅脱敏后的审批内容会发送至模型服务。' });
      var saveOff = addButton('保存连接（关闭模式）', 'ai-save-connection', function () { run('保存连接', function () { return save('off'); }); });
      var saveConfig = addButton('保存设置', 'ai-save', function () { run('保存设置', function () { return save(); }); }, 'primary');
      var test = addButton('测试已保存连接', 'ai-test', function () {
        run('测试连接', function () { return net.post('/api/ai/test', {}).then(function (result) {
          if (result.connected !== true) throw { message: result.error || result.message || '模型连接测试失败' };
          message.textContent = result.message || '模型连接测试成功。';
        }); });
      });
      var models = addButton('获取已保存连接的模型', 'ai-models', function () {
        run('获取模型', function () { return net.get('/api/ai/models').then(function (data) {
          if (!current()) return;
          if (data.error) throw { message: data.error, hint: data.message || '' };
          UI.clear(modelChoices);
          modelChoices.appendChild(UI.el('option', { value: '', text: '选择模型，或直接输入名称' }));
          var items = listOf(data, 'models');
          items.forEach(function (name) { modelChoices.appendChild(UI.el('option', { value: name, text: name })); });
          modelChoices.disabled = !items.length;
          message.textContent = items.length ? '已获取 ' + items.length + ' 个模型。选择后保存设置。' : '服务未返回模型列表，可直接输入支持的模型名称。';
        }); });
      });
      var start = addButton('启动后台服务', 'ai-start', function () {
        run('启动后台服务', function () { return net.get('/api/ai/config').then(function (latest) {
          if (latest.mode === 'off') throw { message: '请先保存建议或自动审批模式，再启动后台服务' };
          if (!latest.sdk_available || !latest.vault || !latest.vault.available) throw { message: 'AI 集成不可用，请运行 bash install.sh --with-integrations 并确认系统钥匙串已解锁' };
          if (!latest.has_api_key || !latest.model) throw { message: '请先保存 API Key 与模型名称' };
          return net.post('/api/ai/service/start', {});
        }).then(requestStatus).then(function () {
          if (!serviceStatus || serviceStatus.running !== true) throw { message: '后台服务尚未启动，请检查依赖和已保存配置' };
          message.textContent = '后台服务已启动，关闭页面后仍会继续处理。';
        }); });
      });
      var stop = addButton('停止后台服务', 'ai-stop', function () {
        run('停止后台服务', function () { return net.post('/api/ai/service/stop', {}).then(requestStatus).then(function () {
          if (!serviceStatus || serviceStatus.running !== false) throw { message: '未能确认后台服务已停止，请重试' };
          message.textContent = '后台服务已停止。保存的审批模式未改变。';
        }); });
      });
      var disable = addButton('关闭自动审批并停止服务', 'ai-disable', function () {
        run('关闭自动审批', function () {
          return net.get('/api/ai/config').then(function (latest) {
            return net.put('/api/ai/config', { mode: 'off', base_url: latest.base_url, model: latest.model, ttl_s: latest.ttl_s, scopes: { ssh: latest.scopes && latest.scopes.ssh || [], db: latest.scopes && latest.scopes.db || [] } });
          }).then(function () {
            if (current()) mode.value = 'off';
            return net.post('/api/ai/service/stop', {});
          }).then(requestStatus).then(function () {
            if (!serviceStatus || serviceStatus.running !== false) throw { message: '配置已关闭，但尚未确认服务停止，请重试停止服务' };
            if (current()) message.textContent = 'AI 审批已关闭，后台服务已停止。';
          });
        });
      });
      var refreshStatus = addButton('刷新服务状态', 'ai-refresh-status', function () { run('查询服务状态', function () { return requestStatus().then(function () { message.textContent = '服务状态已更新。'; }); }); });
      var refreshAliases = addButton('刷新别名', 'ai-refresh-aliases', function () { run('加载连接别名', function () { return readAliases().then(function (hint) { scopeHelp.textContent = hint; message.textContent = '连接别名已更新。'; }); }); });
      var connection = UI.el('section', { 'class': 'settings-section' }, [
        UI.el('h2', { 'class': 'section-title', text: '模型连接' }), dependencyNote,
        UI.field('API 地址', baseUrl), UI.field('API Key', apiKey, { help: '密钥仅写入系统钥匙串；保存、出错或离开页面后会清空输入框。' }), keyStatus, clearKey.wrap,
        UI.field('模型', model), modelChoices,
        UI.el('p', { 'class': 'field-help', text: '首次配置先保存连接（关闭模式），再测试或获取模型。服务不支持列出模型时，可直接输入名称。' }),
        UI.el('div', { 'class': 'settings-actions' }, [saveOff, test, models])
      ]);
      var policy = UI.el('section', { 'class': 'settings-section' }, [
        UI.el('h2', { 'class': 'section-title', text: '审批范围' }), UI.field('审批模式', mode),
        UI.field('当前工具：' + (state().tool === 'ssh' ? 'SSH 服务器' : '数据库'), scope.el), scopeHelp, refreshAliases,
        UI.field('AI 决策有效期（秒）', ttl, { help: '范围 60–300 秒，决定仅使用一次。' }),
        UI.el('p', { 'class': 'field-help', text: '模型异常、超时或无法确定时回退人工审批；AI 决定仅使用一次。另一个工具的审批范围会保留。' }),
        UI.el('div', { 'class': 'settings-actions' }, [saveConfig, disable])
      ]);
      root.appendChild(error.el); root.appendChild(message);
      root.appendChild(UI.el('div', { 'class': 'settings-grid' }, [connection, policy]));
      root.appendChild(UI.el('section', { 'class': 'settings-section mt-16' }, [UI.el('h2', { 'class': 'section-title', text: '后台审批服务' }), serviceText, UI.el('div', { 'class': 'settings-actions' }, [start, stop, refreshStatus])]));
      readAliases().then(function (hint) { if (current()) scopeHelp.textContent = hint; }).catch(function (err) { if (current()) scopeHelp.textContent = '加载连接别名失败：' + err.message + '。已保存选择保留，请刷新重试。'; });
      requestStatus().catch(function () {});
    }
    function load() {
      UI.clear(root); root.appendChild(UI.loadingBlock('正在加载 AI 设置…'));
      return net.get('/api/ai/config').then(function (data) { if (current()) draw(data); }, function (err) {
        if (current()) { UI.clear(root); root.appendChild(UI.errorBlock(err, load)); }
      });
    }
    load();
  }

  BC.pages = {
    setup: setupPage,
    login: loginPage,
    servers: serversPage,
    databases: databasesPage,
    approvals: approvalsPage,
    audit: auditPage,
    ai: aiPage
  };
})();
