/*
 * bindconsole — 应用引导：工具注入 / 状态 / 哈希路由 / 轮询 / 会话
 * 工具类型只从 window.__BINDCONSOLE_TOOL__ 读取（由内核替换 index.html 中的占位）。
 */
(function () {
  'use strict';

  var BC = window.BC;
  var UI = BC.ui;
  var net = BC.net;

  var TOOL_INFO = {
    ssh: {
      key: 'ssh',
      product: 'sshbind',
      label: 'SSH 控制台',
      resource: 'servers',
      listRoute: '#/servers',
      listLabel: '服务器'
    },
    db: {
      key: 'db',
      product: 'dbbind',
      label: '数据库控制台',
      resource: 'databases',
      listRoute: '#/databases',
      listLabel: '数据库'
    }
  };

  var ROUTES = ['setup', 'login', 'servers', 'databases', 'approvals', 'audit'];

  var state = {
    tool: null,
    resource: null,
    setupRequired: true,
    setupRequiresToken: false,
    authed: false,
    booted: false,
    pendingCount: 0,
    policy: null,
    policyLoaded: false,
    route: ''
  };

  var routeEpoch = 0;
  var cleanupFns = [];
  var silentRefresher = null;
  var pollTimer = null;

  /* ---------- 工具识别 ---------- */

  function detectInjectedTool() {
    var injected = window.__BINDCONSOLE_TOOL__;
    if (injected === 'ssh' || injected === 'db') return injected;
    return null;
  }

  function setTool(tool) {
    state.tool = tool;
    state.resource = TOOL_INFO[tool].resource;
    document.documentElement.setAttribute('data-tool', tool);
    document.title = TOOL_INFO[tool].product + ' · bindconsole';
  }

  function toolInfo() { return state.tool ? TOOL_INFO[state.tool] : null; }

  function toolChip() {
    var info = toolInfo();
    var chip = UI.el('span', { 'class': 'tool-chip' }, [
      UI.el('span', { 'class': 'dot' }),
      UI.el('span', { text: info ? info.product : 'bindconsole' })
    ]);
    return chip;
  }

  /* ---------- 状态 ---------- */

  function normalizeStatus(data) {
    data = data || {};
    var setupRequired = data.setup_required;
    if (setupRequired === undefined) setupRequired = data.setupRequired;
    if (setupRequired === undefined) setupRequired = data.needs_setup;
    var authenticated = data.authenticated;
    if (authenticated === undefined) authenticated = data.logged_in;
    if (authenticated === undefined) authenticated = data.authed;
    var pending = data.pending_count;
    if (pending === undefined) pending = data.pending;
    if (pending === undefined) pending = data.pending_approvals;
    var tool = (data.tool === 'ssh' || data.tool === 'db') ? data.tool : null;
    return {
      setupRequired: !!setupRequired,
      setupRequiresToken: data.setup_requires_token === true,
      authenticated: !!authenticated,
      tool: tool,
      resource: typeof data.resource === 'string' ? data.resource : null,
      pendingCount: typeof pending === 'number' ? pending : null,
      csrfToken: data.csrf_token || '',
      lockedOut: !!data.locked_out,
      lockoutRemaining: data.lockout_remaining_s || 0
    };
  }

  function applyStatus(status) {
    state.setupRequired = status.setupRequired;
    state.setupRequiresToken = status.setupRequiresToken === true;
    state.authed = status.authenticated;
    if (typeof status.pendingCount === 'number') state.pendingCount = status.pendingCount;
    if (!state.tool && status.tool) setTool(status.tool);
    if (status.csrfToken) net.csrf = status.csrfToken;
  }

  function fetchStatus() {
    return net.get('/api/status').then(function (data) {
      var status = normalizeStatus(data);
      applyStatus(status);
      return status;
    }, function (err) {
      if (err && err.status === 401) {
        // 有些实现未登录时会给 401；此时至少可以判断"已设置过密码"。
        var fallback = { setupRequired: false, setupRequiresToken: false, authenticated: false, tool: null, pendingCount: null };
        applyStatus(fallback);
        return fallback;
      }
      throw err;
    });
  }

  function refreshStatus() {
    return fetchStatus().then(function (status) {
      updatePendingBadge();
      return status;
    });
  }

  function updatePendingBadge() {
    var badges = document.querySelectorAll('[data-testid="pending-badge"]');
    for (var i = 0; i < badges.length; i++) {
      var badge = badges[i];
      badge.textContent = String(state.pendingCount);
      badge.hidden = !state.pendingCount;
    }
  }

  /* ---------- policy（可选增强；字段缺失时列表项自带策略字段） ---------- */

  function normalizePolicy(data) {
    var result = { defaults: {}, entries: {} };
    if (!data || typeof data !== 'object') return result;
    var policy = (data.policy && typeof data.policy === 'object') ? data.policy : data;
    if (policy.defaults && typeof policy.defaults === 'object') result.defaults = policy.defaults;
    var candidates = [policy.servers, policy.databases, policy.items, policy.aliases, policy.entries, policy.overrides];
    for (var i = 0; i < candidates.length; i++) {
      var candidate = candidates[i];
      if (!candidate) continue;
      if (Array.isArray(candidate)) {
        var map = {};
        candidate.forEach(function (entry) {
          if (!entry || typeof entry !== 'object') return;
          var name = entry.name || entry.alias;
          if (name) map[name] = entry;
        });
        if (Object.keys(map).length) { result.entries = map; break; }
      } else if (typeof candidate === 'object') {
        result.entries = candidate;
        break;
      }
    }
    return result;
  }

  function ensurePolicy(force) {
    if (state.policyLoaded && !force) return Promise.resolve(state.policy);
    return net.get('/api/policy').then(function (data) {
      state.policy = normalizePolicy(data);
      state.policyLoaded = true;
      return state.policy;
    }, function () {
      state.policy = null;
      state.policyLoaded = true;
      return null;
    });
  }

  function policyDefaults() {
    return (state.policy && state.policy.defaults) || {};
  }

  function policyEntry(name) {
    if (!state.policy || !state.policy.entries) return {};
    var entry = state.policy.entries[name];
    return (entry && typeof entry === 'object') ? entry : {};
  }

  /* ---------- 路由 ---------- */

  function currentRoute() {
    var raw = String(location.hash || '');
    raw = raw.replace(/^#\/?/, '');
    raw = raw.split('?')[0];
    return raw;
  }

  function defaultRoute() {
    if (state.setupRequired) return '#/setup';
    if (!state.authed) return '#/login';
    return TOOL_INFO[state.tool].listRoute;
  }

  function isCurrent(epoch) { return epoch === routeEpoch; }

  function registerCleanup(fn) {
    if (typeof fn === 'function') cleanupFns.push(fn);
  }

  function registerSilentRefresher(fn) {
    silentRefresher = (typeof fn === 'function') ? fn : null;
  }

  function navigate(hash, opts) {
    opts = opts || {};
    if (opts.replace) location.replace(hash);
    else location.hash = hash;
  }

  function runCleanups() {
    var fns = cleanupFns;
    cleanupFns = [];
    for (var i = 0; i < fns.length; i++) {
      try { fns[i](); } catch (e) { /* ignore */ }
    }
  }

  function render() {
    if (!state.booted) return;
    var epoch = ++routeEpoch;
    runCleanups();
    silentRefresher = null;

    var route = currentRoute();
    var target = null;
    if (state.setupRequired) {
      if (route !== 'setup') target = '#/setup';
    } else if (!state.authed) {
      if (route !== 'login') target = '#/login';
    } else {
      if (route === '' || route === 'login' || route === 'setup') {
        target = defaultRoute();
      } else if (route === 'servers' && state.tool === 'db') {
        target = '#/databases';
      } else if (route === 'databases' && state.tool === 'ssh') {
        target = '#/servers';
      } else if (ROUTES.indexOf(route) === -1) {
        target = defaultRoute();
      }
    }
    if (target) { location.replace(target); return; }

    state.route = route;
    var appRoot = document.getElementById('app');
    UI.clear(appRoot);

    var view;
    if (route === 'setup' || route === 'login') {
      view = renderAuthLayout(appRoot);
    } else {
      view = renderShell(appRoot, route);
    }

    var page = BC.pages[route];
    if (typeof page !== 'function') {
      view.appendChild(UI.errorBlock({ message: '未知页面：' + route }));
      return;
    }

    var result;
    try {
      result = page(view, { epoch: epoch });
    } catch (err) {
      view.appendChild(UI.errorBlock(err));
      return;
    }
    if (result && typeof result.catch === 'function') {
      result.catch(function (err) {
        if (!isCurrent(epoch)) return;
        UI.clear(view);
        view.appendChild(UI.errorBlock(err, function () { render(); }));
      });
    }
  }

  function renderAuthLayout(root) {
    var viewEl = UI.el('div');
    var brand = UI.el('div', { 'class': 'auth-brand' }, [
      UI.el('span', { 'class': 'brand-mark', text: 'b' }),
      UI.el('span', { 'class': 'auth-brand-name', text: 'bindconsole' }),
      toolChip()
    ]);
    // 局域网模式（--host 0.0.0.0）下提示 HTTP 明文风险；回环访问保持原提示。
    var host = String(location.hostname || '');
    var loopback = (host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]');
    var lanMode = state.setupRequiresToken || !loopback;
    var foot = UI.el('div', { 'class': 'auth-foot' }, [
      UI.el('span', { text: lanMode ? '局域网模式：HTTP 明文传输，注意凭证暴露风险' : '仅限本机访问' }),
      UI.el('span', { 'class': 'mono', text: host || '127.0.0.1' })
    ]);
    var card = UI.el('div', { 'class': 'auth-card' }, [brand, viewEl, foot]);
    root.appendChild(UI.el('div', { 'class': 'auth-main' }, [card]));
    return viewEl;
  }

  function renderShell(root, route) {
    var info = toolInfo();
    var navItems = state.tool === 'ssh'
      ? [
          { route: 'servers', label: '服务器' },
          { route: 'approvals', label: '审批中心' },
          { route: 'audit', label: '审计' }
        ]
      : [
          { route: 'databases', label: '数据库' },
          { route: 'approvals', label: '审批中心' },
          { route: 'audit', label: '审计' }
        ];

    var nav = UI.el('nav', { 'class': 'nav', 'aria-label': '主导航' });
    navItems.forEach(function (item) {
      var link = UI.el('a', {
        'class': 'nav-link' + (route === item.route ? ' active' : ''),
        href: '#/' + item.route,
        'data-testid': 'nav-' + item.route,
        text: item.label
      });
      if (route === item.route) link.setAttribute('aria-current', 'page');
      if (item.route === 'approvals') {
        link.appendChild(UI.el('span', {
          'class': 'pending-badge',
          hidden: !state.pendingCount,
          'data-testid': 'pending-badge',
          text: String(state.pendingCount),
          title: '带审批的操作数'
        }));
      }
      nav.appendChild(link);
    });

    var brand = UI.el('a', { 'class': 'brand', href: info.listRoute }, [
      UI.el('span', { 'class': 'brand-mark', text: 'b' }),
      UI.el('span', { text: 'bindconsole' }),
      toolChip()
    ]);
    var logoutBtn = UI.button({ label: '退出', variant: 'ghost', small: true, testid: 'logout', onClick: logout });
    var right = UI.el('div', { 'class': 'topbar-right' }, [logoutBtn]);

    var topbar = UI.el('header', { 'class': 'topbar' }, [
      UI.el('div', { 'class': 'topbar-inner' }, [brand, nav, right])
    ]);
    var viewEl = UI.el('div', { id: 'view' });
    var main = UI.el('main', { 'class': 'main' }, [viewEl]);
    root.appendChild(topbar);
    root.appendChild(main);
    updatePendingBadge();
    return viewEl;
  }

  function handleUnauthorized() {
    if (!state.booted || !state.authed) return;
    state.authed = false;
    state.pendingCount = 0;
    net.csrf = '';
    UI.toast('会话已过期，请重新登录', { tone: 'warn' });
    navigate('#/login');
  }

  function logout() {
    net.post('/api/logout', {}).catch(function () { /* 忽略：本地状态照样清 */ }).then(function () {
      state.authed = false;
      state.pendingCount = 0;
      state.policy = null;
      state.policyLoaded = false;
      net.csrf = '';
      UI.toast('已退出登录', { tone: 'info' });
      navigate('#/login');
    });
  }

  /* ---------- 轮询 ---------- */

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(pollTick, 5000);
  }

  function pollTick() {
    if (!state.booted || state.setupRequired || !state.authed) return;
    if (document.visibilityState !== 'visible') return;
    refreshStatus().then(function () {
      if (!state.authed) { handleUnauthorized(); return; }
      if (typeof silentRefresher === 'function') {
        try {
          var result = silentRefresher();
          if (result && typeof result.catch === 'function') result.catch(function () { /* 静默 */ });
        } catch (e) { /* 静默 */ }
      }
    }, function (err) {
      if (err && err.status === 401) handleUnauthorized();
    });
  }

  /* ---------- 启动 ---------- */

  function bootSplash() {
    return UI.el('div', { 'class': 'boot' }, [
      UI.el('span', { 'class': 'spinner' }),
      UI.el('span', { text: '正在连接 bindconsole…' })
    ]);
  }

  function renderFatal(title, detail, retry) {
    var appRoot = document.getElementById('app');
    UI.clear(appRoot);
    var block = UI.el('div', { 'class': 'state-block', 'data-testid': 'state-fatal' }, [
      UI.el('div', { 'class': 'state-icon', text: '!' }),
      UI.el('div', { 'class': 'state-title', text: title }),
      UI.el('div', { 'class': 'state-hint', text: detail || '' })
    ]);
    if (retry) block.appendChild(UI.button({ label: '重试', variant: 'primary', onClick: retry }));
    appRoot.appendChild(UI.el('div', { 'class': 'main' }, [block]));
  }

  function boot() {
    var injected = detectInjectedTool();
    if (injected) setTool(injected);

    var appRoot = document.getElementById('app');
    UI.clear(appRoot);
    appRoot.appendChild(bootSplash());

    net.syncCsrf();

    return fetchStatus().then(function (status) {
      if (!state.tool && status.tool) setTool(status.tool);
      if (!state.tool) {
        renderFatal(
          '无法识别控制台类型',
          '工具占位符没有被内核注入。请通过 sshbind --startserver 或 dbbind --startserver 启动控制台后打开页面。'
        );
        return;
      }
      state.booted = true;
      net.setUnauthorizedHandler(handleUnauthorized);
      startPolling();
      if (ROUTES.indexOf(currentRoute()) === -1) {
        location.replace(defaultRoute());
      }
      render();
    }).catch(function (err) {
      renderFatal('无法连接管理服务', (err && err.message ? err.message : '请求失败') +
        (err && err.hint ? '：' + err.hint : ''), boot);
    });
  }

  BC.app = {
    state: state,
    TOOL_INFO: TOOL_INFO,
    boot: boot,
    render: render,
    reload: render,
    navigate: navigate,
    defaultRoute: defaultRoute,
    currentRoute: currentRoute,
    isCurrent: isCurrent,
    registerCleanup: registerCleanup,
    registerSilentRefresher: registerSilentRefresher,
    refreshStatus: refreshStatus,
    updatePendingBadge: updatePendingBadge,
    ensurePolicy: ensurePolicy,
    policyDefaults: policyDefaults,
    policyEntry: policyEntry,
    toolInfo: toolInfo,
    toolChip: toolChip,
    handleUnauthorized: handleUnauthorized,
    logout: logout
  };

  window.addEventListener('hashchange', render);
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') pollTick();
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
