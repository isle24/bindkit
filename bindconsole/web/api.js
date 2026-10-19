/*
 * bindconsole — API 客户端
 * 无构建、无依赖。统一处理：响应包络 {ok,data} / 错误体 {ok:false,error} /
 * CSRF 双提交（X-Bindconsole-CSRF）/ 401 回登录 / 403 CSRF 自动刷新重试一次。
 */
(function () {
  'use strict';

  var BC = (window.BC = window.BC || {});

  var CSRF_HEADER = 'X-Bindconsole-CSRF';
  var CSRF_COOKIE_NAMES = ['bindconsole_csrf', 'csrf_token', 'bindconsole_csrf_token', 'csrf'];

  function APIError(info) {
    var self = this;
    info = info || {};
    this.name = 'APIError';
    this.status = info.status || 0;
    this.code = info.code || '';
    this.hint = info.hint || '';
    this.retryAfter = info.retry_after_s || 0;
    this.message = info.message || defaultMessage(this.status);
    this.stack = (new Error(this.message)).stack;
    void self;
  }
  APIError.prototype = Object.create(Error.prototype);
  APIError.prototype.constructor = APIError;

  function defaultMessage(status) {
    if (status === 0) return '无法连接管理服务';
    if (status === 400) return '请求参数有误';
    if (status === 401) return '未登录或登录已过期';
    if (status === 403) return '请求被拒绝（CSRF 校验失败）';
    if (status === 404) return '资源不存在';
    if (status === 405) return '请求方法不允许';
    if (status === 409) return '当前状态不允许该操作';
    if (status === 429) return '操作过于频繁，请稍后重试';
    if (status >= 500) return '服务端内部错误';
    return '请求失败（HTTP ' + status + '）';
  }

  function readCookie(name) {
    var prefix = name + '=';
    var parts = document.cookie ? document.cookie.split(';') : [];
    for (var i = 0; i < parts.length; i++) {
      var s = parts[i].trim();
      if (s.indexOf(prefix) === 0) {
        var raw = s.slice(prefix.length);
        try { return decodeURIComponent(raw); } catch (e) { return raw; }
      }
    }
    return '';
  }

  function readCsrfCookie() {
    for (var i = 0; i < CSRF_COOKIE_NAMES.length; i++) {
      var v = readCookie(CSRF_COOKIE_NAMES[i]);
      if (v) return v;
    }
    return '';
  }

  var net = {
    csrf: '',
    onUnauthorized: null,   // function () {}
    onForbidden: null       // function () {}  （保留给调试）
  };

  function syncCsrf() {
    var fromCookie = readCsrfCookie();
    if (fromCookie) net.csrf = fromCookie;
    return net.csrf;
  }

  function captureCsrf(payload) {
    if (!payload || typeof payload !== 'object') return;
    var candidates = [payload.csrf_token, payload.csrf, payload.csrfToken];
    if (payload.data && typeof payload.data === 'object') {
      candidates.push(payload.data.csrf_token, payload.data.csrf, payload.data.csrfToken);
    }
    for (var i = 0; i < candidates.length; i++) {
      if (typeof candidates[i] === 'string' && candidates[i]) {
        net.csrf = candidates[i];
        return;
      }
    }
  }

  function buildQuery(params) {
    if (!params) return '';
    var pairs = [];
    Object.keys(params).forEach(function (key) {
      var value = params[key];
      if (value === undefined || value === null || value === '') return;
      pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(value)));
    });
    return pairs.length ? '?' + pairs.join('&') : '';
  }

  // 不带包络解析的底层请求（用于 CSRF 自救，避免递归）。
  function rawStatus() {
    return fetch('/api/status', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store'
    }).then(function (res) {
      return res.json().catch(function () { return null; });
    }).then(function (payload) {
      captureCsrf(payload);
      syncCsrf();
      return payload;
    }).catch(function () { return null; });
  }

  /**
   * 请求 API。
   * @param {string} path  例如 '/api/servers'
   * @param {{method?:string, body?:any, query?:object, redirect401?:boolean}} [options]
   * @returns {Promise<any>} 解包后的 data
   */
  function apiFetch(path, options) {
    options = options || {};
    var method = (options.method || 'GET').toUpperCase();
    var query = buildQuery(options.query);
    var url = path + query;
    var redirect401 = options.redirect401 !== false;

    function attempt(isRetry) {
      var headers = { 'Accept': 'application/json' };
      var body;
      if (options.body !== undefined && options.body !== null) {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(options.body);
      }
      if (method !== 'GET' && method !== 'HEAD') {
        headers[CSRF_HEADER] = net.csrf || syncCsrf();
      }
      return fetch(url, {
        method: method,
        headers: headers,
        body: body,
        credentials: 'same-origin',
        cache: 'no-store'
      }).then(function (res) {
        var contentType = (res.headers.get('content-type') || '').toLowerCase();
        var payloadPromise = contentType.indexOf('application/json') >= 0
          ? res.json().catch(function () { return null; })
          : Promise.resolve(null);

        return payloadPromise.then(function (payload) {
          captureCsrf(payload);

          if (!res.ok || (payload && payload.ok === false)) {
            var err = (payload && payload.error) || {};
            var apiErr = new APIError({
              status: res.status,
              code: err.code || ('HTTP_' + res.status),
              message: err.message || defaultMessage(res.status),
              hint: err.hint || '',
              retry_after_s: err.retry_after_s || 0
            });

            // 403：可能是 CSRF nonce 轮换，刷新后重试一次。
            if (res.status === 403 && method !== 'GET' && !isRetry) {
              return rawStatus().then(function () { return attempt(true); });
            }

            // 401：会话失效 → 回登录页（app 侧判断当前是否已登录，避免登录页自身报错时乱跳）。
            // /api/status 是启动探测接口，不触发全局跳转。
            if (res.status === 401 && redirect401 && path !== '/api/status') {
              if (typeof net.onUnauthorized === 'function') net.onUnauthorized(apiErr);
            }

            throw apiErr;
          }

          // 成功：解包 {ok:true,data}
          if (payload && typeof payload === 'object' && payload.ok === true) {
            return Object.prototype.hasOwnProperty.call(payload, 'data') ? payload.data : payload;
          }
          return payload;
        });
      }, function (networkErr) {
        throw new APIError({
          status: 0,
          code: 'NETWORK_ERROR',
          message: '无法连接管理服务',
          hint: '确认 sshbind/dbbind --startserver 仍在运行，且地址是本机 127.0.0.1。'
        });
      });
    }

    return attempt(false);
  }

  function apiGet(path, query) { return apiFetch(path, { method: 'GET', query: query }); }
  function apiPost(path, body, query) { return apiFetch(path, { method: 'POST', body: body === undefined ? {} : body, query: query }); }
  function apiPut(path, body) { return apiFetch(path, { method: 'PUT', body: body === undefined ? {} : body }); }
  function apiDelete(path, body, query) { return apiFetch(path, { method: 'DELETE', body: body, query: query }); }

  // 401 全局钩子由 app.js 注册。
  net.setUnauthorizedHandler = function (fn) { net.onUnauthorized = fn; };

  // 直接导出内部 net 对象（而不是新建对象），保证 app.js 对 BC.net.csrf 的
  // 赋值与 apiFetch 使用的是同一份状态。
  net.APIError = APIError;
  net.csrfHeader = CSRF_HEADER;
  net.csrfCookieNames = CSRF_COOKIE_NAMES;
  net.readCookie = readCookie;
  net.readCsrfCookie = readCsrfCookie;
  net.syncCsrf = syncCsrf;
  net.get = apiGet;
  net.post = apiPost;
  net.put = apiPut;
  net.del = apiDelete;
  net.fetch = apiFetch;

  BC.net = net;
})();
