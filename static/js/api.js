/* Talking to the server. The login token lives in sessionStorage, which is cleared
   when the tab closes. Nothing is kept in long-term browser storage. */
(function () {
  "use strict";
  const SV = (window.SV = window.SV || {});
  const STORE_KEY = "securevault.session";

  SV.session = {
    get() {
      try { return JSON.parse(sessionStorage.getItem(STORE_KEY)) || null; } catch (e) { return null; }
    },
    set(data) { sessionStorage.setItem(STORE_KEY, JSON.stringify(data)); },
    clear() { sessionStorage.removeItem(STORE_KEY); },
  };

  class ApiError extends Error {
    constructor(status, data) {
      super((data && data.error) || "Request failed (" + status + ")");
      this.status = status;
      this.data = data || {};
    }
  }
  SV.ApiError = ApiError;

  /* options: body (JSON), form (FormData), auth (send token, default true),
     raw (return the Response), keepSession (a 401 here is NOT a session expiry) */
  async function request(method, path, options) {
    const o = options || {};
    const auth = o.auth !== false;
    const session = SV.session.get();
    const headers = {};
    const init = { method: method, headers: headers };
    if (auth && session && session.token) headers["Authorization"] = "Bearer " + session.token;
    if (o.form) {
      init.body = o.form;
    } else if (o.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(o.body);
    }

    let response;
    try {
      response = await fetch(path, init);
    } catch (e) {
      throw new ApiError(0, { error: "Cannot reach the server. Is it running?" });
    }
    if (o.raw && response.ok) return response;

    let data = null;
    if ((response.headers.get("Content-Type") || "").includes("application/json")) {
      try { data = await response.json(); } catch (e) { data = null; }
    }
    if (!response.ok) {
      if (response.status === 401 && auth && session && !o.keepSession && SV.onSessionExpired) {
        SV.onSessionExpired();
      }
      throw new ApiError(response.status, data);
    }
    return data;
  }

  SV.api = {
    get: (path, o) => request("GET", path, o),
    post: (path, body, o) => request("POST", path, Object.assign({ body: body }, o)),
    put: (path, body, o) => request("PUT", path, Object.assign({ body: body }, o)),
    del: (path, o) => request("DELETE", path, o),
    upload: (path, form, o) => request("POST", path, Object.assign({ form: form }, o)),
    async blobUrl(path) {
      const response = await request("GET", path, { raw: true });
      return URL.createObjectURL(await response.blob());
    },
  };
})();
