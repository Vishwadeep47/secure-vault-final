/* Small UI helpers. Everything is built with createElement + textContent, never
   HTML strings, so text typed by users can never turn into running code (no XSS). */
(function () {
  "use strict";
  const SV = (window.SV = window.SV || {});
  SV.views = {};
  SV.tabs = {};

  SV.h = function (tag, attrs) {
    const el = document.createElement(tag);
    const a = attrs || {};
    Object.keys(a).forEach(function (key) {
      const value = a[key];
      if (value === null || value === undefined || value === false) return;
      if (key === "class") el.className = value;
      else if (key.indexOf("on") === 0 && typeof value === "function") el.addEventListener(key.slice(2), value);
      else if (value === true) el.setAttribute(key, "");
      else el.setAttribute(key, String(value));
    });
    Array.prototype.slice.call(arguments, 2).flat(Infinity).forEach(function (child) {
      if (child === null || child === undefined || child === false) return;
      el.append(child.nodeType ? child : document.createTextNode(String(child)));
    });
    return el;
  };
  const h = SV.h;

  /* A label + input pair. Returns { wrap, input }. attrs.tag can be "textarea". */
  let fieldCounter = 0;
  SV.field = function (label, attrs) {
    const a = Object.assign({}, attrs);
    const tag = a.tag || "input";
    delete a.tag;
    const id = "field-" + ++fieldCounter;
    const input = h(tag, Object.assign({ class: "input", id: id }, a));
    return { wrap: h("div", { class: "field" }, h("label", { for: id }, label), input), input: input };
  };

  SV.showMsg = function (el, text, kind) {
    el.textContent = text || "";
    el.className = "msg " + (kind || "");
    el.hidden = !text;
  };
  SV.msgBox = function () { return h("p", { class: "msg", role: "alert", hidden: true }); };

  /* Run an async action: disable the button, show errors in the message box. */
  SV.run = async function (button, msgEl, action) {
    if (msgEl) SV.showMsg(msgEl, "");
    if (button) button.disabled = true;
    try {
      return await action();
    } catch (e) {
      const text = (e && e.message) || "Something went wrong";
      if (msgEl) SV.showMsg(msgEl, text, "error"); else SV.toast(text, "error");
      return undefined;
    } finally {
      if (button) button.disabled = false;
    }
  };

  SV.toast = function (text, kind) {
    const box = document.getElementById("toasts");
    if (!box) return;
    const t = h("div", { class: "toast " + (kind || "") }, text);
    box.append(t);
    setTimeout(function () { t.remove(); }, 4500);
  };

  SV.formatTime = function (iso) {
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString();
  };
  SV.formatBytes = function (n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  };

  /* Things to tidy up when the user leaves a screen (timers, picture URLs). */
  const cleanups = [];
  SV.onLeave = function (fn) { cleanups.push(fn); };
  SV.runCleanups = function () {
    while (cleanups.length) {
      try { cleanups.pop()(); } catch (e) { /* ignore */ }
    }
  };

  /* The frame around every signed-in screen: top bar, content, bottom tabs. */
  SV.appShell = function (active, content) {
    const s = SV.session.get() || {};
    const links = [["vault", "Vault", "#/vault/notes"], ["account", "Account", "#/account"]];
    if (s.role === "admin") links.push(["admin", "Admin", "#/admin"]);
    return h("div", { class: "shell" },
      h("header", { class: "topbar" },
        h("span", { class: "brand" }, "SecureVault"),
        h("span", { class: "who" }, (s.username || "") + (s.role === "admin" ? " (admin)" : "")),
        h("button", { class: "btn small", type: "button", onclick: function () { SV.logout(); } }, "Log out")),
      h("main", { class: "container" }, content),
      h("nav", { class: "bottom-nav" },
        links.map(function (l) { return h("a", { href: l[2], class: l[0] === active ? "active" : "" }, l[1]); })));
  };

  SV.logout = async function () {
    try { await SV.api.post("/api/logout", {}, { keepSession: true }); } catch (e) { /* already ended */ }
    SV.session.clear();
    SV.toast("You are logged out.");
    SV.navigate("#/login");
  };
})();
