/* Admin screen: numbers, users, audit log. Only shown to admins. */
(function () {
  "use strict";
  const SV = window.SV;
  const h = SV.h, field = SV.field, api = SV.api;

  function table(headings, rows) {
    return h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, headings.map(function (t) { return h("th", {}, t); }))),
      h("tbody", {}, rows.map(function (r) { return h("tr", {}, r.map(function (c) { return h("td", {}, c); })); }))));
  }

  SV.views.admin = function () {
    const stats = h("div", {});
    const users = h("div", {});
    const logs = h("div", {});
    const chainStatus = h("span", { class: "muted" });
    const verifyBtn = h("button", { class: "btn small", type: "button", onclick: async function () {
      chainStatus.textContent = "Checking...";
      const r = await SV.run(null, null, function () { return api.get("/api/admin/logs/verify"); });
      if (!r) { chainStatus.textContent = ""; return; }
      chainStatus.replaceChildren(r.ok
        ? h("span", { class: "pill ok" }, "Chain intact (" + r.checked + " entries)")
        : h("span", { class: "pill danger" }, "Tampering detected at entry #" + r.broken_at));
    } }, "Verify audit log integrity");

    const root = h("div", {}, h("h2", {}, "Admin"),
      stats, h("section", { class: "block" }, h("h2", {}, "Users"), users),
      h("section", { class: "block" }, h("h2", {}, "Audit log"),
        h("div", { class: "row" }, verifyBtn, chainStatus), logs));

    (async function loadStats() {
      const s = await SV.run(null, null, function () { return api.get("/api/admin/stats"); });
      if (!s) return;
      const tile = function (label, value) { return h("div", { class: "stat" }, h("strong", {}, value), h("span", { class: "muted" }, label)); };
      const events = Object.keys(s.events_last_24h);
      stats.replaceChildren(
        h("div", { class: "stats" }, tile("Users", s.users), tile("Admins", s.admins), tile("With MFA", s.mfa_enabled_users),
          tile("Images", s.images), tile("Cards", s.cards)),
        h("p", { class: "muted" }, events.length
          ? "Last 24 hours: " + events.map(function (e) { return e + " " + s.events_last_24h[e]; }).join(", ")
          : "No activity in the last 24 hours."));
    })();

    async function loadUsers() {
      const d = await SV.run(null, null, function () { return api.get("/api/admin/users"); });
      if (!d) return;
      const me = (SV.session.get() || {}).username;
      users.replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Username", "Role", "MFA", "Status", "Images", "Cards", "Joined", ""].map(function (t) { return h("th", {}, t); }))),
        h("tbody", {}, d.users.map(function (u) {
          const actions = h("div", { class: "row" });
          if (u.username !== me) {
            actions.append(
              u.disabled
                ? h("button", { class: "btn small", type: "button", onclick: function () { userAction(u.id, "enable"); } }, "Enable")
                : h("button", { class: "btn small danger", type: "button", onclick: function () { userAction(u.id, "disable"); } }, "Disable"));
          }
          actions.append(h("button", { class: "btn small", type: "button", onclick: function () { userAction(u.id, "unlock"); } }, "Unlock"));
          return h("tr", {},
            h("td", {}, u.username), h("td", {}, u.role), h("td", {}, u.mfa_enabled ? "on" : "off"),
            h("td", {}, u.disabled ? h("span", { class: "pill" }, "Disabled") : h("span", { class: "pill ok" }, "Active")),
            h("td", {}, u.images_count), h("td", {}, u.cards_count),
            h("td", {}, SV.formatTime(u.created_at)), h("td", {}, actions));
        })))));
    }

    async function userAction(userId, action) {
      const data = await SV.run(null, null, function () { return api.post("/api/admin/users/" + userId + "/" + action, {}); });
      if (data) { SV.toast(data.message, "ok"); loadUsers(); }
    }

    loadUsers();

    const state = { offset: 0, limit: 20, event: "", username: "" };
    const eventInput = field("Event", { type: "text", placeholder: "e.g. login_failed", autocomplete: "off" });
    const userInput = field("Username", { type: "text", autocomplete: "off", autocapitalize: "none" });
    const results = h("div", {});
    const filterBtn = h("button", { class: "btn small", type: "submit" }, "Filter");
    logs.append(h("form", { class: "filters", onsubmit: function (ev) {
      ev.preventDefault();
      state.event = eventInput.input.value.trim();
      state.username = userInput.input.value.trim();
      state.offset = 0;
      loadLogs();
    } }, eventInput.wrap, userInput.wrap, filterBtn), results);

    async function loadLogs() {
      let url = "/api/admin/logs?limit=" + state.limit + "&offset=" + state.offset;
      if (state.event) url += "&event=" + encodeURIComponent(state.event);
      if (state.username) url += "&username=" + encodeURIComponent(state.username);
      const d = await SV.run(null, null, function () { return api.get(url); });
      if (!d) return;
      const from = d.total ? d.offset + 1 : 0;
      const to = d.offset + d.logs.length;
      results.replaceChildren(
        table(["Time", "Event", "User", "IP"], d.logs.map(function (l) { return [SV.formatTime(l.ts), l.event, l.username || "-", l.ip || "-"]; })),
        h("div", { class: "row between" },
          h("button", { class: "btn small", type: "button", disabled: state.offset === 0, onclick: function () { state.offset = Math.max(0, state.offset - state.limit); loadLogs(); } }, "Newer"),
          h("span", { class: "muted" }, "Showing " + from + "-" + to + " of " + d.total),
          h("button", { class: "btn small", type: "button", disabled: to >= d.total, onclick: function () { state.offset += state.limit; loadLogs(); } }, "Older")));
    }
    loadLogs();
    return SV.appShell("admin", root);
  };
})();
