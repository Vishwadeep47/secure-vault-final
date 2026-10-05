/* Account screen: profile, multi-factor authentication, change password. */
(function () {
  "use strict";
  const SV = window.SV;
  const h = SV.h, field = SV.field, api = SV.api;

  SV.views.account = function () {
    const root = h("div", {}, h("p", { class: "muted" }, "Loading..."));

    async function render() {
      const me = await SV.run(null, null, function () { return api.get("/api/me"); });
      if (!me) return;
      root.replaceChildren(
        h("h2", {}, "Account"),
        h("div", { class: "card" },
          h("div", { class: "row between" }, h("strong", {}, me.username), h("span", { class: "pill" }, me.role)),
          h("p", { class: "muted" }, "Session lasts 15 minutes. Logging out ends it on every device.")),
        mfaCard(me), passwordCard(me));
    }

    function mfaCard(me) {
      const card = h("div", { class: "card" }, h("h2", {}, "Multi-factor authentication"));
      if (me.mfa_enabled) {
        card.append(h("p", {}, h("span", { class: "pill ok" }, "On"), " Login needs a code from your authenticator app."));
        return card;
      }
      card.append(h("p", { class: "muted" }, "Add a second step to login using an authenticator app (Google Authenticator, Microsoft Authenticator, Authy)."));
      const area = h("div", {});
      const startBtn = h("button", { class: "btn primary", type: "button", onclick: async function () {
        const data = await SV.run(startBtn, null, function () { return api.post("/api/mfa/setup", {}); });
        if (!data) return;
        startBtn.hidden = true;
        const code = field("6-digit code from the app", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", required: true });
        const msg = SV.msgBox();
        const enableBtn = h("button", { class: "btn primary", type: "submit" }, "Turn on MFA");
        area.replaceChildren(
          h("p", {}, "1. Scan this code with your authenticator app:"),
          h("div", { class: "qr" }, h("img", { alt: "QR code for your authenticator app", src: "data:image/svg+xml;utf8," + encodeURIComponent(data.qr_svg) })),
          h("p", { class: "muted" }, "Cannot scan? Type this key into the app instead:"),
          h("p", { class: "mono" }, data.secret),
          h("form", { onsubmit: async function (ev) {
            ev.preventDefault();
            const ok = await SV.run(enableBtn, msg, async function () {
              await api.post("/api/mfa/enable", { code: code.input.value.trim() });
              return true;
            });
            if (ok) { SV.toast("MFA is now on.", "ok"); render(); }
          } }, h("p", {}, "2. Enter the code the app shows:"), code.wrap, msg, enableBtn));
        code.input.focus();
      } }, "Set up MFA");
      card.append(startBtn, area);
      return card;
    }

    function passwordCard(me) {
      const current = field("Current password", { type: "password", autocomplete: "current-password", required: true });
      const next = field("New password (10+ characters)", { type: "password", autocomplete: "new-password", required: true, minlength: "10", maxlength: "128" });
      const again = field("Repeat new password", { type: "password", autocomplete: "new-password", required: true });
      const code = field("Authenticator code", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6" });
      code.wrap.hidden = !me.mfa_enabled;
      code.input.required = !!me.mfa_enabled;
      const msg = SV.msgBox();
      const btn = h("button", { class: "btn primary", type: "submit" }, "Change password");
      return h("form", { class: "card", onsubmit: async function (ev) {
        ev.preventDefault();
        if (next.input.value !== again.input.value) { SV.showMsg(msg, "The new passwords do not match.", "error"); return; }
        const data = await SV.run(btn, msg, function () {
          const body = { current_password: current.input.value, new_password: next.input.value };
          if (!code.wrap.hidden) body.totp = code.input.value.trim();
          return api.post("/api/auth/password/change", body, { keepSession: true });
        });
        if (data) {
          const s = SV.session.get();
          SV.session.set({ token: data.token, role: s.role, username: s.username }); // other sessions ended
          [current, next, again, code].forEach(function (f) { f.input.value = ""; });
          SV.showMsg(msg, "Password changed. Your other sessions were logged out.", "ok");
        }
      } }, h("h2", {}, "Change password"), current.wrap, next.wrap, again.wrap, code.wrap, msg, btn);
    }

    render();
    return SV.appShell("account", root);
  };
})();
