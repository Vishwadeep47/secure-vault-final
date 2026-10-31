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
        mfaCard(me), encryptionKeyCard(), passwordCard(me), activityCard());
    }

    function activityCard() {
      const list = h("div", {}, h("p", { class: "muted" }, "Loading..."));
      SV.run(null, null, function () { return api.get("/api/me/activity?limit=15"); }).then(function (data) {
        if (!data) return;
        if (!data.events.length) { list.replaceChildren(h("p", { class: "muted" }, "No activity yet.")); return; }
        list.replaceChildren(h("ul", { class: "activity-list" }, data.events.map(function (e) {
          return h("li", {}, h("span", {}, e.event.replace(/_/g, " ")), h("span", { class: "muted" }, SV.formatTime(e.ts)));
        })));
      });
      return h("div", { class: "card" }, h("h2", {}, "Recent activity"),
        h("p", { class: "muted" }, "Logins, lockouts, and changes to your own account - the last 15 events."),
        list);
    }

    function encryptionKeyCard() {
      const msg = SV.msgBox();
      const form = h("div", {});
      const rotateBtn = h("button", { class: "btn small", type: "button", onclick: function () {
        const pw = field("Current password", { type: "password", autocomplete: "current-password", required: true });
        const confirmBtn = h("button", { class: "btn primary small", type: "submit" }, "Confirm");
        form.replaceChildren(h("form", { onsubmit: async function (ev) {
          ev.preventDefault();
          const data = await SV.run(confirmBtn, msg, function () {
            return api.post("/api/encryption-key/rotate", { password: pw.input.value });
          });
          if (data) {
            SV.toast("New encryption key issued. New items will use it.", "ok");
            form.replaceChildren();
          }
        } }, pw.wrap, confirmBtn));
      } }, "Rotate my encryption key");
      return h("div", { class: "card" },
        h("h2", {}, "Data encryption key"),
        h("p", { class: "muted" }, "Your notes, images, and cards are encrypted with a key that is yours alone, separate from other accounts. Rotating it issues a new one for anything you add from now on; items you already saved keep working normally."),
        rotateBtn, form, msg);
    }

    /* Shows a set of recovery codes once, with a button that only continues once
       the person says they saved them. Used right after turning MFA on, and
       after regenerating codes. */
    function recoveryCodesBlock(codes, onDone) {
      const list = h("ul", { class: "mono recovery-codes" }, codes.map(function (c) { return h("li", {}, c); }));
      const ackInput = h("input", { type: "checkbox", id: "recovery-ack" });
      const ackLabel = h("label", { for: "recovery-ack" }, "I have saved these codes somewhere safe.");
      const continueBtn = h("button", { class: "btn primary", type: "button", disabled: true }, "Continue");
      ackInput.addEventListener("change", function () { continueBtn.disabled = !ackInput.checked; });
      continueBtn.addEventListener("click", onDone);
      return h("div", { class: "recovery-codes-box" },
        h("p", {}, h("strong", {}, "Save these recovery codes now.")),
        h("p", { class: "muted" }, "Each one lets you log in once if you lose access to your authenticator app. They are shown only this one time."),
        list,
        h("div", { class: "row" }, ackInput, ackLabel),
        continueBtn);
    }

    function mfaCard(me) {
      const card = h("div", { class: "card" }, h("h2", {}, "Multi-factor authentication"));
      if (me.mfa_enabled) {
        card.append(h("p", {}, h("span", { class: "pill ok" }, "On"), " Login needs a code from your authenticator app."));
        card.append(recoveryCodesCard());
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
            const result = await SV.run(enableBtn, msg, function () {
              return api.post("/api/mfa/enable", { code: code.input.value.trim() });
            });
            if (result) {
              area.replaceChildren(recoveryCodesBlock(result.recovery_codes, function () {
                SV.toast("MFA is now on.", "ok");
                render();
              }));
            }
          } }, h("p", {}, "2. Enter the code the app shows:"), code.wrap, msg, enableBtn));
        code.input.focus();
      } }, "Set up MFA");
      card.append(startBtn, area);
      return card;
    }

    function recoveryCodesCard() {
      const box = h("div", { class: "recovery-status" }, h("p", { class: "muted" }, "Checking recovery codes..."));
      SV.run(null, null, function () { return api.get("/api/mfa/recovery-codes"); }).then(function (data) {
        if (!data) return;
        const low = data.remaining <= 2;
        box.replaceChildren(
          h("p", {}, "Unused recovery codes left: ", h("strong", {}, String(data.remaining)),
            low ? h("span", { class: "pill" }, "Running low") : null),
          h("button", { class: "btn small", type: "button", onclick: function () { showRegenerateForm(); } }, "Generate new codes"));
      });

      function showRegenerateForm() {
        const pw = field("Current password", { type: "password", autocomplete: "current-password", required: true });
        const msg = SV.msgBox();
        const btn = h("button", { class: "btn primary", type: "submit" }, "Generate new codes");
        box.replaceChildren(h("form", { onsubmit: async function (ev) {
          ev.preventDefault();
          const data = await SV.run(btn, msg, function () {
            return api.post("/api/mfa/recovery-codes/regenerate", { password: pw.input.value });
          });
          if (data) {
            box.replaceChildren(recoveryCodesBlock(data.recovery_codes, function () {
              SV.toast("New recovery codes issued. The old ones no longer work.", "ok");
              render();
            }));
          }
        } }, h("p", { class: "muted" }, "Your old codes stop working as soon as new ones are issued."),
          pw.wrap, msg, btn));
      }

      return box;
    }

    function passwordCard(me) {
      const current = field("Current password", { type: "password", autocomplete: "current-password", required: true });
      const next = field("New password (12+ characters)", { type: "password", autocomplete: "new-password", required: true, minlength: "12", maxlength: "128" });
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
          [current, next, again, code].forEach(function (f) { f.input.value = ""; f.input.dispatchEvent(new Event("input")); });
          SV.showMsg(msg, "Password changed. Your other sessions were logged out.", "ok");
        }
      } }, h("h2", {}, "Change password"), current.wrap, next.wrap, SV.strengthMeter(next.input), again.wrap, code.wrap, msg, btn);
    }

    render();
    return SV.appShell("account", root);
  };
})();
