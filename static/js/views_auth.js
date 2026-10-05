/* Sign-in screens: login, register, forgot password. */
(function () {
  "use strict";
  const SV = window.SV;
  const h = SV.h, field = SV.field, api = SV.api;

  function authShell(title, subtitle, children) {
    return h("main", { class: "auth" },
      h("div", { class: "auth-card" },
        h("div", { class: "brand" }, "SecureVault"),
        h("h1", {}, title),
        subtitle ? h("p", { class: "muted" }, subtitle) : null,
        children));
  }

  /* Called after a successful password (+ MFA) check.
     FACE_STEP_HOOK: when face login is built, run the face check here and only
     save the session if it passes. Nothing else in the login flow has to change. */
  SV.completeLogin = async function (data, username) {
    SV.session.set({ token: data.token, role: data.role, username: username });
    SV.navigate("#/vault/notes");
  };

  SV.views.login = function () {
    let needCode = false;
    const user = field("Username", { type: "text", autocomplete: "username", autocapitalize: "none", required: true });
    const pass = field("Password", { type: "password", autocomplete: "current-password", required: true });
    const code = field("Authenticator code", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6" });
    code.wrap.hidden = true;
    const msg = SV.msgBox();
    const btn = h("button", { class: "btn primary block", type: "submit" }, "Log in");

    const form = h("form", {
      onsubmit: async function (ev) {
        ev.preventDefault();
        SV.showMsg(msg, "");
        btn.disabled = true;
        try {
          const body = { username: user.input.value.trim(), password: pass.input.value };
          if (needCode) body.totp = code.input.value.trim();
          const data = await api.post("/api/login", body, { auth: false });
          await SV.completeLogin(data, body.username);
        } catch (e) {
          if (e.status === 401 && e.data.mfa_required) {
            needCode = true;
            code.wrap.hidden = false;
            code.input.required = true;
            code.input.focus();
            SV.showMsg(msg, "Enter the 6-digit code from your authenticator app.", "info");
          } else {
            SV.showMsg(msg, e.message, "error");
          }
        } finally {
          btn.disabled = false;
        }
      },
    }, user.wrap, pass.wrap, code.wrap, msg, btn);

    return authShell("Log in", "Welcome back.", [
      form,
      h("div", { class: "links" },
        h("a", { href: "#/register" }, "Create an account"),
        h("a", { href: "#/forgot" }, "Forgot password?")),
    ]);
  };

  SV.views.register = function () {
    const user = field("Username", { type: "text", autocomplete: "username", autocapitalize: "none", required: true, minlength: "3", maxlength: "32", pattern: "[a-z0-9_]+" });
    const pass = field("Password", { type: "password", autocomplete: "new-password", required: true, minlength: "10", maxlength: "128" });
    const again = field("Repeat password", { type: "password", autocomplete: "new-password", required: true });
    const msg = SV.msgBox();
    const btn = h("button", { class: "btn primary block", type: "submit" }, "Create account");

    const form = h("form", {
      onsubmit: async function (ev) {
        ev.preventDefault();
        if (pass.input.value !== again.input.value) {
          SV.showMsg(msg, "The two passwords do not match.", "error");
          return;
        }
        const ok = await SV.run(btn, msg, async function () {
          await api.post("/api/register", { username: user.input.value.trim().toLowerCase(), password: pass.input.value }, { auth: false });
          return true;
        });
        if (ok) {
          SV.toast("Account created. Please log in.", "ok");
          SV.navigate("#/login");
        }
      },
    }, user.wrap, h("p", { class: "muted" }, "Lowercase letters, numbers and underscore, 3 to 32 characters."),
      pass.wrap, h("p", { class: "muted" }, "At least 10 characters. A long phrase works well."),
      again.wrap, msg, btn);

    return authShell("Create account", null, [form, h("div", { class: "links" }, h("a", { href: "#/login" }, "I already have an account"))]);
  };

  SV.views.forgot = function () {
    const user = field("Username", { type: "text", autocomplete: "username", autocapitalize: "none", required: true });
    const msg1 = SV.msgBox();
    const btn1 = h("button", { class: "btn primary block", type: "submit" }, "Get a reset token");
    const step2 = h("div", { hidden: true });

    const token = field("Reset token", { type: "text", autocomplete: "off", required: true });
    const pass = field("New password", { type: "password", autocomplete: "new-password", required: true, minlength: "10", maxlength: "128" });
    const msg2 = SV.msgBox();
    const btn2 = h("button", { class: "btn primary block", type: "submit" }, "Set new password");

    const form1 = h("form", {
      onsubmit: async function (ev) {
        ev.preventDefault();
        const data = await SV.run(btn1, msg1, function () {
          return api.post("/api/auth/password/forgot", { username: user.input.value.trim().toLowerCase() }, { auth: false });
        });
        if (data) {
          SV.showMsg(msg1, data.message, "ok");
          step2.hidden = false;
          token.input.focus();
        }
      },
    }, user.wrap, msg1, btn1);

    const form2 = h("form", {
      onsubmit: async function (ev) {
        ev.preventDefault();
        const data = await SV.run(btn2, msg2, function () {
          return api.post("/api/auth/password/reset", { token: token.input.value.trim(), new_password: pass.input.value }, { auth: false });
        });
        if (data) {
          SV.toast(data.message, "ok");
          SV.navigate("#/login");
        }
      },
    }, token.wrap, pass.wrap, msg2, btn2);

    step2.append(
      h("h2", {}, "Step 2: use your token"),
      h("p", { class: "muted" }, "Tokens last 15 minutes and work once. While the project is in development the token is printed in the server console instead of being emailed."),
      form2);

    return authShell("Reset password", "We never say whether an account exists.", [
      form1, step2,
      h("div", { class: "links" }, h("a", { href: "#/login" }, "Back to log in")),
    ]);
  };
})();
