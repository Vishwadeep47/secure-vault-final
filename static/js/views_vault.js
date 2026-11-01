/* The vault: a chat about the encryption used here, images, cards. */
(function () {
  "use strict";
  const SV = window.SV;
  const h = SV.h, field = SV.field, api = SV.api;

  SV.views.vault = function (sub) {
    const tab = ["chat", "images", "cards"].indexOf(sub) >= 0 ? sub : "chat";
    const body = h("div", {});
    const tabs = h("div", { class: "tabs" },
      [["chat", "Chat"], ["images", "Images"], ["cards", "Cards"]].map(function (t) {
        return h("a", { href: "#/vault/" + t[0], class: "tab" + (t[0] === tab ? " active" : "") }, t[1]);
      }));
    SV.tabs[tab](body);
    return SV.appShell("vault", [tabs, body]);
  };

  /* ------------------------------------------------------------------- chat
     Offline, built-in FAQ chat about the encryption techniques used in this
     project (AES-256-GCM, Argon2, TOTP, JWTs, the hash-chained audit log,
     per-user keys). Entirely client-side, pattern-matched against a fixed
     set of topics - no external API, no network call, no key to configure. */
  const CHAT_TOPICS = [
    {
      keys: ["aes", "gcm", "encrypt", "cipher", "vault data", "images", "cards"],
      q: "How is my data encrypted?",
      a: "Images and card details are encrypted with AES-256-GCM before they ever reach the database or disk. Every item gets a fresh random nonce, and the ciphertext is bound (via associated data) to its owner and its own record id, so a ciphertext copied onto someone else's row - or onto a different record - fails to decrypt instead of silently reading as something else.",
    },
    {
      keys: ["argon2", "password hash", "hashing", "hash"],
      q: "How are passwords stored?",
      a: "Passwords are hashed with Argon2 (a memory-hard algorithm built to resist GPU/ASIC cracking) and never stored or logged in plain text. Sign-up, change, and reset all enforce a length-first policy: at least 12 characters, checked against a common-password blocklist and against your own username.",
    },
    {
      keys: ["totp", "mfa", "multi-factor", "authenticator", "2fa", "two factor", "recovery code"],
      q: "How does multi-factor authentication work?",
      a: "MFA uses TOTP: a 6-digit code that changes every 30 seconds, generated from a shared secret and the current time, the same standard your phone's authenticator app already speaks. Once it's turned on, 8 single-use recovery codes are issued (stored only as hashes) in case the app is unavailable; regenerating them invalidates the old set.",
    },
    {
      keys: ["jwt", "token", "session", "login", "logout"],
      q: "How are sessions kept secure?",
      a: "A signed JWT is issued on login and lasts 15 minutes. Each account also has a token_version counter in the database; logging out, changing or resetting a password, or an admin disabling the account all bump it, which makes every token issued before that moment stop working immediately - instead of just expiring on its own later.",
    },
    {
      keys: ["key rotation", "per-user key", "per user key", "own key", "wrapped key", "master key"],
      q: "What is a per-user encryption key?",
      a: "Each account gets its own random 256-bit data key instead of everyone sharing one key. That key is itself encrypted (\"wrapped\") by a server master key kept outside the database, in a separate .secrets folder. Rotating your key issues a new version for anything you save afterwards; older items keep decrypting fine under the key version that originally wrote them.",
    },
    {
      keys: ["audit", "log", "tamper", "hash chain", "chain"],
      q: "What is the audit log, and how is it tamper-evident?",
      a: "Every security-relevant event (logins, card and image activity, admin actions) is written to an audit log where each row's hash covers its own fields plus the previous row's hash - a hash chain. Editing, deleting, or reordering any row breaks the chain from that point on, and an admin can recompute it to find exactly where.",
    },
    {
      keys: ["card", "cvv", "luhn", "payment"],
      q: "How are payment cards protected?",
      a: "Card numbers are checked with the Luhn algorithm, then encrypted; only a token and the last 4 digits are stored outside the ciphertext. The CVV is never asked for and never stored. Revealing a full number requires your password (and MFA if enabled) again, and the number hides itself - and clears the clipboard - after 15 seconds.",
    },
  ];
  const CHAT_FALLBACK = "I don't have a canned answer for that. Try asking about encryption, passwords, MFA, sessions, per-user keys, the audit log, or cards.";
  const CHAT_GREETING = "Ask me about the security tech behind SecureVault - AES-GCM encryption, Argon2 password hashing, TOTP/MFA, sessions, per-user keys, or the audit log.";

  function chatAnswer(text) {
    const q = text.toLowerCase();
    const hit = CHAT_TOPICS.find(function (t) { return t.keys.some(function (k) { return q.indexOf(k) >= 0; }); });
    return hit ? hit.a : CHAT_FALLBACK;
  }

  SV.tabs.chat = function (root) {
    const log = h("div", { class: "chat-log" });
    const input = field("Ask about the encryption used here", { type: "text", maxlength: "200", autocomplete: "off" });
    const sendBtn = h("button", { class: "btn primary", type: "submit" }, "Ask");
    const form = h("form", { class: "chat-form", onsubmit: ask }, input.wrap, sendBtn);

    function addBubble(text, who) {
      log.append(h("div", { class: "chat-bubble " + who }, text));
      log.scrollTop = log.scrollHeight;
    }

    function addSuggestions() {
      const row = h("div", { class: "chat-suggestions" },
        CHAT_TOPICS.map(function (t) {
          return h("button", { class: "pill", type: "button", onclick: function () { input.input.value = t.q; ask(); } }, t.q);
        }));
      log.append(row);
    }

    function ask(ev) {
      if (ev) ev.preventDefault();
      const text = input.input.value.trim();
      if (!text) return;
      addBubble(text, "me");
      input.input.value = "";
      setTimeout(function () { addBubble(chatAnswer(text), "bot"); }, 150);
    }

    root.append(
      h("div", { class: "row between" }, h("h2", {}, "Encryption chat"),
        h("span", { class: "muted" }, "Offline - built-in answers only")),
      log, form);
    addBubble(CHAT_GREETING, "bot");
    addSuggestions();
    input.input.focus();
  };

  /* ----------------------------------------------------------------- images */
  SV.tabs.images = function (root) {
    let urls = [];
    function revokeAll() { urls.forEach(function (u) { URL.revokeObjectURL(u); }); urls = []; }
    SV.onLeave(revokeAll);

    const fileInput = h("input", { class: "input", type: "file", accept: "image/png,image/jpeg,image/gif,image/webp", required: true });
    const msg = SV.msgBox();
    const upBtn = h("button", { class: "btn primary", type: "submit" }, "Encrypt and upload");
    const form = h("form", { class: "card", onsubmit: upload },
      h("h2", {}, "Upload an image"),
      h("p", { class: "muted" }, "PNG, JPEG, GIF or WEBP, up to 10 MB. Encrypted before it is saved."),
      fileInput, msg, upBtn);
    const grid = h("div", { class: "image-grid" });
    root.append(form, grid);

    async function upload(ev) {
      ev.preventDefault();
      const file = fileInput.files && fileInput.files[0];
      if (!file) { SV.showMsg(msg, "Choose an image first.", "error"); return; }
      if (file.size > 10 * 1024 * 1024) { SV.showMsg(msg, "That file is larger than 10 MB.", "error"); return; }
      const ok = await SV.run(upBtn, msg, async function () {
        const data = new FormData();
        data.append("file", file);
        await api.upload("/api/vault/images", data);
        return true;
      });
      if (ok) { fileInput.value = ""; SV.toast("Image encrypted and saved.", "ok"); load(); }
    }

    async function load() {
      const data = await SV.run(null, null, function () { return api.get("/api/vault/images"); });
      if (!data) return;
      revokeAll();
      grid.replaceChildren();
      if (!data.images.length) grid.append(h("p", { class: "muted" }, "No images yet."));
      data.images.forEach(function (img) {
        const thumb = h("div", { class: "thumb" }, "Decrypting...");
        grid.append(h("figure", { class: "image-item" },
          thumb,
          h("figcaption", {}, img.original_name, h("br"), h("span", { class: "muted" }, SV.formatBytes(img.size_bytes))),
          h("button", { class: "btn small danger", type: "button", onclick: function () { remove(img); } }, "Delete")));
        api.blobUrl("/api/vault/images/" + img.id).then(function (url) {
          urls.push(url);
          thumb.replaceWith(h("img", { src: url, alt: img.original_name }));
        }).catch(function () { thumb.textContent = "Could not load"; });
      });
    }

    async function remove(img) {
      if (!window.confirm("Delete this image permanently?")) return;
      const ok = await SV.run(null, null, async function () { await api.del("/api/vault/images/" + img.id); return true; });
      if (ok) { SV.toast("Image deleted."); load(); }
    }
    load();
  };

  /* ------------------------------------------------------------------ cards */
  SV.tabs.cards = function (root) {
    const timers = [];
    SV.onLeave(function () { timers.forEach(clearInterval); });

    const number = field("Card number", { type: "text", inputmode: "numeric", autocomplete: "off", placeholder: "4242 4242 4242 4242", required: true });
    const holder = field("Name on card", { type: "text", autocomplete: "off", maxlength: "60", required: true });
    const month = field("Expiry month (1-12)", { type: "number", min: "1", max: "12", autocomplete: "off", required: true });
    const year = field("Expiry year (e.g. 2030)", { type: "number", min: String(new Date().getFullYear()), autocomplete: "off", required: true });
    const label = field("Label (optional)", { type: "text", maxlength: "50", autocomplete: "off" });
    const msg = SV.msgBox();
    const addBtn = h("button", { class: "btn primary", type: "submit" }, "Encrypt and save card");
    const form = h("form", { class: "card", onsubmit: add },
      h("h2", {}, "Save a card"),
      h("p", { class: "muted" }, "Demo only: use test numbers such as 4242 4242 4242 4242, never a real card. The CVV is never asked for and never stored."),
      number.wrap, holder.wrap, month.wrap, year.wrap, label.wrap, msg, addBtn);
    const list = h("div", { class: "list" });
    root.append(form, list);

    async function add(ev) {
      ev.preventDefault();
      const ok = await SV.run(addBtn, msg, async function () {
        await api.post("/api/vault/cards", {
          card_number: number.input.value, holder_name: holder.input.value.trim(),
          exp_month: month.input.value, exp_year: year.input.value, label: label.input.value.trim(),
        });
        return true;
      });
      if (ok) {
        [number, holder, month, year, label].forEach(function (f) { f.input.value = ""; });
        SV.toast("Card encrypted and saved.", "ok");
        load();
      }
    }

    async function load() {
      const data = await SV.run(null, null, function () { return api.get("/api/vault/cards"); });
      if (!data) return;
      list.replaceChildren();
      if (!data.cards.length) list.append(h("p", { class: "muted" }, "No cards saved yet."));
      data.cards.forEach(function (c) { list.append(cardItem(c)); });
    }

    function cardItem(c) {
      const slot = h("div", { class: "slot" });
      return h("div", { class: "card" },
        h("div", { class: "row between" }, h("strong", {}, c.label), h("span", { class: "pill" }, c.brand)),
        h("p", { class: "mono" }, c.masked),
        h("div", { class: "row wrap" },
          h("button", { class: "btn small", type: "button", onclick: function () { showDetails(c, slot); } }, "Details"),
          h("button", { class: "btn small", type: "button", onclick: function () { showReveal(c, slot); } }, "Reveal number"),
          h("button", { class: "btn small danger", type: "button", onclick: function () { remove(c); } }, "Delete")),
        slot);
    }

    async function showDetails(c, slot) {
      const d = await SV.run(null, null, function () { return api.get("/api/vault/cards/" + c.id); });
      if (!d) return;
      slot.replaceChildren(
        h("p", {}, "Name: " + d.holder),
        h("p", {}, "Expires: " + String(d.exp_month).padStart(2, "0") + "/" + d.exp_year),
        h("p", { class: "muted mono" }, "Token: " + d.token));
    }

    function showReveal(c, slot) {
      const pw = field("Confirm your password to reveal", { type: "password", autocomplete: "current-password", required: true });
      const code = field("Authenticator code", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6" });
      code.wrap.hidden = true;
      const rmsg = SV.msgBox();
      const btn = h("button", { class: "btn primary small", type: "submit" }, "Reveal");
      slot.replaceChildren(h("form", {
        onsubmit: async function (ev) {
          ev.preventDefault();
          await SV.run(btn, rmsg, async function () {
            const body = { password: pw.input.value };
            if (!code.wrap.hidden) body.totp = code.input.value.trim();
            try {
              const d = await api.post("/api/vault/cards/" + c.id + "/reveal", body, { keepSession: true });
              showNumber(d, slot);
            } catch (e) {
              if (e.status === 401 && e.data.mfa_required) {
                code.wrap.hidden = false;
                code.input.required = true;
                code.input.focus();
                SV.showMsg(rmsg, "Enter your authenticator code too.", "info");
              } else {
                throw e;
              }
            }
          });
        },
      }, pw.wrap, code.wrap, rmsg, btn));
      pw.input.focus();
    }

    function showNumber(d, slot) {
      let seconds = 15;
      const info = h("p", { class: "muted" }, "Hidden again in " + seconds + " s");
      const clearClipboard = function () {
        // Best-effort: this can also clobber something unrelated the person
        // copied in the meantime, which is an acceptable trade for not
        // leaving a card number sitting in the clipboard indefinitely.
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText("").catch(function () {});
        }
      };
      const timer = setInterval(function () {
        seconds -= 1;
        if (seconds <= 0) {
          clearInterval(timer);
          clearClipboard();
          slot.replaceChildren(h("p", { class: "muted" }, "Number hidden again."));
        } else info.textContent = "Hidden again in " + seconds + " s";
      }, 1000);
      timers.push(timer);
      const plain = String(d.card_number).replace(/(.{4})(?=.)/g, "$1 ");
      slot.replaceChildren(
        h("p", { class: "mono big" }, plain),
        info,
        h("div", { class: "row" },
          h("button", { class: "btn small", type: "button", onclick: function () {
            navigator.clipboard.writeText(d.card_number).then(function () {
              SV.toast("Copied. It will be cleared from your clipboard when the number hides.", "ok");
            }).catch(function () {});
          } }, "Copy number"),
          h("button", { class: "btn small", type: "button", onclick: function () { clearInterval(timer); clearClipboard(); slot.replaceChildren(); } }, "Hide now")));
    }

    async function remove(c) {
      if (!window.confirm("Delete this card permanently?")) return;
      const ok = await SV.run(null, null, async function () { await api.del("/api/vault/cards/" + c.id); return true; });
      if (ok) { SV.toast("Card deleted."); load(); }
    }
    load();
  };
})();
