/* The vault: notes, images, cards. */
(function () {
  "use strict";
  const SV = window.SV;
  const h = SV.h, field = SV.field, api = SV.api;

  SV.views.vault = function (sub) {
    const tab = ["notes", "images", "cards"].indexOf(sub) >= 0 ? sub : "notes";
    const body = h("div", {});
    const tabs = h("div", { class: "tabs" },
      [["notes", "Notes"], ["images", "Images"], ["cards", "Cards"]].map(function (t) {
        return h("a", { href: "#/vault/" + t[0], class: "tab" + (t[0] === tab ? " active" : "") }, t[1]);
      }));
    SV.tabs[tab](body);
    return SV.appShell("vault", [tabs, body]);
  };

  /* ------------------------------------------------------------------ notes */
  SV.tabs.notes = function (root) {
    let editingId = null;
    const title = field("Title", { type: "text", maxlength: "200", required: true });
    const content = field("Note", { tag: "textarea", rows: "6", maxlength: "20000", required: true });
    const msg = SV.msgBox();
    const formHeading = h("h2", {}, "New note");
    const saveBtn = h("button", { class: "btn primary", type: "submit" }, "Save note");
    const form = h("form", { class: "card", hidden: true, onsubmit: save },
      formHeading, title.wrap, content.wrap, msg,
      h("div", { class: "row" }, saveBtn, h("button", { class: "btn", type: "button", onclick: closeForm }, "Cancel")));
    const detail = h("div", {});
    const list = h("div", { class: "list" });

    root.append(
      h("div", { class: "row between" }, h("h2", {}, "Notes"),
        h("button", { class: "btn primary small", type: "button", onclick: function () { openForm(null); } }, "+ New note")),
      form, detail, list);

    function openForm(note) {
      editingId = note ? note.id : null;
      formHeading.textContent = note ? "Edit note" : "New note";
      title.input.value = note ? note.title : "";
      content.input.value = note ? note.content : "";
      SV.showMsg(msg, "");
      form.hidden = false;
      title.input.focus();
    }
    function closeForm() { form.hidden = true; editingId = null; }

    async function save(ev) {
      ev.preventDefault();
      const ok = await SV.run(saveBtn, msg, async function () {
        const body = { title: title.input.value.trim(), content: content.input.value };
        if (editingId) await api.put("/api/vault/notes/" + editingId, body);
        else await api.post("/api/vault/notes", body);
        return true;
      });
      if (ok) {
        SV.toast("Note saved (encrypted).", "ok");
        closeForm();
        detail.replaceChildren();
        load();
      }
    }

    async function openNote(id) {
      const note = await SV.run(null, null, function () { return api.get("/api/vault/notes/" + id); });
      if (!note) return;
      detail.replaceChildren(h("div", { class: "card" },
        h("h2", {}, note.title),
        h("p", { class: "muted" }, "Updated " + SV.formatTime(note.updated_at)),
        h("pre", { class: "pre" }, note.content),
        h("div", { class: "row wrap" },
          h("button", { class: "btn small", type: "button", onclick: function () { openForm(note); } }, "Edit"),
          h("button", { class: "btn small danger", type: "button", onclick: function () { remove(note); } }, "Delete"),
          h("button", { class: "btn small", type: "button", onclick: function () { detail.replaceChildren(); } }, "Close"))));
    }

    async function remove(note) {
      if (!window.confirm("Delete this note permanently?")) return;
      const ok = await SV.run(null, null, async function () { await api.del("/api/vault/notes/" + note.id); return true; });
      if (ok) { detail.replaceChildren(); SV.toast("Note deleted."); load(); }
    }

    async function load() {
      const data = await SV.run(null, null, function () { return api.get("/api/vault/notes"); });
      if (!data) return;
      list.replaceChildren();
      if (!data.notes.length) list.append(h("p", { class: "muted" }, "No notes yet. Create your first one."));
      data.notes.forEach(function (n) {
        list.append(h("button", { class: "list-item", type: "button", onclick: function () { openNote(n.id); } },
          h("strong", {}, n.title), h("span", { class: "muted" }, SV.formatTime(n.updated_at))));
      });
    }
    load();
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
      const timer = setInterval(function () {
        seconds -= 1;
        if (seconds <= 0) { clearInterval(timer); slot.replaceChildren(h("p", { class: "muted" }, "Number hidden again.")); }
        else info.textContent = "Hidden again in " + seconds + " s";
      }, 1000);
      timers.push(timer);
      slot.replaceChildren(
        h("p", { class: "mono big" }, String(d.card_number).replace(/(.{4})(?=.)/g, "$1 ")),
        info,
        h("button", { class: "btn small", type: "button", onclick: function () { clearInterval(timer); slot.replaceChildren(); } }, "Hide now"));
    }

    async function remove(c) {
      if (!window.confirm("Delete this card permanently?")) return;
      const ok = await SV.run(null, null, async function () { await api.del("/api/vault/cards/" + c.id); return true; });
      if (ok) { SV.toast("Card deleted."); load(); }
    }
    load();
  };
})();
