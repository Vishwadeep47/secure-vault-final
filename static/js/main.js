/* Router: shows the right screen for the address after the # sign. */
(function () {
  "use strict";
  const SV = window.SV;
  const PUBLIC = ["login", "register", "forgot"];
  const ALWAYS_ACCESSIBLE = PUBLIC.concat(["shared"]); // "shared" works whether or not you're logged in

  SV.navigate = function (hash) {
    if (window.location.hash === hash) render(); else window.location.hash = hash;
  };

  /* Any request that finds the session ended (token expired or revoked) lands here. */
  SV.onSessionExpired = function () {
    SV.session.clear();
    SV.toast("Your session ended. Please log in again.", "error");
    SV.navigate("#/login");
  };

  function parse() {
    const parts = window.location.hash.replace(/^#\/?/, "").split("/");
    return { name: parts[0] || "", sub: parts[1] || "" };
  }

  function render() {
    SV.runCleanups();
    const route = parse();
    const session = SV.session.get();
    const isPublic = PUBLIC.indexOf(route.name) >= 0;
    const isAlwaysAccessible = ALWAYS_ACCESSIBLE.indexOf(route.name) >= 0;

    if (!session && !isAlwaysAccessible) return SV.navigate("#/login");
    if (session && (route.name === "" || isPublic)) return SV.navigate("#/vault/notes");
    if (route.name === "admin" && session.role !== "admin") return SV.navigate("#/vault/notes");
    if (!SV.views[route.name]) return SV.navigate(session ? "#/vault/notes" : "#/login");

    document.getElementById("app").replaceChildren(SV.views[route.name](route.sub));
    window.scrollTo(0, 0);
  }

  window.addEventListener("hashchange", render);
  render();

  /* Idle auto-logout: someone who walks away from an unlocked device should
     not leave a live session sitting open indefinitely. This is separate
     from (and shorter than) the 15-minute token lifetime - that one limits
     how long a token works at all; this one reacts to the person actually
     being gone. */
  const IDLE_LIMIT_MS = 5 * 60 * 1000;
  let idleTimer = null;

  function armIdleTimer() {
    if (!SV.session.get()) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(function () {
      if (SV.session.get()) SV.logout("Logged out after 5 minutes of inactivity.");
    }, IDLE_LIMIT_MS);
  }

  ["mousemove", "keydown", "mousedown", "touchstart", "scroll"].forEach(function (evt) {
    window.addEventListener(evt, armIdleTimer, { passive: true });
  });
  armIdleTimer();
})();
