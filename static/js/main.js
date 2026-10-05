/* Router: shows the right screen for the address after the # sign. */
(function () {
  "use strict";
  const SV = window.SV;
  const PUBLIC = ["login", "register", "forgot"];

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

    if (!session && !isPublic) return SV.navigate("#/login");
    if (session && (route.name === "" || isPublic)) return SV.navigate("#/vault/notes");
    if (route.name === "admin" && session.role !== "admin") return SV.navigate("#/vault/notes");
    if (!SV.views[route.name]) return SV.navigate(session ? "#/vault/notes" : "#/login");

    document.getElementById("app").replaceChildren(SV.views[route.name](route.sub));
    window.scrollTo(0, 0);
  }

  window.addEventListener("hashchange", render);
  render();
})();
