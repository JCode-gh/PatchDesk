(function () {
  var ROLES = [
    { id: "owner", label: "I own the site", forWhom: "For the person who owns the site", tone: "down" },
    { id: "operator", label: "I run the server", forWhom: "For the person who runs the server", tone: "down" },
    { id: "author", label: "I write the code", forWhom: "For the person who writes the code", tone: "ask" },
    { id: "host", label: "I host other people’s sites", forWhom: "For the host", tone: "down" },
    { id: "visitor", label: "I only use the site", forWhom: "For someone who only uses the site", tone: "ask" }
  ];
  var EMPTY_LIMIT = 8;
  var SEARCH_LIMIT = 20;
  var COMMIT_URL = "https://api.github.com/repos/cisagov/kev-data/commits/develop";
  var FILE_PATH = "/known_exploited_vulnerabilities.json";

  var state = { role: "owner", query: "", selected: "", view: "list", vulns: [] };
  var narrow = window.matchMedia("(max-width: 860px)");
  var catalog = null;

  var list = document.getElementById("list");
  var status = document.getElementById("status");
  var released = document.getElementById("released");
  var filter = document.getElementById("filter");
  var group = document.getElementById("role-group");
  var action = document.getElementById("action");
  var copyButton = document.getElementById("copy-action");
  var backButton = document.getElementById("back");
  var feed = window.PatchDesk;

  function isPhone() {
    return narrow.matches;
  }

  function roleById(id) {
    for (var i = 0; i < ROLES.length; i++) {
      if (ROLES[i].id === id) return ROLES[i];
    }
    return ROLES[0];
  }

  function catalogUrl(sha) {
    var ref = sha || "develop";
    return "https://cdn.jsdelivr.net/gh/cisagov/kev-data@" + ref + FILE_PATH;
  }

  function readUrl() {
    var params = new URLSearchParams(window.location.search);
    if (roleById(params.get("role")).id === params.get("role")) state.role = params.get("role");
    state.selected = params.get("cve") || "";
    state.view = params.get("view") === "action" ? "action" : "list";
    if (params.get("q")) {
      state.query = params.get("q");
      filter.value = state.query;
    }
  }

  function syncUrl(mode) {
    var params = new URLSearchParams();
    params.set("role", state.role);
    if (state.selected) params.set("cve", state.selected);
    if (state.query) params.set("q", state.query);
    if (isPhone() && state.view === "action") params.set("view", "action");
    var next = window.location.pathname + "?" + params.toString();
    if (mode === "push") window.history.pushState(null, "", next);
    else window.history.replaceState(null, "", next);
  }

  function renderRoles() {
    group.replaceChildren();
    ROLES.forEach(function (role) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "choice";
      button.textContent = role.label;
      button.dataset.id = role.id;
      button.setAttribute("aria-pressed", role.id === state.role ? "true" : "false");
      group.appendChild(button);
    });
  }

  function shown() {
    var limit = state.query.trim() ? SEARCH_LIMIT : EMPTY_LIMIT;
    return feed.visibleVulns(state.vulns, state.query, limit);
  }

  function pickedVuln(rows) {
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].cveID === state.selected) return rows[i];
    }
    return null;
  }

  function signVuln(rows) {
    return pickedVuln(rows) || rows[0] || null;
  }

  function renderList(rows, current) {
    list.replaceChildren();
    rows.forEach(function (vuln) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "flaw";
      button.dataset.cve = vuln.cveID;
      button.title = feed.productLabel(vuln) + ". " + (vuln.vulnerabilityName || vuln.cveID);
      button.setAttribute("aria-pressed", current && vuln.cveID === current.cveID ? "true" : "false");

      var title = document.createElement("span");
      title.className = "flaw-title";
      title.textContent = feed.productLabel(vuln);

      var name = document.createElement("span");
      name.className = "flaw-name";
      name.textContent = vuln.vulnerabilityName || vuln.cveID;

      var meta = document.createElement("span");
      meta.className = "meta";
      meta.textContent = [vuln.cveID, feed.formatDate(vuln.dateAdded)].filter(Boolean).join(", ");
      if (vuln.knownRansomwareCampaignUse === "Known") {
        var flag = document.createElement("span");
        flag.className = "flag";
        flag.textContent = "Ransomware";
        meta.append(document.createTextNode(", "), flag);
      }

      button.append(title, name, meta);
      var item = document.createElement("li");
      item.appendChild(button);
      list.appendChild(item);
    });
  }

  function renderAction(vuln) {
    var role = roleById(state.role);
    var stamp = action.querySelector("[data-slot=stamp]");
    var detail = action.querySelector("[data-slot=detail]");
    var link = action.querySelector("[data-slot=link]");
    var due = action.querySelector("[data-slot=due]");

    if (!vuln) {
      action.dataset.tone = "ask";
      action.querySelector("[data-slot=for]").textContent = role.forWhom;
      stamp.textContent = state.query.trim()
        ? "Nothing in the catalog matches that."
        : "The catalog has not loaded.";
      detail.hidden = true;
      link.hidden = true;
      due.hidden = true;
      copyButton.hidden = true;
      return;
    }

    var sentence = feed.actionText(role.id, vuln);
    var url = feed.vendorUrl(vuln.notes);
    action.dataset.tone = role.tone;
    action.querySelector("[data-slot=for]").textContent = role.forWhom;
    stamp.textContent = sentence;
    detail.hidden = false;
    detail.textContent = vuln.cveID + ", added " + feed.formatDate(vuln.dateAdded) + ".";
    if (url) {
      link.hidden = false;
      link.href = url;
    } else {
      link.hidden = true;
    }
    if (vuln.dueDate) {
      due.hidden = false;
      due.textContent = "US federal agencies are due " + feed.formatDate(vuln.dueDate) + ".";
    } else {
      due.hidden = true;
    }
    copyButton.hidden = false;
  }

  function applyView() {
    document.body.dataset.view = isPhone() ? state.view : "both";
  }

  function render() {
    applyView();
    var rows = shown();
    var picked = pickedVuln(rows);
    var current = (!isPhone() || state.view === "action") ? (picked || rows[0] || null) : picked;
    var total = state.vulns.length;
    var matched = state.query.trim()
      ? feed.visibleVulns(state.vulns, state.query, state.vulns.length).length
      : total;
    if (!total) {
      status.textContent = "Loading the catalog.";
    } else if (!rows.length) {
      status.textContent = "No match in " + total.toLocaleString("en") + " exploited flaws.";
    } else if (state.query.trim()) {
      status.textContent = "Showing " + rows.length + " of " + matched + " matches.";
    } else {
      status.textContent = "Newest " + rows.length + " of " + total.toLocaleString("en") + " exploited flaws.";
    }
    renderList(rows, current);
    renderAction(signVuln(rows));
    renderRoles();
  }

  function applyCatalog(data) {
    catalog = data;
    state.vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    var when = feed.formatDate(data.dateReleased || "");
    released.dateTime = String(data.dateReleased || "").slice(0, 10);
    released.textContent = when ? "Catalog " + when : "Catalog loaded";
    render();
    syncUrl();
  }

  function showError() {
    status.textContent = "The catalog did not load.";
    action.dataset.tone = "down";
    action.querySelector("[data-slot=stamp]").textContent = "Try again in a moment. The list comes from CISA and needs a network connection.";
    copyButton.hidden = true;
  }

  function load() {
    if (window.location.protocol === "file:") {
      status.textContent = "Open this page over http. A file from disk cannot call the catalog.";
      return Promise.resolve();
    }
    status.textContent = "Loading the catalog.";
    return fetch(COMMIT_URL, { cache: "no-store" })
      .then(function (res) { return res.ok ? res.json() : {}; })
      .catch(function () { return {}; })
      .then(function (commit) {
        var url = catalogUrl(commit && commit.sha);
        return fetch(url).then(function (res) {
          if (res.ok) return res.json();
          return fetch(catalogUrl("")).then(function (fallback) {
            if (!fallback.ok) throw new Error(String(fallback.status));
            return fallback.json();
          });
        });
      })
      .then(applyCatalog)
      .catch(showError);
  }

  group.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-id]");
    if (!button) return;
    state.role = button.dataset.id;
    render();
    syncUrl();
  });

  list.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-cve]");
    if (!button) return;
    var opening = isPhone() && state.view !== "action";
    state.selected = button.dataset.cve;
    if (isPhone()) state.view = "action";
    render();
    syncUrl(opening ? "push" : "replace");
    if (opening) backButton.focus();
  });

  backButton.addEventListener("click", function () {
    state.view = "list";
    render();
    syncUrl("replace");
    var picked = list.querySelector('[data-cve="' + state.selected + '"]');
    if (picked) picked.focus();
    else filter.focus();
  });

  window.addEventListener("popstate", function () {
    readUrl();
    render();
  });

  narrow.addEventListener("change", function () {
    render();
  });

  filter.addEventListener("input", function () {
    state.query = filter.value;
    render();
    syncUrl();
  });

  document.getElementById("filter-form").addEventListener("submit", function (event) {
    event.preventDefault();
  });

  copyButton.addEventListener("click", function () {
    var vuln = signVuln(shown());
    if (!vuln) return;
    var text = [
      feed.actionText(state.role, vuln),
      vuln.cveID,
      feed.vendorUrl(vuln.notes)
    ].filter(Boolean).join("\n");
    function done(ok) {
      copyButton.textContent = ok ? "Copied" : "Could not copy";
      window.setTimeout(function () { copyButton.textContent = "Copy the action"; }, 2000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    } else {
      done(false);
    }
  });

  readUrl();
  applyView();
  renderRoles();
  load();
})();
