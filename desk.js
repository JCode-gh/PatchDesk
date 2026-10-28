(function () {
  var ROLES = [
    { id: "owner", label: "I own the site", short: "Site owner", forWhom: "For the person who owns the site", tone: "down" },
    { id: "operator", label: "I run the server", short: "Person who runs the server", forWhom: "For the person who runs the server", tone: "down" },
    { id: "author", label: "I write the code", short: "Person who writes the code", forWhom: "For the person who writes the code", tone: "ask" },
    { id: "host", label: "I host other people’s sites", short: "Host", forWhom: "For the host", tone: "down" },
    { id: "visitor", label: "I only use the site", short: "Visitor", forWhom: "For someone who only uses the site", tone: "ask" }
  ];
  var DATE_LIMIT = 8;
  var CATALOG_URL = "https://cdn.jsdelivr.net/gh/cisagov/kev-data@develop/known_exploited_vulnerabilities.json";

  var state = { role: "owner", query: "", selected: "", view: "list", openDate: null, vulns: [] };
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

  function shownGroups() {
    return feed.groupsByDate(state.vulns, state.query, DATE_LIMIT);
  }

  function flatten(groups) {
    var rows = [];
    groups.forEach(function (group) {
      group.items.forEach(function (vuln) { rows.push(vuln); });
    });
    return rows;
  }

  function ensureOpen(groups) {
    var keys = groups.map(function (group) { return group.key; });
    if (state.openDate === null || (state.openDate && keys.indexOf(state.openDate) === -1)) {
      state.openDate = keys[0] || "";
    }
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

  function flawButton(vuln, pressed) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "flaw";
    button.dataset.cve = vuln.cveID;
    button.title = feed.productLabel(vuln) + ". " + (vuln.vulnerabilityName || vuln.cveID);
    button.setAttribute("aria-pressed", pressed ? "true" : "false");

    var title = document.createElement("span");
    title.className = "flaw-title";
    title.textContent = feed.productLabel(vuln);

    var meta = document.createElement("span");
    meta.className = "flaw-cve";
    meta.textContent = vuln.cveID;
    if (vuln.knownRansomwareCampaignUse === "Known") {
      var flag = document.createElement("span");
      flag.className = "flag";
      flag.textContent = "Ransomware";
      meta.append(document.createTextNode(", "), flag);
    }

    var problem = document.createElement("span");
    problem.className = "flaw-problem";
    problem.textContent = vuln.shortDescription || vuln.vulnerabilityName || "";

    var actions = document.createElement("ul");
    actions.className = "flaw-actions";
    ROLES.forEach(function (role) {
      var step = document.createElement("li");
      var who = document.createElement("strong");
      who.textContent = role.short + ". ";
      step.append(who, document.createTextNode(feed.actionText(role.id, vuln)));
      actions.appendChild(step);
    });

    button.append(title, meta, problem, actions);
    return button;
  }

  function renderList(groups, current) {
    list.replaceChildren();
    groups.forEach(function (group) {
      var open = group.key === state.openDate;
      var day = document.createElement("li");
      day.className = "day";

      var toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "day-toggle";
      toggle.dataset.date = group.key;
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.setAttribute("aria-controls", "day-" + group.key);

      var when = document.createElement("span");
      when.textContent = group.label;
      var count = document.createElement("span");
      count.className = "day-count";
      count.textContent = group.items.length === 1 ? "1 flaw" : group.items.length + " flaws";
      toggle.append(when, count);

      var flaws = document.createElement("ul");
      flaws.className = "day-flaws";
      flaws.id = "day-" + group.key;
      flaws.hidden = !open;
      if (open) {
        group.items.forEach(function (vuln) {
          var item = document.createElement("li");
          item.appendChild(flawButton(vuln, current && vuln.cveID === current.cveID));
          flaws.appendChild(item);
        });
      }

      day.append(toggle, flaws);
      list.appendChild(day);
    });
  }

  function renderAction(vuln) {
    var role = roleById(state.role);
    var stamp = action.querySelector("[data-slot=stamp]");
    var detail = action.querySelector("[data-slot=detail]");
    var link = action.querySelector("[data-slot=link]");
    var due = action.querySelector("[data-slot=due]");

    var problem = action.querySelector("[data-slot=problem]");

    if (!vuln) {
      action.dataset.tone = "ask";
      action.querySelector("[data-slot=for]").textContent = role.forWhom;
      stamp.textContent = state.query.trim()
        ? "Nothing in the catalog matches that."
        : "The catalog has not loaded.";
      detail.hidden = true;
      problem.hidden = true;
      link.hidden = true;
      due.hidden = true;
      copyButton.hidden = true;
      return;
    }

    var sentence = feed.actionText(role.id, vuln);
    var url = feed.vendorUrl(vuln.notes);
    var about = vuln.shortDescription || vuln.vulnerabilityName || "";
    action.dataset.tone = role.tone;
    action.querySelector("[data-slot=for]").textContent = role.forWhom;
    stamp.textContent = sentence;
    detail.hidden = false;
    detail.textContent = vuln.cveID;
    problem.hidden = !about;
    problem.textContent = about;
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
    var result = shownGroups();
    var groups = result.groups;
    ensureOpen(groups);
    var rows = flatten(groups);
    var openGroup = null;
    for (var i = 0; i < groups.length; i++) {
      if (groups[i].key === state.openDate) openGroup = groups[i];
    }
    var visibleRows = openGroup ? openGroup.items : [];
    var picked = pickedVuln(rows);
    var pickedVisible = picked && visibleRows.indexOf(picked) !== -1 ? picked : null;
    var current = (!isPhone() || state.view === "action")
      ? (pickedVisible || visibleRows[0] || null)
      : pickedVisible;
    var total = state.vulns.length;
    if (!total) {
      status.textContent = "Loading the catalog.";
    } else if (!groups.length) {
      status.textContent = "No match in " + total.toLocaleString("en") + " exploited flaws.";
    } else if (state.query.trim()) {
      status.textContent = groups.length + (groups.length === 1 ? " date matches." : " dates match.");
    } else {
      status.textContent = "Newest " + groups.length + " dates. " + total.toLocaleString("en") + " exploited flaws in the catalog.";
    }
    renderList(groups, current);
    renderAction(picked || visibleRows[0] || rows[0] || null);
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
    return fetch(CATALOG_URL)
      .then(function (res) {
        if (!res.ok) throw new Error(String(res.status));
        return res.json();
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
    var day = event.target.closest("button[data-date]");
    if (day) {
      state.openDate = state.openDate === day.dataset.date ? "" : day.dataset.date;
      render();
      return;
    }
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
    var vuln = signVuln(flatten(shownGroups().groups));
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
