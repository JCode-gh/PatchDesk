(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PatchDesk = factory();
})(typeof self !== "undefined" ? self : global, function () {
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var SKIP_URL = ["cisa.gov/news-events/directives", "nvd.nist.gov"];

  function productLabel(vuln) {
    var vendor = String((vuln && vuln.vendorProject) || "").trim();
    var product = String((vuln && vuln.product) || "").trim();
    var vendorLower = vendor.toLowerCase();
    var productLower = product.toLowerCase();
    if (!product) return vendor || "this product";
    if (!vendor || vendorLower.indexOf(productLower) !== -1) return product;
    if (productLower.indexOf(vendorLower) !== -1) return product;
    return vendor + " " + product;
  }

  function formatDate(iso) {
    var match = String(iso || "").match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!match) return "";
    return Number(match[3]) + " " + MONTHS[Number(match[2]) - 1] + " " + match[1];
  }

  function vendorUrl(notes) {
    var urls = String(notes || "").match(/https?:\/\/[^\s;]+/g) || [];
    var preferred = urls.filter(function (url) {
      return SKIP_URL.every(function (part) { return url.indexOf(part) === -1; });
    });
    var chosen = preferred[0] || urls[0] || "";
    return chosen.replace(/[),.\]]+$/, "");
  }

  function actionText(role, vuln) {
    var label = productLabel(vuln);
    if (role === "operator") return "Apply the vendor fix for " + label + ", or take it offline.";
    if (role === "author") return "You cannot fix " + label + " from application code. Send the vendor instructions to whoever restarts it.";
    if (role === "host") return "Patch every customer running " + label + ", or suspend what you cannot patch.";
    if (role === "visitor") return "Nothing to install. This is a flaw in " + label + ".";
    return "Ask whoever runs " + label + " to apply the vendor fix. If they cannot, take it offline.";
  }

  function matches(vuln, query) {
    if (!query) return true;
    var haystack = [
      vuln.cveID,
      vuln.vendorProject,
      vuln.product,
      vuln.vulnerabilityName,
      vuln.shortDescription
    ].join(" ").toLowerCase();
    return haystack.indexOf(query) !== -1;
  }

  function newestFirst(vulns) {
    return vulns.slice().sort(function (a, b) {
      if (a.dateAdded === b.dateAdded) return String(a.cveID).localeCompare(String(b.cveID));
      return a.dateAdded < b.dateAdded ? 1 : -1;
    });
  }

  function visibleVulns(vulns, query, limit) {
    var needle = String(query || "").trim().toLowerCase();
    var found = newestFirst(vulns).filter(function (vuln) { return matches(vuln, needle); });
    return found.slice(0, limit);
  }

  function groupsByDate(vulns, query, dateLimit) {
    var needle = String(query || "").trim().toLowerCase();
    var all = newestFirst(vulns).filter(function (vuln) { return matches(vuln, needle); });
    var groups = [];
    var seen = {};
    all.forEach(function (vuln) {
      var key = vuln.dateAdded || "";
      if (!seen[key]) {
        if (groups.length >= dateLimit) return;
        seen[key] = {
          key: key,
          label: formatDate(key) || "Undated",
          items: []
        };
        groups.push(seen[key]);
      }
      seen[key].items.push(vuln);
    });
    return { groups: groups, matchCount: all.length };
  }

  return {
    productLabel: productLabel,
    formatDate: formatDate,
    vendorUrl: vendorUrl,
    actionText: actionText,
    visibleVulns: visibleVulns,
    groupsByDate: groupsByDate
  };
});
