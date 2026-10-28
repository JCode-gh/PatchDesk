const CATALOG_URL = "https://cdn.jsdelivr.net/gh/cisagov/kev-data@develop/known_exploited_vulnerabilities.json";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const ROLES = [
  ["owner", "Site owner"],
  ["operator", "Person who runs the server"],
  ["author", "Person who writes the code"],
  ["host", "Host"],
  ["visitor", "Visitor"]
];

function escapeHtml(value) {
  return String(value || "").replace(/[&<>"']/g, function (char) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
  });
}

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

function actionText(role, vuln) {
  var label = productLabel(vuln);
  if (role === "operator") return "Apply the vendor fix for " + label + ", or take it offline.";
  if (role === "author") return "You cannot fix " + label + " from application code. Send the vendor instructions to whoever restarts it.";
  if (role === "host") return "Patch every customer running " + label + ", or suspend what you cannot patch.";
  if (role === "visitor") return "Nothing to install. This is a flaw in " + label + ".";
  return "Ask whoever runs " + label + " to apply the vendor fix. If they cannot, take it offline.";
}

function cveHref(cve) {
  return /^CVE-\d{4}-\d+$/.test(cve) ? "https://nvd.nist.gov/vuln/detail/" + cve : "";
}

export function renderCrawl(catalog) {
  var vulns = (catalog && catalog.vulnerabilities) || [];
  var groups = [];
  var seen = {};
  vulns.slice().sort(function (a, b) {
    if (a.dateAdded === b.dateAdded) return String(a.cveID).localeCompare(String(b.cveID));
    return a.dateAdded < b.dateAdded ? 1 : -1;
  }).forEach(function (vuln) {
    var key = vuln.dateAdded || "";
    if (!seen[key]) {
      if (groups.length >= 8) return;
      seen[key] = { key: key, label: formatDate(key) || "Undated", items: [] };
      groups.push(seen[key]);
    }
    seen[key].items.push(vuln);
  });

  return groups.map(function (group, index) {
    var count = group.items.length === 1 ? "1 flaw" : group.items.length + " flaws";
    var items = group.items.map(function (vuln) {
      var name = escapeHtml(productLabel(vuln));
      var cve = escapeHtml(vuln.cveID || "");
      var href = cveHref(vuln.cveID || "");
      var cveHtml = href
        ? '<a href="' + href + '" target="_blank" rel="noopener noreferrer">' + cve + "</a>"
        : cve;
      var problem = escapeHtml(vuln.shortDescription || vuln.vulnerabilityName || "");
      var actions = ROLES.map(function (role) {
        return "<li><strong>" + escapeHtml(role[1]) + ".</strong> " + escapeHtml(actionText(role[0], vuln)) + "</li>";
      }).join("");
      return "<li><article><h3>" + name + "</h3><p>" + cveHtml + "</p><p>" + problem + "</p><ul>" + actions + "</ul></article></li>";
    }).join("");
    return "<li class=\"day\"><details" + (index === 0 ? " open" : "") + "><summary>" + escapeHtml(group.label) + ", " + count + "</summary><ul class=\"day-flaws\">" + items + "</ul></details></li>";
  }).join("\n");
}

export function inject(html, block) {
  return html.replace(/<!--crawl-->[\s\S]*?<!--\/crawl-->/, "<!--crawl-->\n" + block + "\n<!--/crawl-->");
}

export async function loadCatalog() {
  var res = await fetch(CATALOG_URL);
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}
