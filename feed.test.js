const assert = require("assert");
const feed = require("./feed.js");

const php = {
  cveID: "CVE-2026-109618",
  vendorProject: "PHP Group",
  product: "PHP",
  vulnerabilityName: "PHP Memory Corruption Vulnerability",
  dateAdded: "2026-10-26",
  dueDate: "2026-10-29",
  shortDescription: "PHP contains an out-of-memory corruption vulnerability.",
  notes: "See https://www.php.net/ and https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk and https://nvd.nist.gov/vuln/detail/CVE-2026-109618"
};

assert.strictEqual(feed.productLabel(php), "PHP");
assert.strictEqual(feed.productLabel({ vendorProject: "Google", product: "Brotli" }), "Google Brotli");
assert.strictEqual(feed.productLabel({ vendorProject: "Adobe Commerce and Magento", product: "" }), "Adobe Commerce and Magento");
assert.strictEqual(feed.formatDate("2026-10-27T19:00:02.2307Z"), "27 Oct 2026");
assert.strictEqual(feed.vendorUrl(php.notes), "https://www.php.net/");
assert.strictEqual(feed.actionText("owner", php), "Ask whoever runs PHP to apply the vendor fix. If they cannot, take it offline.");
assert.strictEqual(feed.actionText("visitor", { vendorProject: "Plex", product: "Media Server" }), "Nothing to install. This is a flaw in Plex Media Server.");

const vulns = [
  { cveID: "CVE-1", vendorProject: "Old", product: "Box", vulnerabilityName: "Old bug", dateAdded: "2026-01-01", shortDescription: "" },
  { cveID: "CVE-2", vendorProject: "PHP Group", product: "PHP", vulnerabilityName: "Memory", dateAdded: "2026-10-26", shortDescription: "remote code" },
  { cveID: "CVE-3", vendorProject: "Google", product: "Brotli", vulnerabilityName: "Decoder", dateAdded: "2026-10-27", shortDescription: "" }
];
assert.deepStrictEqual(feed.visibleVulns(vulns, "", 2).map(function (v) { return v.cveID; }), ["CVE-3", "CVE-2"]);
assert.deepStrictEqual(feed.visibleVulns(vulns, "php", 8).map(function (v) { return v.cveID; }), ["CVE-2"]);

var sameDay = vulns.concat([
  { cveID: "CVE-4", vendorProject: "Google", product: "Brotli", vulnerabilityName: "Other", dateAdded: "2026-10-27", shortDescription: "" }
]);
var grouped = feed.groupsByDate(sameDay, "", 2);
assert.strictEqual(grouped.groups.length, 2);
assert.strictEqual(grouped.groups[0].key, "2026-10-27");
assert.deepStrictEqual(grouped.groups[0].items.map(function (v) { return v.cveID; }), ["CVE-3", "CVE-4"]);
assert.strictEqual(grouped.groups[1].key, "2026-10-26");
assert.strictEqual(feed.groupsByDate(sameDay, "php", 8).groups[0].key, "2026-10-26");

console.log("feed checks passed");
