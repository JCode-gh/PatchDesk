import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inject, loadCatalog, renderCrawl } from "../netlify/edge-functions/crawl-html.js";

const indexPath = join(dirname(fileURLToPath(import.meta.url)), "..", "index.html");
const catalog = await loadCatalog();
const html = readFileSync(indexPath, "utf8");
if (!html.includes("<!--crawl-->")) {
  console.error("index.html is missing the crawl markers");
  process.exit(1);
}
writeFileSync(indexPath, inject(html, renderCrawl(catalog)));
console.log("Wrote crawlable flaws for", catalog.dateReleased || catalog.catalogVersion || "the current catalog");
