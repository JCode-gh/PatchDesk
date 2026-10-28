import { inject, loadCatalog, renderCrawl } from "./crawl-html.js";

var memory = { at: 0, block: "" };

export default async function handler(request, context) {
  var response = await context.next();
  var type = response.headers.get("content-type") || "";
  if (!type.includes("text/html")) return response;
  var html = await response.text();
  if (html.indexOf("<!--crawl-->") === -1) return new Response(html, response);
  try {
    var now = Date.now();
    if (!memory.block || now - memory.at > 6 * 60 * 60 * 1000) {
      memory = { at: now, block: renderCrawl(await loadCatalog()) };
    }
    var headers = new Headers(response.headers);
    headers.delete("content-length");
    return new Response(inject(html, memory.block), { status: response.status, headers: headers });
  } catch (error) {
    return new Response(html, response);
  }
}

export const config = { path: "/" };
