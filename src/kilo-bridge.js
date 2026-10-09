import { createServer } from "node:http";
import { random } from "./io.js";
import { openBrowser } from "./desktop.js";

const escape = (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

// Kilo 7.x does not expose OpenCode's session form API to plugins. Selection
// happens in a one-shot loopback page; no choice is sent to the model.
export class KiloBridge {
  constructor(toast = () => {}, open = openBrowser) {
    this.toast = toast;
    this.open = open;
    this.forms = new Map();
  }
  async form(_sessionID, title, fields) {
    const id = random();
    const csrf = random();
    const field = fields.find((item) => item.type === "multiselect");
    if (!field) return { id };
    const options = new Map(field.options.map((item) => [item.value, item]));
    let accept;
    const result = new Promise((resolve) => { accept = resolve; });
    const server = createServer(async (request, response) => {
      const url = `http://127.0.0.1:${server.address().port}/form/${id}`;
      const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" };
      if (request.url !== `/form/${id}` || request.headers.host !== `127.0.0.1:${server.address().port}`) { response.writeHead(404, headers).end(); return; }
      if (request.method === "GET") {
        const choices = field.options.map((item) => `<label><input type="checkbox" name="choice" value="${escape(item.value)}" ${field.default?.includes(item.value) ? "checked" : ""}><span><b>${escape(item.label)}</b><small>${escape(item.description ?? "")}</small></span></label>`).join("");
        const html = `<!doctype html><html lang="ru"><meta charset="utf-8"><title>${escape(title)}</title><style>body{font:16px system-ui;background:#f7f7f4;color:#222;max-width:620px;margin:6vh auto;padding:24px}h1{font-size:24px}label{display:flex;gap:12px;padding:14px;margin:10px 0;background:white;border:1px solid #ddd;border-radius:10px}small{display:block;color:#666;margin-top:4px}button{background:#222;color:white;border:0;border-radius:8px;padding:12px 20px;cursor:pointer}</style><h1>${escape(title)}</h1><p>${escape(field.description ?? "")}</p><form method="post" action="/form/${id}"><input type="hidden" name="csrf" value="${csrf}">${choices}<button>Применить</button></form></html>`;
        response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(html);
        return;
      }
      const origin = new URL(url).origin;
      if (request.method !== "POST" || (request.headers.origin && request.headers.origin !== origin && request.headers.origin !== "null") || request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") { response.writeHead(403, headers).end(); return; }
      let body = "";
      for await (const chunk of request) { body += chunk; if (body.length > 65536) { response.writeHead(413, headers).end(); return; } }
      const form = new URLSearchParams(body);
      if (form.getAll("csrf").length !== 1 || form.get("csrf") !== csrf) { response.writeHead(403, headers).end(); return; }
      const values = form.getAll("choice");
      if (new Set(values).size !== values.length || values.some((value) => !options.has(value))) { response.writeHead(400, headers).end(); return; }
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end("<!doctype html><html lang=ru><meta charset=utf-8><p>Выбор применён. Эту вкладку можно закрыть.</p></html>");
      accept({ [field.key]: values });
      server.close();
    });
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const url = `http://127.0.0.1:${server.address().port}/form/${id}`;
    this.forms.set(id, { server, result, accept });
    this.open(url).catch(() => this.toast({ title, message: `Откройте ${url}`, variant: "info", duration: 15000 }));
    return { id, url };
  }
  async message(_sessionID, title, description) {
    this.toast({ title, message: description, variant: "info", duration: 10000 });
  }
  wait(_sessionID, id, signal) {
    const form = this.forms.get(id);
    // External login and personal-token pages are opened by the runtime itself.
    if (!form) return signal?.aborted ? Promise.resolve(undefined) : new Promise((resolve) => signal?.addEventListener("abort", () => resolve(undefined), { once: true }));
    if (signal?.aborted) return Promise.resolve(null);
    return Promise.race([form.result, new Promise((resolve) => signal?.addEventListener("abort", () => resolve(null), { once: true }))]);
  }
  async cancel(_sessionID, id) {
    const form = this.forms.get(id);
    if (!form) return;
    this.forms.delete(id);
    form.accept(null);
    form.server.close();
  }
  dispose() { for (const id of this.forms.keys()) this.cancel(null, id); }
}
