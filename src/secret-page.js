import { createServer } from "node:http";
import { random } from "./io.js";
import { escapeHTML } from "./io.js";

export async function captureSecret(title, { timeoutMs = 300000 } = {}) {
  const nonce = random();
  let settled = false;
  let accept, reject;
  const result = new Promise((yes, no) => { accept = yes; reject = no; });
  const server = createServer((request, response) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const path = `/secret/${nonce}`;
    const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" };
    if (request.url !== path || request.headers.host !== `127.0.0.1:${server.address().port}`) { response.writeHead(404).end(); return; }
    if (request.method === "GET") {
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" });
      response.end(`<html lang="ru"><meta charset="utf-8"><title>${escapeHTML(title)}</title><style>body{font:16px system-ui;max-width:32rem;margin:4rem auto;padding:1rem}input,button{font:inherit;padding:.6rem}input{width:100%;box-sizing:border-box;margin:1rem 0}</style><h1>${escapeHTML(title)}</h1><p>Введите токен. Он будет сохранён только на этом компьютере и не попадёт в чат. Для локального эмулятора используйте только тестовый токен из описания MCP, не настоящий Jira/Confluence PAT.</p><form method="post" action="${path}"><input type="password" name="token" autocomplete="off" required autofocus><button>Передать плагину</button></form>`);
      return;
    }
    if (request.method !== "POST" || request.headers.origin !== origin || request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") { response.writeHead(403, headers).end(); return; }
    let input = "";
    request.on("data", (chunk) => { input += chunk; if (input.length > 2048) request.destroy(); });
    request.on("end", () => {
      const token = new URLSearchParams(input).get("token");
      if (!token || token.length > 512 || /[\r\n]/.test(token)) { response.writeHead(400, headers).end("Некорректный токен"); return; }
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end("<html lang=ru><meta charset=utf-8><p>Токен передан плагину. Эту вкладку можно закрыть.</p>");
      if (!settled) { settled = true; accept(token); server.close(); }
    });
  });
  await new Promise((resolve, fail) => { server.once("error", fail); server.listen(0, "127.0.0.1", resolve); });
  const timer = setTimeout(() => { if (!settled) { settled = true; reject(new Error("Время ввода токена истекло")); server.close(); } }, timeoutMs);
  timer.unref();
  result.finally(() => clearTimeout(timer)).catch(() => {});
  return { url: `http://127.0.0.1:${server.address().port}/secret/${nonce}`, result, cancel: () => { if (!settled) { settled = true; reject(new Error("Ввод токена отменён")); server.close(); } } };
}
