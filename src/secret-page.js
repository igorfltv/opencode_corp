import { createServer } from "node:http";
import { random, escapeHTML } from "./io.js";

const maxToken = 512;

function page(items, action, csrf) {
  const fields = items.map((item, index) => `<section class="system"><div class="system-head"><span class="number">${String(index + 1).padStart(2, "0")}</span><div><h2>${escapeHTML(item.name)}</h2><p>${escapeHTML(item.description)}</p></div></div><label for="token-${index}">Личный токен</label><input id="token-${index}" name="token:${escapeHTML(item.id)}" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="${maxToken}" placeholder="Вставьте токен для ${escapeHTML(item.name)}" required></section>`).join("");
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>Подключение MCP</title><style>
  :root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#f3f6f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 90% 0%,#d7ebe8 0,transparent 38%),#f3f6f7}main{width:min(720px,calc(100% - 32px));margin:56px auto 72px}.brand{display:flex;align-items:center;gap:12px;color:#264e54;font-size:13px;font-weight:750;letter-spacing:.11em;text-transform:uppercase}.mark{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:#15766d;color:white;font-size:21px;font-weight:700;letter-spacing:0}.panel{margin-top:22px;padding:clamp(24px,5vw,44px);background:#fff;border:1px solid #e0e8e9;border-radius:24px;box-shadow:0 20px 60px #1c434b12}h1{margin:0;font-size:clamp(28px,4vw,38px);line-height:1.15;letter-spacing:-.035em}.lead{margin:15px 0 0;color:#5a6b75;font-size:16px;line-height:1.55}.notice{display:flex;gap:12px;margin:26px 0 8px;padding:15px 17px;background:#ecf8f5;border:1px solid #cce8e1;border-radius:13px;color:#275f57;font-size:14px;line-height:1.45}.notice b{font-size:18px;line-height:1}.system{padding:25px 0;border-bottom:1px solid #e9eef0}.system-head{display:flex;gap:16px;align-items:flex-start}.number{display:grid;place-items:center;flex:none;width:35px;height:35px;border-radius:10px;background:#eaf1f2;color:#4b7278;font-size:12px;font-weight:750}.system h2{margin:1px 0 5px;font-size:19px;letter-spacing:-.015em}.system p{margin:0;color:#64747e;font-size:14px;line-height:1.45}.system label{display:block;margin:20px 0 8px;color:#344a54;font-size:13px;font-weight:700}.system input{display:block;width:100%;height:48px;padding:0 14px;border:1px solid #bdcdd1;border-radius:10px;background:#fbfdfd;color:#17212b;font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}.system input:focus{border-color:#15766d;box-shadow:0 0 0 4px #15766d20}.system input::placeholder{color:#9ba9ae}.footer{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-top:28px}.footnote{max-width:350px;color:#667780;font-size:13px;line-height:1.45}button{border:0;border-radius:11px;padding:14px 23px;background:#126d64;color:#fff;font:inherit;font-size:14px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 6px 16px #126d642d}button:hover{background:#0d5a52}button:focus-visible{outline:3px solid #71cabe;outline-offset:3px}@media(max-width:600px){main{margin:24px auto 40px}.panel{border-radius:18px}.footer{align-items:stretch;flex-direction:column-reverse}button{width:100%}}
  </style></head><body><main><div class="brand"><span class="mark">↗</span> Корпоративные инструменты</div><div class="panel"><h1>Подключите выбранные системы</h1><p class="lead">Введите личные токены для ${items.length} ${items.length % 10 === 1 && items.length % 100 !== 11 ? "системы" : "систем"}. Отправка подключит MCP в текущем запуске OpenCode или Kilo.</p><div class="notice"><b>◈</b><span>Токены передаются только локальному плагину. Они не появятся в чате и не будут записаны в файл конфигурации.</span></div><form method="post" action="${action}" autocomplete="off"><input type="hidden" name="csrf" value="${csrf}">${fields}<div class="footer"><span class="footnote">После перезапуска приложения потребуется ввести токены снова.</span><button type="submit">Подключить ${items.length} MCP</button></div></form></div></main></body></html>`;
}

export async function captureSecrets(items, { timeoutMs = 300000 } = {}) {
  if (!Array.isArray(items) || !items.length || items.length > 30 || new Set(items.map((item) => item.id)).size !== items.length || items.some((item) => !/^[a-z][a-z0-9_-]{0,39}$/.test(item.id))) throw new Error("Некорректный список MCP для ввода токенов");
  const nonce = random();
  const csrf = random();
  let settled = false;
  let accept, reject;
  const result = new Promise((yes, no) => { accept = yes; reject = no; });
  const server = createServer(async (request, response) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const path = `/secret/${nonce}`;
    const headers = { "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" };
    if (request.url !== path || request.headers.host !== `127.0.0.1:${server.address().port}`) { response.writeHead(404, headers).end(); return; }
    if (request.method === "GET") {
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(page(items, path, csrf));
      return;
    }
    // Some local browsers omit Origin (or send "null") for form submissions.
    // The unguessable form token provides CSRF protection in those cases.
    if (request.method !== "POST" || (request.headers.origin && request.headers.origin !== origin && request.headers.origin !== "null") || request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") { response.writeHead(403, headers).end(); return; }
    let input = "";
    try {
      for await (const chunk of request) {
        input += chunk;
        if (input.length > 65536) { response.writeHead(413, headers).end(); return; }
      }
    } catch { if (!response.writableEnded) response.writeHead(400, headers).end(); return; }
    const form = new URLSearchParams(input);
    if (form.getAll("csrf").length !== 1 || form.get("csrf") !== csrf) { response.writeHead(403, headers).end(); return; }
    const expected = new Set(items.map((item) => `token:${item.id}`));
    if ([...form.keys()].some((key) => key !== "csrf" && !expected.has(key)) || [...expected].some((key) => form.getAll(key).length !== 1 || !form.get(key) || form.get(key).length > maxToken || /[\r\n]/.test(form.get(key)))) {
      response.writeHead(400, { ...headers, "Content-Type": "text/plain; charset=utf-8" }).end("Проверьте токены и повторите отправку.");
      return;
    }
    const tokens = new Map(items.map((item) => [item.id, form.get(`token:${item.id}`)]));
    response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end("<!doctype html><html lang=ru><meta charset=utf-8><title>MCP подключаются</title><style>body{font:16px system-ui;max-width:32rem;margin:12vh auto;padding:2rem;background:#f3f6f7;color:#17212b}main{padding:2rem;background:white;border-radius:18px}h1{font-size:25px}</style><main><h1>Токены переданы</h1><p>Плагин подключает выбранные MCP. Эту вкладку можно закрыть.</p></main></html>");
    if (!settled) { settled = true; accept(tokens); server.close(); }
  });
  await new Promise((resolve, fail) => { server.once("error", fail); server.listen(0, "127.0.0.1", resolve); });
  const timer = setTimeout(() => { if (!settled) { settled = true; reject(new Error("Время ввода токенов истекло")); server.close(); } }, timeoutMs);
  timer.unref();
  result.finally(() => clearTimeout(timer)).catch(() => {});
  return { url: `http://127.0.0.1:${server.address().port}/secret/${nonce}`, result, cancel: () => { if (!settled) { settled = true; reject(new Error("Ввод токенов отменён")); server.close(); } } };
}
