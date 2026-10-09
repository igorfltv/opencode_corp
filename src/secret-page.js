import { createServer } from "node:http";
import { random, escapeHTML } from "./io.js";

const maxToken = 512;
const idPattern = /^[a-z][a-z0-9_-]{0,39}$/;

function page(items, selected, action, csrf, scriptNonce) {
  const cards = items.map((item, index) => {
    const active = selected.has(item.id);
    const id = escapeHTML(item.id);
    const name = escapeHTML(item.name);
    return `<article class="system${active ? " active" : ""}" data-connected="${active}"><div class="system-head"><input class="choice" id="mcp-${index}" type="checkbox" name="mcp" value="${id}"${active ? " checked" : ""}><label class="system-choice" for="mcp-${index}"><span class="number">${String(index + 1).padStart(2, "0")}</span><span class="system-copy"><strong>${name}</strong><span class="description">${escapeHTML(item.description)}</span></span><span class="status">${active ? "Уже выбран" : "Не выбран"}</span></label></div><div class="credentials"><label for="token-${index}">${active ? "Новый токен, если хотите заменить текущий" : "Личный токен"}</label><input id="token-${index}" name="token:${id}" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="${maxToken}" placeholder="${active ? "Оставьте пустым, чтобы сохранить текущий" : `Вставьте токен для ${name}`}"${active ? "" : " required"}><p class="hint">${active ? "Текущий токен не показывается. Можно оставить это поле пустым." : "Токен нужен для первого подключения."}</p></div></article>`;
  }).join("");
  const script = `
    const form = document.querySelector('form');
    const button = document.querySelector('#submit');
    const count = document.querySelector('#count');
    const cards = [...document.querySelectorAll('.system')];
    const hadSelected = ${selected.size > 0};
    function update() {
      let chosen = 0;
      for (const card of cards) {
        const choice = card.querySelector('.choice');
        const token = card.querySelector('input[type=password]');
        const wasSelected = card.dataset.connected === 'true';
        card.classList.toggle('active', choice.checked);
        card.querySelector('.status').textContent = choice.checked
          ? (wasSelected ? 'Уже выбран' : 'Будет добавлен')
          : (wasSelected ? 'Будет отключён' : 'Не выбран');
        token.disabled = !choice.checked;
        token.required = choice.checked && !wasSelected;
        if (choice.checked) chosen++;
      }
      count.textContent = chosen ? chosen + ' MCP выбрано' : 'Ни одного MCP не выбрано';
      button.textContent = chosen ? 'Сохранить и подключить ' + chosen + ' MCP' : hadSelected ? 'Отключить все MCP' : 'Выберите MCP';
      button.disabled = !chosen && !hadSelected;
    }
    for (const card of cards) card.querySelector('.choice').addEventListener('change', update);
    form.addEventListener('submit', () => { button.disabled = true; button.textContent = 'Подключаем…'; });
    update();`;
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>Подключение MCP</title><style>
  :root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#f3f6f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 90% 0%,#d7ebe8 0,transparent 38%),#f3f6f7}main{width:min(760px,calc(100% - 32px));margin:48px auto 72px}.brand{display:flex;align-items:center;gap:12px;color:#264e54;font-size:13px;font-weight:750;letter-spacing:.11em;text-transform:uppercase}.mark{display:grid;place-items:center;width:34px;height:34px;border-radius:11px;background:#15766d;color:white;font-size:21px;font-weight:700;letter-spacing:0}.panel{margin-top:22px;padding:clamp(24px,5vw,44px);background:#fff;border:1px solid #e0e8e9;border-radius:24px;box-shadow:0 20px 60px #1c434b12}h1{margin:0;font-size:clamp(28px,4vw,38px);line-height:1.15;letter-spacing:-.035em}.lead{margin:15px 0 0;color:#5a6b75;font-size:16px;line-height:1.55}.notice{display:flex;gap:12px;margin:25px 0 15px;padding:15px 17px;background:#ecf8f5;border:1px solid #cce8e1;border-radius:13px;color:#275f57;font-size:14px;line-height:1.45}.notice b{font-size:18px;line-height:1}.system{margin-top:12px;border:1px solid #dce6e7;border-radius:15px;background:#fbfdfd;overflow:hidden;transition:border-color .15s,background .15s}.system.active{border-color:#8fc8be;background:#f7fcfa}.system-head{position:relative;display:flex;align-items:flex-start;padding:18px;gap:15px}.choice{width:21px;height:21px;margin:7px 0 0;flex:none;accent-color:#126d64;cursor:pointer}.system-choice{display:flex;align-items:flex-start;gap:13px;flex:1;min-width:0;cursor:pointer}.number{display:grid;place-items:center;flex:none;width:35px;height:35px;border-radius:10px;background:#eaf1f2;color:#4b7278;font-size:12px;font-weight:750}.system-copy{display:flex;flex-direction:column;min-width:0}.system-copy strong{font-size:18px;letter-spacing:-.015em}.description{margin-top:4px;color:#64747e;font-size:14px;line-height:1.45}.status{margin-left:auto;padding:5px 8px;border-radius:8px;background:#e9f4ef;color:#27725f;font-size:12px;font-weight:700;white-space:nowrap}.system:not([data-connected=true]) .status{background:#edf1f3;color:#64747e}.credentials{display:none;padding:0 18px 18px 54px}.system.active .credentials{display:block}.credentials label{display:block;margin:3px 0 8px;color:#344a54;font-size:13px;font-weight:700}.credentials input{display:block;width:100%;height:46px;padding:0 14px;border:1px solid #bdcdd1;border-radius:10px;background:white;color:#17212b;font:inherit;outline:none}.credentials input:focus{border-color:#15766d;box-shadow:0 0 0 4px #15766d20}.credentials input::placeholder{color:#87979e}.hint{margin:7px 0 0;color:#687a81;font-size:12px;line-height:1.4}.footer{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-top:27px}.footnote{max-width:370px;color:#667780;font-size:13px;line-height:1.45}.footnote strong{display:block;color:#344a54;margin-bottom:3px}button{border:0;border-radius:11px;padding:14px 22px;background:#126d64;color:#fff;font:inherit;font-size:14px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 6px 16px #126d642d}button:hover{background:#0d5a52}button:disabled{background:#a7b8b7;box-shadow:none;cursor:default}button:focus-visible,.choice:focus-visible{outline:3px solid #71cabe;outline-offset:3px}@media(max-width:600px){main{margin:24px auto 40px}.panel{border-radius:18px}.system-head{gap:10px;padding:14px}.system-choice{gap:10px;flex-wrap:wrap}.status{margin-left:0}.credentials{padding:0 14px 16px}.footer{align-items:stretch;flex-direction:column}button{width:100%}}
  </style></head><body><main><div class="brand"><span class="mark">↗</span> Корпоративные инструменты</div><div class="panel"><h1>Подключить MCP</h1><p class="lead">Отметьте нужные системы и введите токен рядом с каждой новой системой. Уже выбранные MCP отмечены заранее.</p><div class="notice"><b>◈</b><span>Токены получает только локальный плагин. Они не появятся в чате или файле конфигурации.</span></div><form method="post" action="${action}" autocomplete="off"><input type="hidden" name="csrf" value="${csrf}">${cards}<div class="footer"><span class="footnote"><strong id="count">${selected.size} MCP выбрано</strong>Снимите отметку, чтобы отключить MCP. После перезапуска приложения токены нужно ввести снова.</span><button id="submit" type="submit">Сохранить и подключить</button></div></form></div></main><script nonce="${scriptNonce}">${script}</script></body></html>`;
}

function resultPage(outcome = {}) {
  const kind = ["success", "warning", "error"].includes(outcome.kind) ? outcome.kind : "warning";
  const title = escapeHTML(outcome.title ?? "Настройки MCP сохранены");
  const message = escapeHTML(outcome.message ?? "Плагин обрабатывает подключение.");
  const retry = typeof outcome.retry === "string" ? `<p><a href="${escapeHTML(outcome.retry)}">Вернуться к форме</a></p>` : "";
  const icon = { success: "✓", warning: "·", error: "!" }[kind];
  const items = Array.isArray(outcome.items) ? outcome.items.map((item) => {
    const state = item.status === "connected" ? "ok" : item.status === "failed" ? "bad" : "wait";
    return `<li><span class="dot ${state}">${{ ok: "✓", bad: "!", wait: "·" }[state]}</span><span><strong>${escapeHTML(item.name)}</strong><small>${escapeHTML(item.detail ?? "")}</small></span></li>`;
  }).join("") : "";
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>${title}</title><style>
  :root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17212b;background:#f3f6f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 85% 0%,#d7ebe8 0,transparent 40%),#f3f6f7}main{width:min(620px,calc(100% - 32px));margin:9vh auto 48px}.brand{color:#37666a;font-size:12px;font-weight:750;letter-spacing:.12em;text-transform:uppercase}.card{margin-top:20px;padding:clamp(26px,5vw,42px);border:1px solid #e0e8e9;border-radius:24px;background:#fff;box-shadow:0 20px 60px #1c434b12}.icon{display:grid;place-items:center;width:54px;height:54px;border-radius:17px;font-size:29px;font-weight:700;background:#e7f5ef;color:#16805c}.warning .icon{background:#fff4da;color:#a56b14}.error .icon{background:#fcebea;color:#bd5149}h1{margin:24px 0 0;font-size:clamp(28px,4vw,36px);line-height:1.15;letter-spacing:-.035em}p{margin:13px 0 0;color:#5a6b75;font-size:16px;line-height:1.55}ul{list-style:none;margin:27px 0 0;padding:0;border-top:1px solid #edf0f1}li{display:flex;gap:13px;align-items:flex-start;padding:16px 0;border-bottom:1px solid #edf0f1}.dot{display:grid;place-items:center;flex:none;width:27px;height:27px;border-radius:9px;font-size:15px;font-weight:750}.dot.ok{background:#e7f5ef;color:#16805c}.dot.bad{background:#fcebea;color:#bd5149}.dot.wait{background:#edf1f3;color:#667780}strong{display:block;font-size:15px}small{display:block;margin-top:4px;color:#6a7981;font-size:13px;line-height:1.4}.footer{margin-top:25px;color:#7c8b92;font-size:13px}@media(max-width:600px){main{margin:24px auto}.card{border-radius:18px}}
  a{color:#126d64;font-weight:700}a:focus-visible{outline:3px solid #71cabe;outline-offset:3px}</style></head><body><main class="${kind}"><div class="brand">↗ Корпоративные инструменты</div><div class="card"><div class="icon">${icon}</div><h1>${title}</h1><p>${message}</p>${retry}${items ? `<ul>${items}</ul>` : ""}<div class="footer">Эту вкладку можно закрыть.</div></div></main></body></html>`;
}

export async function captureMCPSetup(items, { selected = [], timeoutMs = 300000, onSubmit } = {}) {
  if (!Array.isArray(items) || !items.length || items.length > 30 || new Set(items.map((item) => item.id)).size !== items.length || items.some((item) => !idPattern.test(item.id))) throw new Error("Некорректный каталог MCP для формы");
  if (!Array.isArray(selected) || new Set(selected).size !== selected.length || selected.some((id) => !items.some((item) => item.id === id))) throw new Error("Некорректный выбор MCP");
  const selectedSet = new Set(selected);
  const nonce = random();
  const csrf = random();
  const scriptNonce = random();
  let settled = false;
  let processing = false;
  let accept, reject;
  const result = new Promise((yes, no) => { accept = yes; reject = no; });
  const server = createServer(async (request, response) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const path = `/secret/${nonce}`;
    const headers = { "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${scriptNonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` };
    const explain = (status, title, message, retry = null) => response.writeHead(status, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(resultPage({ kind: "warning", title, message, retry }));
    if (request.url !== path || request.headers.host !== `127.0.0.1:${server.address().port}`) { explain(404, "Страница не найдена", "Вернитесь в приложение и выполните /mcps_load ещё раз."); return; }
    if (request.method === "GET") {
      response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(page(items, selectedSet, path, csrf, scriptNonce));
      return;
    }
    // Some local browsers omit Origin (or send "null") for form submissions.
    // The unguessable form token provides CSRF protection in those cases.
    if (request.method !== "POST" || (request.headers.origin && request.headers.origin !== origin && request.headers.origin !== "null") || request.headers["content-type"]?.split(";")[0] !== "application/x-www-form-urlencoded") { explain(403, "Отправка не принята", "Откройте форму через /mcps_load в приложении и отправьте её из той же вкладки."); return; }
    let input = "";
    try {
      for await (const chunk of request) {
        input += chunk;
        if (input.length > 65536) { explain(413, "Данные слишком большие", "Проверьте длину введённых токенов и повторите отправку.", path); return; }
      }
    } catch { if (!response.writableEnded) explain(400, "Отправка прервалась", "Откройте форму снова и повторите отправку.", path); return; }
    const form = new URLSearchParams(input);
    if (form.getAll("csrf").length !== 1 || form.get("csrf") !== csrf) { explain(403, "Форма устарела", "Вернитесь в приложение и выполните /mcps_load ещё раз."); return; }
    const ids = form.getAll("mcp");
    const known = new Set(items.map((item) => item.id));
    const validKeys = new Set(["csrf", "mcp", ...items.map((item) => `token:${item.id}`)]);
    const tokens = new Map();
    let invalid = ids.length > items.length || new Set(ids).size !== ids.length || ids.some((id) => !known.has(id)) || [...form.keys()].some((key) => !validKeys.has(key));
    for (const item of items) {
      const values = form.getAll(`token:${item.id}`);
      if (values.length > 1 || values.some((value) => value.length > maxToken || /[\r\n]/.test(value))) { invalid = true; continue; }
      const value = values[0] ?? "";
      if (ids.includes(item.id)) {
        if (value) tokens.set(item.id, value);
        else if (!selectedSet.has(item.id)) invalid = true;
      } else if (value) invalid = true;
    }
    if (invalid) {
      explain(400, "Проверьте выбор MCP", "Для каждого нового MCP нужен токен. Вернитесь к форме, проверьте отметки и введите токены снова.", path);
      return;
    }
    if (settled || processing) { explain(409, "Подключение уже выполняется", "Дождитесь результата в первой вкладке. Если он не появится, выполните /mcps_load ещё раз."); return; }
    processing = true;
    try {
      const outcome = await onSubmit?.(ids, tokens);
      if (!settled) {
        response.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(resultPage(outcome));
        settled = true;
        accept({ ids, tokens });
      }
    } catch (error) {
      if (!settled) {
        response.writeHead(500, { ...headers, "Content-Type": "text/html; charset=utf-8" }).end(resultPage({ kind: "error", title: "Не удалось завершить подключение", message: "Проверьте OpenCode или Kilo и повторите /mcps_load." }));
        settled = true;
        reject(error);
      }
    } finally { server.close(); }
  });
  await new Promise((resolve, fail) => { server.once("error", fail); server.listen(0, "127.0.0.1", resolve); });
  const timer = setTimeout(() => { if (!settled) { settled = true; reject(new Error("Время настройки MCP истекло")); server.close(); } }, timeoutMs);
  timer.unref();
  result.finally(() => clearTimeout(timer)).catch(() => {});
  return { url: `http://127.0.0.1:${server.address().port}/secret/${nonce}`, result, cancel: () => { if (!settled) { settled = true; reject(new Error("Настройка MCP отменена")); server.close(); } } };
}
