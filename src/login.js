import { createHash, timingSafeEqual } from "node:crypto";
import { random } from "./io.js";

export async function startLogin(api, { timeoutMs = 300000 } = {}) {
  const state = random();
  const verifier = random();
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  let resolve, reject, consumed = false, timer;
  const controller = new AbortController();
  const result = new Promise((yes, no) => { resolve = yes; reject = no; });
  result.catch(() => {});
  const server = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const received = url.searchParams.get("state") ?? "";
      if (request.method !== "GET" || url.pathname !== "/callback" || consumed || !/^[A-Za-z0-9_-]{43}$/.test(received) || !timingSafeEqual(Buffer.from(received), Buffer.from(state))) return new Response("Invalid callback", { status: 400 });
      consumed = true;
      try {
        const token = await api.request("/oauth/token", { method: "POST", body: { code: url.searchParams.get("code"), verifier, redirectURI }, signal: controller.signal });
        resolve(token.data);
        return new Response("Вход подтверждён. Вернитесь в приложение.", { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
      } catch (error) { reject(error); return new Response("Вход не завершён. Повторите вход в приложении.", { status: 400 }); }
      finally { clearTimeout(timer); setTimeout(() => server.stop(true), 100).unref(); }
    },
  });
  const redirectURI = `http://127.0.0.1:${server.port}/callback`;
  const cancel = () => { clearTimeout(timer); controller.abort(); server.stop(true); reject(new Error("Вход отменён или время ожидания истекло")); };
  try {
    const { data } = await api.request("/oauth/requests", { method: "POST", body: { state, challenge, redirectURI }, signal: controller.signal });
    if (new URL(data.authorizationURL).origin !== new URL(api.baseURL).origin) throw new Error("Сервер вернул неожиданный адрес входа");
    timer = setTimeout(cancel, timeoutMs);
    timer.unref();
    return { url: data.authorizationURL, result, cancel };
  } catch (error) { cancel(); throw error; }
}
