export class Unauthorized extends Error { constructor() { super("Сессия истекла. Выполните /login"); } }
export class CorporateAPI {
  constructor(baseURL) { this.baseURL = baseURL; }
  async request(path, { token, method = "GET", body, etag, signal } = {}) {
    const response = await fetch(`${this.baseURL}${path}`, {
      method, redirect: "error",
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10000)]) : AbortSignal.timeout(10000),
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { "Content-Type": "application/json" } : {}), ...(etag ? { "If-None-Match": etag } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (response.status === 401) throw new Unauthorized();
    if (response.status === 304) return { unchanged: true, etag };
    if (!response.ok) throw new Error(`Корпоративный сервер: HTTP ${response.status}`);
    const text = await response.text();
    if (text.length > 1048576) throw new Error("Ответ сервера слишком большой");
    return { data: text ? JSON.parse(text) : null, etag: response.headers.get("etag") };
  }
}
