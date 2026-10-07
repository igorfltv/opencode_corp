import { readJSON, sleep } from "./io.js";

// The company launcher supplies the connection to its own OpenCode process.
// Credentials never enter model context, remote requests, or notification text.
export class OpenCodeBridge {
  constructor(connectionFile) { this.connectionFile = connectionFile; }
  async request(path, { method = "GET", body, signal } = {}) {
    const connection = await readJSON(this.connectionFile);
    if (!connection) throw new Error("Запустите демопрофиль через bun run demo: нет соединения с OpenCode");
    const url = new URL(connection.url);
    if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password) throw new Error("Неверный локальный адрес OpenCode");
    const result = await fetch(`${url.origin}${path}`, {
      method, redirect: "error", signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(5000)]) : AbortSignal.timeout(5000),
      headers: { Authorization: `Basic ${Buffer.from(`opencode:${connection.password}`).toString("base64")}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!result.ok) throw new Error(`OpenCode API: HTTP ${result.status}`);
    return result.status === 204 ? null : result.json();
  }
  async form(sessionID, title, fields) {
    // OpenCode 2.0.24 desktop renders question forms only; generic forms remain API-only.
    const { data } = await this.request(`/api/session/${encodeURIComponent(sessionID)}/form`, { method: "POST", body: { title, metadata: { kind: "question" }, fields } });
    return data;
  }
  message(sessionID, title, description) {
    return this.form(sessionID, title, [{ type: "string", key: "ack", title, description, custom: false, options: [{ value: "ok", label: "Понятно" }] }]);
  }
  async wait(sessionID, formID, signal) {
    const path = `/api/session/${encodeURIComponent(sessionID)}/form/${encodeURIComponent(formID)}`;
    while (!signal?.aborted) {
      const { data } = await this.request(path, { signal });
      if (data.state.status === "answered") return data.state.answer;
      if (data.state.status === "cancelled") return null;
      await sleep(400, signal);
    }
    return null;
  }
  async cancel(sessionID, formID) {
    await this.request(`/api/session/${encodeURIComponent(sessionID)}/form/${encodeURIComponent(formID)}`, { method: "DELETE" }).catch(() => {});
  }
}
