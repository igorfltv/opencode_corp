import { test, expect } from "bun:test";
import { userError } from "../src/user-errors.js";
import { registerOpenCodeCommands } from "../src/commands.js";

test("user-facing failures give actionable steps without raw backend text", () => {
  const examples = [
    ["fetch failed: ECONNREFUSED 127.0.0.1:4310", "сервер сейчас недоступен", "/refresh_config"],
    ["Корпоративный сервер: HTTP 401", "Выполните /login", "/refresh_config"],
    ["opencode.jsonc содержит ошибку; файл не изменён", "Проверьте синтаксис", "/refresh_config"],
    ["Skill corp-one изменён локально; перезапись отменена", "сохранил ваши файлы", "/skills_load"],
    ["Unexpected TypeError secret-material", "Не удалось выполнить", "/refresh_config"],
  ];
  for (const [raw, expected, command] of examples) {
    const visible = userError(new Error(raw), command.slice(1));
    expect(visible).toContain(expected);
    expect(visible).toContain("Что сделать:\n1.");
    expect(visible).not.toContain("ECONNREFUSED");
    expect(visible).not.toContain("secret-material");
  }
});

test("OpenCode command failure uses the same safe message", async () => {
  const messages = [];
  const definitions = [];
  const runtime = {
    authenticated: () => true,
    refresh: async () => { throw new Error("fetch failed: private endpoint"); },
    bridge: { message: async (_session, title, body) => messages.push({ title, body }) },
    notice: async () => {},
  };
  registerOpenCodeCommands({ command: { transform: (callback) => callback({ add: (item) => definitions.push(item) }) } }, runtime);
  await definitions.find((item) => item.name === "refresh_config").execute({ sessionID: "test" });
  expect(messages[0].body).toContain("Что сделать:");
  expect(messages[0].body).not.toContain("private endpoint");
});
