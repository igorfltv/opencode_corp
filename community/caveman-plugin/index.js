import { readFile } from "node:fs/promises";

// OpenCode V2 adapter for the pinned Caveman ruleset. The upstream OpenCode
// installer still emits a V1 hook map, so it cannot be loaded by V2.
export default {
  id: "community.caveman",
  async setup(ctx) {
    const rules = await readFile(new URL("./rules.md", import.meta.url), "utf8");
    const mode = new Map();
    const prompt = await ctx.session.hook("prompt", (event) => {
      const message = event.prompt.text.trim().toLowerCase();
      if (/\b(stop caveman|normal mode|caveman off)\b/.test(message)) mode.set(event.sessionID, "off");
      else if (/\b(caveman ultra|ultracave)\b/.test(message)) mode.set(event.sessionID, "ultra");
      else if (/\b(caveman wenyan|megacave)\b/.test(message)) mode.set(event.sessionID, "wenyan");
      else if (/\b(caveman mode|turn on caveman|caveman on)\b/.test(message)) mode.set(event.sessionID, "on");
    });
    const context = await ctx.session.hook("context", (event) => {
      const current = mode.get(event.sessionID);
      if (!current || current === "off") return;
      event.system.push({ type: "text", text: rules });
      if (current === "ultra") event.system.push({ type: "text", text: "Caveman ultra: use brief fragments, while keeping all facts, exact code, commands, and user language." });
      if (current === "wenyan") event.system.push({ type: "text", text: "Caveman wenyan: use Classical Chinese only when the user has not specified another response language. Keep code and technical facts exact." });
    });
    const command = await ctx.command.transform((editor) => {
      editor.add({
        name: "caveman",
        description: "Caveman: on, off, ultra, wenyan или status для текущей сессии",
        async execute({ sessionID, prompt, delivery }) {
          const arg = prompt.text.toLowerCase().match(/\b(on|off|ultra|wenyan|status)\b/)?.[1] ?? "on";
          if (arg !== "status") mode.set(sessionID, arg);
          await ctx.session.prompt({ sessionID, text: `Caveman mode: ${mode.get(sessionID) ?? "off"}. Подтверди одной строкой.`, delivery });
        },
      });
    });
    return async () => {
      await Promise.all([prompt.dispose(), context.dispose(), command.dispose()]);
    };
  },
};
