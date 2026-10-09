# Curated community packages

Pinned on 2026-10-08. The manifest records SHA-256 for every installed local
file. Review upstream changes before changing a pin or regenerating the manifest.

| Package | Source revision | Files and license |
|---|---|---|
| Superpowers | [obra/superpowers `8ca22dba9a94f28898bbce59f2537ff4d87c747d`](https://github.com/obra/superpowers/tree/8ca22dba9a94f28898bbce59f2537ff4d87c747d) | OpenCode installs the Git plugin directly; upstream MIT. |
| Caveman | [JuliusBrussee/caveman `2e08b9177c07bb7249a8a2d1a6758e5db281d002`](https://github.com/JuliusBrussee/caveman/tree/2e08b9177c07bb7249a8a2d1a6758e5db281d002) | `skills/{caveman,ultracave,megacave}/SKILL.md` and `src/rules/caveman-activate.md`; [Apache-2.0 license](licenses/CAVEMAN-APACHE-2.0.txt). `caveman-plugin/index.js` is our OpenCode V2 adapter. |
| Grill me | [mattpocock/skills `b0618bc436ad893b3c5e84e55fba86586d34a404`](https://github.com/mattpocock/skills/tree/b0618bc436ad893b3c5e84e55fba86586d34a404) | `skills/productivity/{grill-me,grilling}/SKILL.md`; [MIT license](licenses/MATTPOCOCK-MIT.txt). |
| React Best Practices | [vercel-labs/agent-skills `063bee94c3f4df8453406c830b0a7df0f2860278`](https://github.com/vercel-labs/agent-skills/tree/063bee94c3f4df8453406c830b0a7df0f2860278) | `skills/react-best-practices/{SKILL.md,AGENTS.md,rules/*}`; SKILL.md declares MIT. |

Selection is opt-in. Superpowers and Caveman affect agent behavior across
sessions when their plugins are active. Grill me and the React skill load on
demand through the native skill tool.
