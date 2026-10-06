# Trifecta Gate — stop AI assistants from sending your files to whoever asks

An AI agent that can **read private data**, **read text written by outsiders** and **send data out** has the
"lethal trifecta" (Simon Willison's term, 2025): one planted sentence in an email, a web page or a shared document can make it
mail your files to a stranger. Trifecta Gate

1. **finds** that combination in an agent's tool list before deployment and names the smallest change that breaks it, and
2. **blocks** the leak at run time with a provenance rule: an outgoing message may only go to an address the *user* chose —
   not one that appeared in content the agent read. It never asks a model whether text looks malicious.

**Live demo:** https://ryugi62.github.io/trifecta-gate/ (runs in your browser, no account) · built for
[2nd LaserHacks 2026](https://laserhacks2026.thescrs.org/) — *Securing the Next 250*.

<!-- NUMBERS -->
- **Live agent benchmark** (fictional town clerk's office; 84 planted attacks + 30 normal tasks per model, each run with and without the gate): secrets leaked to the attacker in **11 of 252** attack runs without the gate and **0 of 252** with it; the attacker was contacted at all in 21 vs 0. Normal tasks completed: 76/84 without, 77/84 with.
  - gpt-4o-mini: leaked 9/84 → 0/84; normal tasks 27/28 → 27/28; "reply to an outside sender" tasks needing confirmation: 0/2 completed without a click (by design).
  - gpt-5.4-mini: leaked 1/84 → 0/84; normal tasks 28/28 → 28/28; "reply to an outside sender" tasks needing confirmation: 0/2 completed without a click (by design).
  - gpt-4.1-nano: leaked 1/84 → 0/84; normal tasks 21/28 → 22/28; "reply to an outside sender" tasks needing confirmation: 0/2 completed without a click (by design).
- **Policy test** (scripted traces, no model): 168/168 attack traces blocked, 0/28 normal traces wrongly blocked, 2/2 "needs confirmation" traces held; decision time p95 0.044 ms.
- **Public MCP servers** (166 GitHub repositories named as MCP servers with extractable tools, 6,088 tool declarations): 23.5% have a tool that can send data out, 60.2% read private data, 36.1% return outsiders' text (independent LLM labeller; keyword rules give 45.2% / 65.7% / 53.0%). Servers with all three abilities on their own: **21** (flagged by both labellers; rules alone 54, LLM alone 23).
- **Label check**: on a held-out random sample of 100 public tools, the keyword rules agreed with an independent LLM labeller on 80.0% (private), 89.0% (outsiders' text) and 90.0% (send out) of labels; Cohen's kappa 0.42 / 0.38 / 0.45. The rules over-flag more than they miss (recall 0.8 and 0.71 on the two risky abilities).
<!-- /NUMBERS -->

## How the gate decides
| Rule | When | Decision |
|---|---|---|
| R1 | every destination was named by the user or is on the allowlist (`*.town.gov`) | allow |
| R2 | a destination came from content while private data is in the conversation | **block** (the agent is told to ask the user) |
| R3 | a destination came from content but nothing private has been read | allow — browsing keeps working |
| R4 | a ≥12-character piece of a private result is going to a destination the user did not name | **block** |

Destinations are e-mail addresses, URL hosts (a named parent domain covers its subdomains) and channel names. Tool abilities
come from keyword rules (`src/domain/classify.ts`); admins can override any tool's labels.

```ts
import { GateSession } from './src/application/session'
const gate = new GateSession(userRequest, ['*.town.gov'])
// before every tool call
const d = gate.check(toolSpec, args)        // { action: 'allow' | 'block', rule, reason }
// after every tool result
gate.record(toolSpec, resultText)
```

## What it does not do
- If the user names the recipient, the gate lets the message go even if the agent was tricked into adding extra data.
- Replying to someone who emailed you has the same shape as an attack, so it needs one confirmation.
- Keyword labels can be wrong; they lean toward flagging. See the agreement numbers above.

## Reproduce
```bash
npm ci
npm test && npm run typecheck && npm run layers
npm run bench:policy                          # scripted traces, no network
npx tsx scripts/bench-agent.ts gpt-4o-mini     # live agent benchmark (needs OPENAI_API_KEY)
npx tsx scripts/rejudge.ts data/agent-bench-gpt-4o-mini.jsonl
npx tsx scripts/scan-github.ts 250             # public MCP servers (gh CLI)
npx tsx scripts/export-web.ts && npm run build
```
Raw logs: `data/agent-bench-*.jsonl` (every tool call of every run), `data/policy-bench.json`, `data/scan.json`,
`data/labels-llm*.json*`. Spec: [SPEC.md](SPEC.md). The town, people and secrets in the benchmark are fictional.

## Layout
`src/domain` (labels, policy, fix finder — pure) ← `src/application` (gate session, benchmark world, extraction) ←
`src/adapters` (OpenAI agent loop) ← `scripts/`, `web/`. `npm run layers` enforces the direction.

MIT licence.
