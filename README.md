# Trifecta Gate — stop AI assistants from sending your files to whoever asks

An AI agent that can **read private data**, **read text written by outsiders** and **send data out** has the
"lethal trifecta" (Simon Willison's term, 2025): one planted sentence in an email, a web page or a shared document can make it
send your files to a stranger. Trifecta Gate

1. **finds** that combination in an agent's tool list before deployment and names the smallest change that breaks it, and
2. **blocks** the leak at run time with a provenance rule: once private data is in play, an outgoing call may only reach a
   destination the *user* chose — not one that appeared in content the agent read. No language model sits inside the gate.

**Live demo:** https://ryugi62.github.io/trifecta-gate/ (in your browser, no account) · **Video (2:32):**
https://ryugi62.github.io/trifecta-gate/demo.mp4 · built for [2nd LaserHacks 2026](https://laserhacks2026.thescrs.org/) —
*Securing the Next 250*, the theme CISA chose for [Cybersecurity Awareness Month 2026](https://www.cisa.gov/news-events/news/cisa-launches-cybersecurity-awareness-month-securing-next-250).

<!-- NUMBERS -->
- **Live agent benchmark** (fictional town clerk's office; per model 84 planted attacks + 28 normal tasks + 2 tasks that need an address only found in outsiders' text; each run with and without the gate, one run per cell): secrets reached the attacker in **11 of 252** attack runs without the gate and **0 of 252** with it (one-sided Fisher exact p = 0.00044). With the gate, agents tried to contact the attacker 20 times and all 20 were blocked (95% upper bound on the per-attempt miss rate: 15%, rule of three).
- **Cost to normal work:** normal tasks completed 76/84 without and 75/84 with the gate; the gate blocked a call in 0 normal runs (the difference is model variance). The user's own task under attack: 212/252 without, 201/252 with the gate (a blocked step sometimes stops the agent). The 6 "reply to whoever emailed me" runs need one confirmation by design.
  - gpt-4o-mini: leaked 9/84 → 0/84; normal tasks 27/28 → 27/28.
  - gpt-5.4-mini: leaked 1/84 → 0/84; normal tasks 28/28 → 28/28.
  - gpt-4.1-nano: leaked 1/84 → 0/84; normal tasks 21/28 → 20/28.
- **Rule conformance** (scripted traces written for these rules, so not independent evidence): 168/168 attack traces blocked, 0/28 normal traces wrongly blocked. **Adaptive attacks** written against the rules after a review (shared hosts, file names as hosts, extra recipient fields, image links in bodies, ordinary words as channels, unlabelled shell tools, typed secrets, open redirects, re-cased and base64 secrets): all blocked — `tests/redteam.test.ts`.
- **Cost:** with 5 MB of private text read and a 9 KB outgoing body, a gate check takes 0.31 ms (p50) / 0.43 ms (p95); fingerprinting costs about 461 ms per MB read.
- **Public MCP servers** (311 GitHub repositories named as MCP servers → 166 with tool declarations our extractor could read → 6,088 tools): 23.5% of servers have a tool that can send data out, 60.2% read private data, 36.1% return outsiders' text (independent LLM labeller; keyword rules: 60.2% / 72.9% / 60.8%). **22** servers have all three on their own (both labellers agree; rules alone 76, LLM alone 23). Sample: sorted by stars, so it over-represents popular servers.
- **Label check** (held-out random sample of 100 public tools vs an independent LLM labeller, gpt-5.4-mini): private: recall 0.52 (95% CI 0.33–0.7, 25 positives), precision 0.59, kappa 0.42; untrusted: recall 0.8 (95% CI 0.38–0.96, 5 positives), precision 0.27, kappa 0.35; outbound: recall 0.71 (95% CI 0.36–0.92, 7 positives), precision 0.28, kappa 0.33. Because unlabelled tools fail closed, the gate treats 0.8 of private tools as private. Keyword labels are a starting point; admins should review them.
<!-- /NUMBERS -->

## How the gate decides
| Rule | When | Decision |
|---|---|---|
| R1 | every destination was written by the user (any turn), is on the admin allowlist, or the user confirmed it | allow |
| R2 | a destination did not come from the user while private data is in play | **block**; the gate writes the confirmation prompt, naming where the address first appeared |
| R3 | no private data in play yet (`startPrivate: true` makes the conversation private from the start) | allow (browsing keeps working) |
| R4 | fingerprints of private data (12-character runs, passwords, IDs) appear in the call — case-folded, URL/base64/hex-decoded, joined across fields — and the destination is weakly trusted or not trusted | **block** |
| R5 | the tool only writes to the user's own workspace (calendar entry, file) with no outside recipient | allow |
| R6 | a fetch-only tool visits a plain link (no query string, not a shared platform) that carries no private fingerprint | allow |

- **Destinations** are e-mail addresses, channels and URLs in *any* argument, including links inside message bodies (link previews
  and images fetch them) and URLs nested in query strings (open redirects).
- **Trust is narrow:** an exact URL the user wrote; a host the user named, for that host only and without query strings; never a
  shared platform (docs.google.com, github.com, webhook relays…) unless the admin allowlists it; channels only when marked
  (`#council`, "council channel"); file names such as `readme.md` are not hosts.
- **Fail closed:** tools the keyword rules cannot label are treated as returning private data, and any address in their
  arguments as an outgoing destination. Shell/exec tools are labelled private + outbound. MCP `openWorldHint` is honoured.
  Admins can override any label.
- **No raw private text is kept**: only hashed fingerprints. Reasons, prompts and logs never quote a secret or a query string.

```ts
import { GateSession } from './src/application/session'
const gate = new GateSession(userMessage, { allowlist: ['*.town.gov'] })
const d = gate.check(toolSpec, args)   // before every tool call -> { action, rule, reason, confirmPrompt }
gate.record(toolSpec, resultText)      // after every tool result
gate.addUserTurn(nextMessage)          // multi-turn
gate.confirm('chief@maplefalls.gov')   // the user approved one exact destination
gate.unsafeAnswerLinks(finalAnswer)    // links/images in the reply that would leak
```

## Two ways to deploy
- **Host middleware (sees the user's request — full rules).** `src/adapters/openaiAgent.ts` wraps an OpenAI function-calling loop.
- **Drop-in MCP proxy (one config line, allowlist + confirmations).** MCP carries no user message, so the proxy trusts only the
  allowlist and confirmed destinations; everything else follows the same rules.
```jsonc
// before: "command": "node", "args": ["mail-server.js"]
"command": "npx", "args": ["tsx", "scripts/mcp-proxy.ts", "--allow", "*.town.gov", "--log", "audit.jsonl", "--", "node", "mail-server.js"]
```
The proxy learns tool specs from `tools/list`, records results, holds any call that arrives before the previous result is
recorded, answers blocked calls with an MCP error, and writes a **hash-chained JSON audit log** (`scripts/verify-audit.ts`
checks the chain). `npm run e2e:proxy` runs it against a fake server.

## Threat model
- **Attacker:** writes content the agent reads (email, web page, shared document, calendar invite, issue). Cannot change the
  user's messages, the allowlist, the gate or the tool servers.
- **Asset:** anything returned by a tool labelled private, plus secrets the user types.
- **Blocked goal:** moving that data to a destination the attacker chose — by e-mail (to/cc/bcc/any field), chat, URL path or
  query, link preview, rendered image, or redirect.
- **Out of scope:** a compromised tool server, side channels (timing), a user-named recipient receiving more than intended, and
  text the user pastes into their own message (it counts as the user's words).
- **Standards:** OWASP Top 10 for LLM Applications 2025 — LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure,
  LLM06 Excessive Agency; MITRE ATLAS — AML.T0051.001 (indirect prompt injection), AML.T0057 (LLM data leakage).
  Audit events carry these IDs.

## Related work and what is different here
| Approach | What it does | Trade-off |
|---|---|---|
| CaMeL (Debenedetti et al., Google DeepMind, 2025) | rewrites the task as code from the trusted query and runs it in an interpreter with capabilities | strong guarantees; changes the agent, 77% vs 84% of AgentDojo tasks solved |
| FIDES (Costa, Köpf et al., Microsoft, 2025) | integrity and confidentiality labels on all content, deterministic policy | strong; needs label propagation through the agent framework |
| Agents Rule of Two (Meta, 2025) | design rule: at most two of the three abilities per session, else human approval | a design rule, not an enforcement mechanism |
| mcp-scan toxic flow analysis (Invariant Labs, 2025) | static scan of MCP set-ups for trifecta flows | reports risk, blocks nothing at run time |
| **Trifecta Gate** | enforces the Rule of Two only on the one flow that leaks — sends to destinations the user did not choose — at run time, plus a scanner | no agent rewrite, no model in the gate, drop-in proxy, normal tasks unchanged in our test; coarser than full information-flow control (cannot stop leaks to a user-named recipient) |

## Reproduce
```bash
npm ci && npm test && npm run typecheck && npm run layers
npm run bench:policy        # rule conformance on scripted traces (no network)
npm run bench:perf          # gate cost with 5 MB of private text
npm run e2e:proxy           # MCP proxy + audit-log chain check
OPENAI_API_KEY=... npx tsx scripts/bench-agent.ts gpt-4o-mini && npx tsx scripts/rejudge.ts data/agent-bench-gpt-4o-mini.jsonl
npx tsx scripts/scan-github.ts 250 && npx tsx scripts/eval-classifier.ts test
npx tsx scripts/export-web.ts && npx tsx scripts/readme-numbers.ts && npm run build
```
Raw logs: `data/agent-bench-*.jsonl` (every tool call of every run), `data/policy-bench.json`, `data/scan.json`,
`data/labels-*.json*`, `data/classifier-eval-*.json`, `data/perf.json`. Spec: [SPEC.md](SPEC.md). Adaptive attacks against the
rules: `tests/redteam.test.ts`. The town, people and secrets in the benchmark are fictional.

## Layout
`src/domain` (labels, policy, fingerprints — pure) ← `src/application` (gate session, MCP proxy core, extraction) ←
`src/adapters` (OpenAI agent loop) ← `scripts/`, `bench/` (benchmark world), `web/`. `npm run layers` checks the direction.

MIT licence.
