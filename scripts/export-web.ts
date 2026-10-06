// Build web/public/results.json from the benchmark and scan outputs (single source for the page, README and slides).
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { analyzeToolset, suggestFix } from '../src/domain/classify'
import { attackScenarios, injectionText } from '../src/application/townEnv'
import { LEGS, type Leg } from '../src/domain/types'

const MODELS = ['gpt-4o-mini', 'gpt-5.4-mini', 'gpt-4.1-nano']
const HEAD = 'gpt-4o-mini'
const REPLAY = 'A-shared_doc-url-blended'
const rows = (m: string) => readFileSync(`data/agent-bench-${m}.jsonl`, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
const models = MODELS.map((m) => {
  const r = rows(m)
  const a = (g: boolean) => r.filter((x) => x.kind === 'attack' && x.gate === g)
  const b = (g: boolean) => r.filter((x) => x.kind === 'benign' && x.gate === g && !x.needsConfirmation)
  const c = (g: boolean) => r.filter((x) => x.kind === 'benign' && x.gate === g && x.needsConfirmation)
  return { model: m, attacks: a(false).length, leakedNoGate: a(false).filter((x) => x.leaked).length, leakedGate: a(true).filter((x) => x.leaked).length,
    contactedNoGate: a(false).filter((x) => x.contacted).length, contactedGate: a(true).filter((x) => x.contacted).length,
    userTaskUnderAttackNoGate: a(false).filter((x) => x.success).length, userTaskUnderAttackGate: a(true).filter((x) => x.success).length,
    benign: b(false).length, benignNoGate: b(false).filter((x) => x.success).length, benignGate: b(true).filter((x) => x.success).length,
    confirm: c(false).length, confirmNoGate: c(false).filter((x) => x.success).length, confirmGate: c(true).filter((x) => x.success).length }
})
const h = models.find((m) => m.model === HEAD)!
const hr = rows(HEAD)
const sc = attackScenarios().find((s) => s.id === REPLAY)!
const pick = (g: boolean) => hr.find((x) => x.id === REPLAY && x.gate === g).calls.map((c: { tool: string; args: Record<string, unknown>; blocked: boolean }) => ({ tool: c.tool, blocked: c.blocked, args: Object.fromEntries(Object.entries(c.args).map(([k, v]) => [k, typeof v === 'string' ? v.slice(0, 160) : v])) }))

const scan = JSON.parse(readFileSync('data/scan.json', 'utf8'))
const servers = scan.servers as Array<{ repo: string; stars: number; specs: Array<{ name: string; description: string; params: string[] }> }>
const llm = new Map<string, Record<Leg, boolean>>()
if (existsSync('data/labels-llm-all.jsonl')) for (const l of readFileSync('data/labels-llm-all.jsonl', 'utf8').split('\n').filter(Boolean)) { const r = JSON.parse(l); llm.set(`${r.repo}/${r.name}`, r.llm) }
const ruleAgg = servers.map((s) => ({ s, a: analyzeToolset(s.specs) }))
const share = (f: (x: typeof ruleAgg[number]) => boolean) => +(ruleAgg.filter(f).length / servers.length).toFixed(3)
const rulesShare = Object.fromEntries(LEGS.map((l) => [l, share((x) => x.a.providers[l].length > 0)])) as Record<Leg, number>
const llmCover = servers.every((s) => s.specs.every((t) => llm.has(`${s.repo}/${t.name}`)))
const llmLegs = (s: typeof servers[number]) => Object.fromEntries(LEGS.map((l) => [l, s.specs.some((t) => llm.get(`${s.repo}/${t.name}`)?.[l])])) as Record<Leg, boolean>
const llmShare = llmCover ? Object.fromEntries(LEGS.map((l) => [l, +(servers.filter((s) => llmLegs(s)[l]).length / servers.length).toFixed(3)])) as Record<Leg, number> : null
const triRules = ruleAgg.filter((x) => x.a.trifecta)
const triLlm = llmCover ? servers.filter((s) => LEGS.every((l) => llmLegs(s)[l])) : []
const triBoth = triRules.filter((x) => triLlm.some((s) => s.repo === x.s.repo))
const res = {
  generatedAt: new Date().toISOString(),
  headline: { model: HEAD, attacks: h.attacks, leakedNoGate: h.leakedNoGate, leakedGate: h.leakedGate, benign: h.benign, benignNoGate: h.benignNoGate, benignGate: h.benignGate },
  totals: { attacks: models.reduce((t, m) => t + m.attacks, 0), leakedNoGate: models.reduce((t, m) => t + m.leakedNoGate, 0), leakedGate: models.reduce((t, m) => t + m.leakedGate, 0), contactedNoGate: models.reduce((t, m) => t + m.contactedNoGate, 0), contactedGate: models.reduce((t, m) => t + m.contactedGate, 0), benign: models.reduce((t, m) => t + m.benign, 0), benignNoGate: models.reduce((t, m) => t + m.benignNoGate, 0), benignGate: models.reduce((t, m) => t + m.benignGate, 0) },
  models,
  policy: JSON.parse(readFileSync('data/policy-bench.json', 'utf8')).summary,
  scan: {
    candidates: scan.candidates, servers: servers.length, tools: servers.reduce((t, s) => t + s.specs.length, 0),
    share: llmShare ?? rulesShare, labeller: llmShare ? 'llm' : 'rules', rulesShare, llmShare,
    trifectaServers: llmShare ? triBoth.length : triRules.length, trifectaRules: triRules.length, trifectaLlm: llmCover ? triLlm.length : null,
    examples: (llmShare ? triBoth : triRules).slice(0, 30).map((x) => ({ repo: x.s.repo, stars: x.s.stars, fix: suggestFix(x.s.specs) })),
  },
  classifier: existsSync('data/classifier-eval-test.json') ? JSON.parse(readFileSync('data/classifier-eval-test.json', 'utf8')) : null,
  replay: { id: REPLAY, model: HEAD, instruction: sc.instruction, injection: injectionText(sc.channel!, sc.style!), noGate: pick(false), gate: pick(true) },
}
writeFileSync('web/public/results.json', JSON.stringify(res, null, 1))
console.log(JSON.stringify({ headline: res.headline, totals: res.totals, scan: { ...res.scan, examples: res.scan.examples.length } }, null, 1))
