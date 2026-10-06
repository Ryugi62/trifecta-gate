// Keyword rules vs two independent LLM labellers (OpenAI gpt-5.4-mini, Google gemini-2.5-flash) on a random sample of public MCP tools.
// usage: tsx scripts/eval-classifier.ts <dev|test|all> [show]
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { classifyTool } from '../src/domain/classify'
import { LEGS, type Leg } from '../src/domain/types'

type Row = { name: string; description: string; params: string[]; split: string; repo: string; llm: Record<string, boolean>; gemini?: Record<string, boolean> }
const rows = JSON.parse(readFileSync('data/labels-llm.json', 'utf8')) as Row[]
if (existsSync('data/labels-gemini.json')) {
  const g = new Map((JSON.parse(readFileSync('data/labels-gemini.json', 'utf8')) as Array<{ repo: string; name: string; gemini: Record<string, boolean> }>).map((x) => [`${x.repo}/${x.name}`, x.gemini]))
  for (const r of rows) r.gemini = g.get(`${r.repo}/${r.name}`)
}
const split = process.argv[2] ?? 'test'
const S = rows.filter((r) => split === 'all' || r.split === split)

function wilson(k: number, n: number): [number, number] {
  if (n === 0) return [0, 1]
  const z = 1.96, p = k / n, d = 1 + z * z / n, c = p + z * z / (2 * n), m = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
  return [+((c - m) / d).toFixed(2), +((c + m) / d).toFixed(2)]
}
function compare(pred: (r: Row) => boolean, gold: (r: Row) => boolean | undefined) {
  let tp = 0, fp = 0, fn = 0, tn = 0
  for (const r of S) { const g = gold(r); if (g === undefined) continue; const p = pred(r); if (p && g) tp++; else if (p) fp++; else if (g) fn++; else tn++ }
  const n = tp + fp + fn + tn, po = (tp + tn) / Math.max(1, n), pe = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / Math.max(1, n * n)
  return { n, positives: tp + fn, tp, fp, fn, tn, precision: +(tp / Math.max(1, tp + fp)).toFixed(2), recall: +(tp / Math.max(1, tp + fn)).toFixed(2), recallCI95: wilson(tp, tp + fn), agreement: +po.toFixed(2), kappa: +((po - pe) / Math.max(1e-9, 1 - pe)).toFixed(2) }
}
const legsOf = (r: Row) => classifyTool(r).legs
const report: Record<string, unknown> = { split, n: S.length, note: 'rules frozen before this split was scored, except vocabulary added after the mock review (exec/delivery/health words) — see git history' }
for (const leg of LEGS as readonly Leg[]) {
  report[leg] = {
    rulesVsOpenAI: compare((r) => legsOf(r).has(leg), (r) => !!r.llm[leg]),
    rulesVsGemini: compare((r) => legsOf(r).has(leg), (r) => (r.gemini ? !!r.gemini[leg] : undefined)),
    openAIvsGemini: compare((r) => !!r.llm[leg], (r) => (r.gemini ? !!r.gemini[leg] : undefined)),
    // what the gate actually does: a tool with no label at all is treated as returning private data (fail closed)
    ...(leg === 'private' ? { gateEffectiveVsOpenAI: compare((r) => legsOf(r).has('private') || legsOf(r).size === 0, (r) => !!r.llm.private) } : {}),
  }
}
console.log(JSON.stringify(report, null, 1))
writeFileSync(`data/classifier-eval-${split}.json`, JSON.stringify(report, null, 1))
if (process.argv[3] === 'show') for (const r of S) { const p = legsOf(r); const diff = LEGS.filter((l) => p.has(l) !== !!r.llm[l]); if (diff.length) console.log(diff.map((l) => (p.has(l) ? '+' : '-') + l).join(' '), '|', r.name, '|', r.description.slice(0, 110)) }
