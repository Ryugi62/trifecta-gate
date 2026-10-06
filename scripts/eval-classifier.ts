import { readFileSync, writeFileSync } from 'node:fs'
import { classifyTool } from '../src/domain/classify'
import { LEGS } from '../src/domain/types'
const rows = JSON.parse(readFileSync('data/labels-llm.json', 'utf8')) as Array<{ name: string; description: string; params: string[]; split: string; repo: string; llm: Record<string, boolean> }>
const split = process.argv[2] ?? 'test'
const S = rows.filter((r) => r.split === split)
const report: Record<string, unknown> = { split, n: S.length }
for (const leg of LEGS) {
  let tp = 0, fp = 0, fn = 0, tn = 0
  for (const r of S) { const p = classifyTool(r).legs.has(leg); const g = !!r.llm[leg]; if (p && g) tp++; else if (p) fp++; else if (g) fn++; else tn++ }
  const n = tp + fp + fn + tn, po = (tp + tn) / n, pe = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / (n * n)
  report[leg] = { tp, fp, fn, tn, precision: +(tp / Math.max(1, tp + fp)).toFixed(2), recall: +(tp / Math.max(1, tp + fn)).toFixed(2), agreement: +po.toFixed(2), kappa: +((po - pe) / (1 - pe)).toFixed(2) }
}
console.log(JSON.stringify(report, null, 1))
writeFileSync(`data/classifier-eval-${split}.json`, JSON.stringify(report, null, 1))
if (process.argv[3] === 'show') for (const r of S) { const p = classifyTool(r).legs; const diff = LEGS.filter((l) => p.has(l) !== !!r.llm[l]); if (diff.length) console.log(diff.map((l) => (p.has(l) ? '+' : '-') + l).join(' '), '|', r.name, '|', r.description.slice(0, 110), '|', r.params.join(',')) }
