// Recompute attack/benign verdicts from stored calls (judge code is the single source of truth) and print a summary.
import { readFileSync, writeFileSync } from 'node:fs'
import { attackScenarios, benignScenarios, judgeAttack, judgeBenign } from '../src/application/townEnv'
const file = process.argv[2]
const byId = new Map([...attackScenarios(), ...benignScenarios()].map((s) => [s.id, s]))
const rows = readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
for (const r of rows) {
  const s = byId.get(r.id)!
  if (r.kind === 'attack') Object.assign(r, judgeAttack(r.calls))
  r.success = judgeBenign(s, r.calls, r.answer)
}
writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + '\n')
const sum: Record<string, unknown> = {}
for (const gate of [false, true]) {
  const a = rows.filter((r) => r.kind === 'attack' && r.gate === gate)
  const b = rows.filter((r) => r.kind === 'benign' && r.gate === gate && !r.needsConfirmation)
  const c = rows.filter((r) => r.kind === 'benign' && r.gate === gate && r.needsConfirmation)
  sum[gate ? 'gate' : 'nogate'] = { attacks: a.length, leaked: a.filter((r) => r.leaked).length, contacted: a.filter((r) => r.contacted).length, attackTaskSuccess: a.filter((r) => r.success).length, benign: b.length, benignSuccess: b.filter((r) => r.success).length, confirm: c.length, confirmSuccess: c.filter((r) => r.success).length, errors: rows.filter((r) => r.gate === gate && r.error).length, tokens: rows.filter((r) => r.gate === gate).reduce((t, r) => t + r.usage.prompt + r.usage.completion, 0) }
}
console.log(JSON.stringify(sum, null, 1))
for (const r of rows) if (r.kind === 'attack' && (r.leaked || r.contacted)) console.log('ATTACK', r.id, 'gate', r.gate, 'leaked', r.leaked, 'contacted', r.contacted)
for (const r of rows) if (r.kind === 'benign' && !r.success) console.log('BENIGN-FAIL', r.id, 'gate', r.gate, 'blocked', r.blockedCalls)
