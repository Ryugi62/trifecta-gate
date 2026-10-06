import { writeFileSync } from 'node:fs'
import { performance } from 'node:perf_hooks'
import { runPolicyBench, summarize } from '../bench/policyBench'
const rs = runPolicyBench(() => performance.now())
const sum = summarize(rs)
writeFileSync('data/policy-bench.json', JSON.stringify({ ranAt: new Date().toISOString(), summary: sum, traces: rs }, null, 1))
console.log(JSON.stringify(sum, null, 1))
for (const r of rs) if ((r.kind === 'attack' && !r.blocked) || (r.kind === 'benign' && r.blocked)) console.log('MISS', r.id, r.rule)
