import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { runAgent } from '../src/adapters/openaiAgent'
import { attackScenarios, benignScenarios, judgeAttack, judgeBenign, type Scenario } from '../src/application/townEnv'

// usage: tsx scripts/bench-agent.ts <model> [limit] [only-id-substring]
const model = process.argv[2] ?? 'gpt-5.4-mini'
const limit = Number(process.argv[3] ?? 1e9)
const only = process.argv[4] ?? ''
const env = process.env.OPENAI_API_KEY ? `OPENAI_API_KEY=${process.env.OPENAI_API_KEY}` : readFileSync(`${process.env.HOME}/.config/jarvis/env/openai.env`, 'utf8')
const apiKey = env.match(/OPENAI_API_KEY=(\S+)/)?.[1]?.replace(/^["']|["']$/g, '') ?? ''
if (!apiKey) throw new Error('no key')
const all: Scenario[] = [...attackScenarios(), ...benignScenarios()].filter((s) => s.id.includes(only)).slice(0, limit)
const jobs = all.flatMap((s) => [false, true].map((gate) => ({ s, gate })))
mkdirSync('data', { recursive: true })
const outFile = `data/agent-bench-${model}.jsonl`
const done = new Set<string>()
if (existsSync(outFile)) for (const l of readFileSync(outFile, 'utf8').split('\n').filter(Boolean)) { const r = JSON.parse(l); done.add(`${r.id}|${r.gate}`) }
let i = 0
const results: string[] = []
async function worker() {
  while (i < jobs.length) {
    const { s, gate } = jobs[i++]
    if (done.has(`${s.id}|${gate}`)) continue
    const run = await runAgent(s, { gate, model, apiKey })
    const row = s.kind === 'attack'
      ? { id: s.id, kind: s.kind, gate, ...judgeAttack(run.calls), success: judgeBenign(s, run.calls, run.answer), blockedCalls: run.calls.filter((c) => c.blocked).length, calls: run.calls, answer: run.answer.slice(0, 400), error: run.error, usage: run.usage }
      : { id: s.id, kind: s.kind, needsConfirmation: !!s.needsConfirmation, gate, success: judgeBenign(s, run.calls, run.answer), blockedCalls: run.calls.filter((c) => c.blocked).length, calls: run.calls, answer: run.answer.slice(0, 400), error: run.error, usage: run.usage }
    const line = JSON.stringify(row)
    results.push(line)
    writeFileSync(outFile, line + '\n', { flag: 'a' })
    process.stdout.write(`${s.id} gate=${gate} ${'leaked' in row ? `leaked=${row.leaked} contacted=${row.contacted}` : ''} success=${row.success} blocked=${row.blockedCalls}${run.error ? ' ERR ' + run.error.slice(0, 80) : ''}\n`)
  }
}
await Promise.all(Array.from({ length: 6 }, worker))
console.log('done', results.length)
