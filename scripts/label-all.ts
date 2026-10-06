// Label every scanned tool with the same strict rubric as scripts/label-tools.ts (second, independent labelling of the scan).
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
const env = `OPENAI_API_KEY=${process.env.OPENAI_API_KEY ?? ''}`
const apiKey = env.match(/OPENAI_API_KEY=(\S+)/)?.[1]?.replace(/^["']|["']$/g, '') ?? ''
const src = readFileSync('scripts/label-tools.ts', 'utf8')
const DEF = src.slice(src.indexOf('const DEF = `') + 13, src.indexOf('`', src.indexOf('const DEF = `') + 13))
const scan = JSON.parse(readFileSync('data/scan.json', 'utf8'))
const all: Array<{ repo: string; name: string; description: string; params: string[] }> = []
for (const s of scan.servers) for (const t of s.specs) all.push({ repo: s.repo, ...t })
const out = 'data/labels-llm-all.jsonl'
const done = new Set<string>()
if (existsSync(out)) for (const l of readFileSync(out, 'utf8').split('\n').filter(Boolean)) { const r = JSON.parse(l); done.add(`${r.repo}/${r.name}`) }
let i = 0, n = 0
async function worker() {
  while (i < all.length) {
    const t = all[i++]
    if (done.has(`${t.repo}/${t.name}`)) continue
    for (let attempt = 0; attempt < 4; attempt++) {
      const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST', headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'gpt-5.4-mini', response_format: { type: 'json_object' }, messages: [{ role: 'system', content: DEF }, { role: 'user', content: `Server repository: ${t.repo}\nTool name: ${t.name}\nDescription: ${t.description}\nParameters: ${t.params.join(', ') || '(none)'}` }] }) })
      if (r.status === 429 || r.status >= 500) { await new Promise((z) => setTimeout(z, 3000 * (attempt + 1))); continue }
      const j = await r.json() as { choices?: Array<{ message: { content: string } }> }
      try { writeFileSync(out, JSON.stringify({ repo: t.repo, name: t.name, llm: JSON.parse(j.choices![0].message.content) }) + '\n', { flag: 'a' }); n++ } catch { /* skip */ }
      break
    }
  }
}
await Promise.all(Array.from({ length: 8 }, worker))
console.log('labelled', n, 'total', all.length)
