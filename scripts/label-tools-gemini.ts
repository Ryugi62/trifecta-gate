// Second labeller from a different vendor (Gemini) on the same 200-tool sample, same rubric as label-tools.ts.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
const key = process.env.GEMINI_API_KEY ?? ''
if (!key) throw new Error('GEMINI_API_KEY missing')
const src = readFileSync('scripts/label-tools.ts', 'utf8')
const DEF = src.slice(src.indexOf('const DEF = `') + 13, src.indexOf('`', src.indexOf('const DEF = `') + 13))
const rows = JSON.parse(readFileSync('data/labels-llm.json', 'utf8')) as Array<{ repo: string; name: string; description: string; params: string[]; split: string; llm: unknown }>
const out = 'data/labels-gemini.json'
const prev: Array<Record<string, unknown>> = existsSync(out) ? JSON.parse(readFileSync(out, 'utf8')) : []
const done = new Set(prev.map((r) => `${r.repo}/${r.name}`))
const res = [...prev]
for (const t of [...rows.filter((r) => r.split === 'test'), ...rows.filter((r) => r.split !== 'test')]) {
  if (done.has(`${t.repo}/${t.name}`)) continue
  for (let attempt = 0; attempt < 6; attempt++) {
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', { method: 'POST', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: process.env.GEMINI_MODEL ?? 'gemini-3-flash-preview', response_format: { type: 'json_object' }, messages: [{ role: 'system', content: DEF }, { role: 'user', content: `Server repository: ${t.repo}\nTool name: ${t.name}\nDescription: ${t.description}\nParameters: ${t.params.join(', ') || '(none)'}` }] }) })
    if (r.status === 429 || r.status >= 500) { await new Promise((z) => setTimeout(z, 8000 * (attempt + 1))); continue }
    const j = await r.json() as { choices?: Array<{ message: { content: string } }> }
    try { const txt = j.choices![0].message.content.replace(/^```json\s*|```\s*$/g, ''); res.push({ repo: t.repo, name: t.name, split: t.split, model: process.env.GEMINI_MODEL ?? 'gemini-3-flash-preview', gemini: JSON.parse(txt) }) } catch { console.error('fail', t.name) }
    break
  }
  await new Promise((z) => setTimeout(z, 4000))
  if (res.length % 20 === 0) writeFileSync(out, JSON.stringify(res, null, 1))
}
writeFileSync(out, JSON.stringify(res, null, 1))
console.log('labelled', res.length)
