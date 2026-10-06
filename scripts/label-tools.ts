// Independent labeller for classifier validation: a separate LLM call labels each sampled tool's legs from its definition only.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
const env = `OPENAI_API_KEY=${process.env.OPENAI_API_KEY ?? ''}`
const apiKey = env.match(/OPENAI_API_KEY=(\S+)/)?.[1]?.replace(/^["']|["']$/g, '') ?? ''
const scan = JSON.parse(readFileSync('data/scan.json', 'utf8'))
const all: Array<{ repo: string; name: string; description: string; params: string[] }> = []
for (const s of scan.servers) for (const t of s.specs) all.push({ repo: s.repo, ...t })
// deterministic shuffle (mulberry32, seed 2026)
let a = 2026
const rnd = () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296 }
const idx = all.map((_, i) => i).sort(() => rnd() - 0.5)
const sample = idx.slice(0, 200).map((i, k) => ({ ...all[i], split: k < 100 ? 'dev' : 'test' }))
const out = 'data/labels-llm.json'
if (process.argv[2] === 'fresh' && existsSync(out)) writeFileSync(out, '[]')
const prev = existsSync(out) ? JSON.parse(readFileSync(out, 'utf8')) : []
const done = new Map(prev.map((x: { repo: string; name: string }) => [`${x.repo}/${x.name}`, x]))
const DEF = `Label an AI-agent tool with zero or more of three abilities, judging only from its definition. Be strict: label an ability only if the definition clearly implies it.
- private: its OUTPUT gives the agent non-public data belonging to the user or their organisation (their mail, files, messages, calendar, customer/financial/health records, internal tickets, private code, account details). Tools that only change things, control software, or return public/reference data are NOT private.
- untrusted: its OUTPUT can include free text written by people outside the organisation (web pages, search results, inbound email or messages, public issues/comments/reviews, third-party documents, social posts).
- outbound: it can deliver agent-chosen content to people or systems outside the organisation, or to an arbitrary address chosen in its arguments (send email/message, post/publish/comment publicly, upload, HTTP request to a URL given in arguments, webhook).
Answer JSON only: {"private":bool,"untrusted":bool,"outbound":bool}`
const res: unknown[] = [...prev]
let i = 0
async function worker() {
  while (i < sample.length) {
    const t = sample[i++]
    if (done.has(`${t.repo}/${t.name}`)) continue
    const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST', headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'gpt-5.4-mini', response_format: { type: 'json_object' }, messages: [{ role: 'system', content: DEF }, { role: 'user', content: `Server repository: ${t.repo}\nTool name: ${t.name}\nDescription: ${t.description}\nParameters: ${t.params.join(', ') || '(none)'}` }] }) })
    const j = await r.json() as { choices?: Array<{ message: { content: string } }> }
    try { res.push({ ...t, llm: JSON.parse(j.choices![0].message.content) }) } catch { console.error('fail', t.name) }
  }
}
await Promise.all(Array.from({ length: 4 }, worker))
writeFileSync(out, JSON.stringify(res, null, 1))
console.log('labelled', res.length)
