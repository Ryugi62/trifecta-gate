// Rewrite the per-tool labels stored in data/scan.json with the current keyword rules (the specs are unchanged).
import { readFileSync, writeFileSync } from 'node:fs'
import { analyzeToolset, suggestFix } from '../src/domain/classify'
const scan = JSON.parse(readFileSync('data/scan.json', 'utf8'))
for (const s of scan.servers) { const a = analyzeToolset(s.specs); s.tools = a.tools.map((t) => ({ name: t.tool, legs: [...t.legs], evidence: t.evidence })); s.providers = a.providers; s.trifecta = a.trifecta; s.fix = suggestFix(s.specs) }
scan.labelledWith = 'keyword rules at the commit that wrote this file; LLM labels in data/labels-llm-all.jsonl'
writeFileSync('data/scan.json', JSON.stringify(scan, null, 1))
console.log('servers', scan.servers.length, 'trifecta by rules', scan.servers.filter((s: { trifecta: boolean }) => s.trifecta).length)
