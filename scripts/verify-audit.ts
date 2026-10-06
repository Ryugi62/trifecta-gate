// Verify the hash chain of a proxy audit log. usage: tsx scripts/verify-audit.ts audit.jsonl
import { readFileSync } from 'node:fs'
import { createHash, createHmac } from 'node:crypto'
const key = process.env.TRIFECTA_AUDIT_KEY ?? ''
let prev = '0'.repeat(64), n = 0
for (const l of readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean)) {
  const { hash, ...event } = JSON.parse(l)
  if (event.prev_hash !== prev) { console.error(`chain broken at line ${n + 1}`); process.exit(1) }
  const h = (key ? createHmac('sha256', key) : createHash('sha256')).update(prev + JSON.stringify(event)).digest('hex')
  if (h !== hash) { console.error(`hash mismatch at line ${n + 1}`); process.exit(1) }
  prev = hash; n++
}
const lines = readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean)
const last = lines.length ? JSON.parse(lines[lines.length - 1]) : null
if (!last || last.event?.action !== 'session_end') { console.error('audit log chain intact but NOT closed: no session_end record (cut short, or the proxy is still running)'); process.exit(2) }
if (lines.some((l) => JSON.parse(l).keyed === false)) console.warn('note: unkeyed chain — set TRIFECTA_AUDIT_KEY so a writer cannot recompute it')
console.log(`audit log OK: ${n} events, chain intact, closed`)
