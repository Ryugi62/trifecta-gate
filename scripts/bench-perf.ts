// Gate cost with realistic private data: 5 x 1 MB documents, a 9 KB outgoing body.
import { performance } from 'node:perf_hooks'
import { GateSession } from '../src/application/session'
const doc = { name: 'read_document', description: 'Read a document from the town drive', params: ['path'] }
const send = { name: 'send_email', description: 'Send an email to a recipient', params: ['to', 'body'] }
const rnd = (n: number, seed: number) => { let x = seed * 2654435761 >>> 0 || 1; const a: string[] = []; for (let i = 0; i < n; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; a.push("abcdefghijklmnopqrstuvwxyz0123456789 "[x % 37]) } return a.join("") }
const g = new GateSession('email ops@maplefalls.gov the summary', { now: () => performance.now() })
let t0 = performance.now()
for (let i = 0; i < 5; i++) g.record(doc, rnd(1_000_000, i + 1))
const recordMs = performance.now() - t0
const body = rnd(9_000, 99)
const times: number[] = []
for (let i = 0; i < 50; i++) { t0 = performance.now(); g.check(send, { to: i % 2 ? 'ops@maplefalls.gov' : 'eve@evil.example', body }); times.push(performance.now() - t0) }
times.sort((a, b) => a - b)
// false matches: fresh random bodies that share nothing with the private text
let falseHits = 0
for (let i = 0; i < 50; i++) if (g.taint.secrets.find({ body: rnd(9_000, 1000 + i) })) falseHits++
const out = { privateBytes: 5_000_000, bodyBytes: 9_000, recordMsTotal: +recordMs.toFixed(0), checkMsP50: +times[25].toFixed(2), checkMsP95: +times[47].toFixed(2), fingerprints: g.taint.secrets.size, falseMatchBodies: falseHits, falseMatchTrials: 50 }
console.log(JSON.stringify(out))
import { writeFileSync } from 'node:fs'
writeFileSync('data/perf.json', JSON.stringify(out, null, 1))
