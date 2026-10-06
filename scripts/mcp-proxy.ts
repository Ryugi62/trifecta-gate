#!/usr/bin/env -S npx tsx
// Drop-in MCP stdio proxy:
//   mcp-proxy [--allow "*.town.gov,clerk@town.gov"] [--labels labels.json] [--confirm-file confirmed.txt] [--log audit.jsonl] -- <server command> [args...]
// Put this command where your MCP client config names the server; it starts the real server as a child.
// --labels       admin labels per tool name, e.g. {"zap_trigger": ["outbound"]}
// --confirm-file one exact destination per line, written by the user's approval UI; re-read before every call
// --log          hash-chained JSON audit log; set TRIFECTA_AUDIT_KEY to make the chain an HMAC chain
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { appendFileSync, existsSync, readFileSync } from 'node:fs'
import { createHash, createHmac } from 'node:crypto'
import { ProxyCore } from '../src/application/proxyCore'
import type { Leg } from '../src/domain/types'
import { randomUUID } from 'node:crypto'
const SESSION = randomUUID()
const POLICY_VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version as string

const argv = process.argv.slice(2)
const sep = argv.indexOf('--')
if (sep < 0 || sep === argv.length - 1) { console.error('usage: mcp-proxy [--allow list] [--labels f] [--confirm-file f] [--log f] -- <server command> [args]'); process.exit(2) }
const opts = argv.slice(0, sep)
const opt = (name: string) => (opts.includes(name) ? opts[opts.indexOf(name) + 1] ?? '' : '')
const allow = opt('--allow').split(',').map((s) => s.trim()).filter(Boolean)
const labels: Record<string, Leg[]> = opt('--labels') ? JSON.parse(readFileSync(opt('--labels'), 'utf8')) : {}
const confirmFile = opt('--confirm-file')
const core = new ProxyCore(allow, labels)

// audit log: one JSON line per gate decision, chained so edits or truncation are detectable; resumes the chain on restart
const logPath = opt('--log')
const key = process.env.TRIFECTA_AUDIT_KEY ?? ''
const digest = (s: string) => (key ? createHmac('sha256', key) : createHash('sha256')).update(s).digest('hex')
let prevHash = '0'.repeat(64)
let seq = 0
if (logPath && existsSync(logPath)) { const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean); if (lines.length) { const last = JSON.parse(lines[lines.length - 1]); prevHash = last.hash; seq = last.seq ?? lines.length } }
if (logPath && !key) console.error('trifecta-gate: TRIFECTA_AUDIT_KEY not set — audit chain is unkeyed (detects accidental edits, not a writer who recomputes it)')
function writeEvent(event: Record<string, unknown>) {
  const e = { ...event, seq: ++seq, keyed: !!key, prev_hash: prevHash }
  prevHash = digest(prevHash + JSON.stringify(e))
  appendFileSync(logPath, JSON.stringify({ ...e, hash: prevHash }) + '\n')
}
let logged = 0
function audit() {
  if (!logPath) return
  for (const e of core.gate.log.slice(logged)) {
    writeEvent({ '@timestamp': new Date().toISOString(), event: { kind: 'event', category: ['intrusion_detection'], action: e.kind, outcome: e.decision?.action ?? 'n/a' }, rule: { id: e.decision?.rule }, session: { id: SESSION }, policy: { version: POLICY_VERSION, labels: Object.keys(labels).length }, tool: e.tool, reason: e.decision?.reason, destinations: e.decision?.destinations, threat: e.decision?.action === 'block' ? { framework: { name: 'MITRE ATLAS' }, technique: { id: ['AML.T0051.001', 'AML.T0057'] } } : undefined })
  }
  logged = core.gate.log.length
}
function syncConfirmations() {
  if (!confirmFile || !existsSync(confirmFile)) return
  for (const line of readFileSync(confirmFile, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean)) core.confirm(line)
}

const child = spawn(argv[sep + 1], argv.slice(sep + 2), { stdio: ['pipe', 'pipe', 'inherit'] })
const send = (stream: NodeJS.WritableStream, m: unknown) => stream.write(JSON.stringify(m) + '\n')
createInterface({ input: process.stdin }).on('line', (l) => {
  if (!l.trim()) return
  let parsed: unknown
  try { parsed = JSON.parse(l) } catch { return } // fail closed: lines that are not JSON-RPC are dropped, never forwarded
  syncConfirmations()
  // JSON-RPC batches are unpacked so every call inside is gated
  for (const m of (Array.isArray(parsed) ? parsed : [parsed]) as Array<Record<string, unknown>>) {
    const r = core.fromClient(m)
    r.toServer.forEach((x) => send(child.stdin, x)); r.toClient.forEach((x) => send(process.stdout, x))
  }
  audit()
})
createInterface({ input: child.stdout }).on('line', (l) => {
  if (!l.trim()) return
  let parsed: unknown
  try { parsed = JSON.parse(l) } catch { process.stdout.write(l + '\n'); return }
  for (const m of (Array.isArray(parsed) ? parsed : [parsed]) as Array<Record<string, unknown>>) {
    const r = core.fromServer(m)
    r.toServer.forEach((x) => send(child.stdin, x)); r.toClient.forEach((x) => send(process.stdout, x))
  }
  audit()
  if (clientDone && core.idle()) child.stdin.end()
})
// an end-of-session record: a log whose last line is not a session_end was cut short (or the proxy is still running)
child.on('exit', (code) => { if (logPath) { audit(); writeEvent({ '@timestamp': new Date().toISOString(), event: { kind: 'event', action: 'session_end' }, session: { id: SESSION }, events: logged }) }; process.exit(code ?? 0) })
let clientDone = false
process.stdin.on('end', () => { clientDone = true; if (core.idle()) child.stdin.end() })
