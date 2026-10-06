#!/usr/bin/env -S npx tsx
// Drop-in MCP stdio proxy:  trifecta-gate --allow "*.town.gov,clerk@town.gov" -- <server command> [args...]
// Put this command where your MCP client config names the server; it starts the real server as a child.
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { ProxyCore } from '../src/application/proxyCore'

const argv = process.argv.slice(2)
const sep = argv.indexOf('--')
if (sep < 0 || sep === argv.length - 1) { console.error('usage: mcp-proxy [--allow list] -- <server command> [args]'); process.exit(2) }
const opts = argv.slice(0, sep)
const allow = (opts[opts.indexOf('--allow') + 1] && opts.includes('--allow') ? opts[opts.indexOf('--allow') + 1] : '').split(',').map((s) => s.trim()).filter(Boolean)
const core = new ProxyCore(allow)
const child = spawn(argv[sep + 1], argv.slice(sep + 2), { stdio: ['pipe', 'pipe', 'inherit'] })
const send = (stream: NodeJS.WritableStream, m: unknown) => stream.write(JSON.stringify(m) + '\n')
createInterface({ input: process.stdin }).on('line', (l) => {
  if (!l.trim()) return
  let m: Record<string, unknown>; try { m = JSON.parse(l) } catch { child.stdin.write(l + '\n'); return }
  const r = core.fromClient(m)
  r.toServer.forEach((x) => send(child.stdin, x)); r.toClient.forEach((x) => send(process.stdout, x))
})
createInterface({ input: child.stdout }).on('line', (l) => {
  if (!l.trim()) return
  let m: Record<string, unknown>; try { m = JSON.parse(l) } catch { process.stdout.write(l + '\n'); return }
  const r = core.fromServer(m)
  r.toServer.forEach((x) => send(child.stdin, x)); r.toClient.forEach((x) => send(process.stdout, x))
  if (clientDone && core.idle()) child.stdin.end()
})
child.on('exit', (code) => process.exit(code ?? 0))
let clientDone = false
process.stdin.on('end', () => { clientDone = true; if (core.idle()) child.stdin.end() })
