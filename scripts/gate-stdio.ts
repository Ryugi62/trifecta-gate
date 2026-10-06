// Line-delimited JSON gate server for non-TypeScript hosts (used by the AgentDojo adapter).
// {op:'new',id,instruction,allowlist?} | {op:'check',id,tool,args} -> {action,rule,reason} | {op:'record',id,tool,text} | {op:'end',id}
import { createInterface } from 'node:readline'
import { GateSession } from '../src/application/session'
const sessions = new Map<string, GateSession>()
createInterface({ input: process.stdin }).on('line', (l) => {
  let out: unknown = { ok: true }
  try {
    const m = JSON.parse(l)
    if (m.op === 'new') sessions.set(m.id, new GateSession(m.instruction, { allowlist: m.allowlist ?? [], startPrivate: !!m.startPrivate }))
    else if (m.op === 'check') { const d = sessions.get(m.id)!.check(m.tool, m.args ?? {}); out = { action: d.action, rule: d.rule, reason: d.reason } }
    else if (m.op === 'record') sessions.get(m.id)!.record(m.tool, String(m.text ?? ''))
    else if (m.op === 'end') sessions.delete(m.id)
  } catch (e) { out = { error: String(e) } }
  process.stdout.write(JSON.stringify(out) + '\n')
})
