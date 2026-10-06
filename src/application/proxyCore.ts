import { GateSession } from './session'
import type { Leg, ToolSpec } from '../domain/types'

/**
 * MCP (JSON-RPC 2.0, newline-delimited over stdio) proxy logic, without I/O.
 * Sits between an MCP client and one server: learns tool specs from tools/list, gates every tools/call,
 * and records tool results so taint is tracked. MCP carries no user prompt, so provenance comes from the allowlist
 * and from destinations the operator confirms.
 */
type Json = Record<string, unknown>
export interface Routed { toServer: Json[]; toClient: Json[] }

export class ProxyCore {
  readonly gate: GateSession
  private readonly specs = new Map<string, ToolSpec>()
  private readonly pendingList = new Set<unknown>()
  private readonly pendingCall = new Map<unknown, ToolSpec>()
  /** outbound calls wait until every earlier tool result has been recorded (no race past the taint) */
  private readonly held: Json[] = []

  constructor(allowlist: string[], labelOverrides: Record<string, Leg[]> = {}, instruction = '') {
    this.gate = new GateSession(instruction, allowlist, () => 0, labelOverrides)
  }

  private readonly confirmedSet = new Set<string>()
  /** a destination the user approved through the host's approval UI (exact match only) */
  confirm(destination: string): void { if (!this.confirmedSet.has(destination)) { this.confirmedSet.add(destination); this.gate.confirm(destination) } }

  /** nothing held and no tool call awaiting its result */
  idle(): boolean { return this.held.length === 0 && this.pendingCall.size === 0 }

  fromClient(msg: Json): Routed {
    if (msg.method === 'tools/list') this.pendingList.add(msg.id)
    if (msg.method === 'tools/call') {
      if (this.pendingCall.size > 0 || this.held.length > 0) { this.held.push(msg); return { toServer: [], toClient: [] } }
      return this.gateCall(msg)
    }
    return { toServer: [msg], toClient: [] }
  }

  private gateCall(msg: Json): Routed {
    const p = (msg.params ?? {}) as { name?: string; arguments?: Record<string, unknown> }
    const spec = this.specs.get(String(p.name)) ?? { name: String(p.name), description: '', params: Object.keys(p.arguments ?? {}) }
    const d = this.gate.check(spec, p.arguments ?? {})
    if (d.action === 'block') {
      return { toServer: [], toClient: [{ jsonrpc: '2.0', id: msg.id, result: { isError: true, content: [{ type: 'text', text: `BLOCKED by Trifecta Gate (${d.rule}): ${d.reason}. Ask the user to confirm this destination if it is intended.` }] } }] }
    }
    this.pendingCall.set(msg.id, spec)
    return { toServer: [msg], toClient: [] }
  }

  private release(): Routed {
    const out: Routed = { toServer: [], toClient: [] }
    while (this.held.length && this.pendingCall.size === 0) {
      const r = this.gateCall(this.held.shift()!)
      out.toServer.push(...r.toServer); out.toClient.push(...r.toClient)
    }
    return out
  }

  fromServer(msg: Json): Routed {
    if (this.pendingList.has(msg.id)) {
      this.pendingList.delete(msg.id)
      const tools = ((msg.result as Json | undefined)?.tools ?? []) as Array<{ name: string; description?: string; inputSchema?: { properties?: Json }; annotations?: ToolSpec['annotations'] }>
      for (const t of tools) this.specs.set(t.name, { name: t.name, description: t.description ?? '', params: Object.keys(t.inputSchema?.properties ?? {}), annotations: t.annotations })
    }
    const spec = this.pendingCall.get(msg.id)
    if (spec) {
      this.pendingCall.delete(msg.id)
      const result = (msg.result ?? {}) as Json
      const content = (result.content ?? []) as Array<{ type: string; text?: string; resource?: { text?: string; uri?: string } }>
      // text blocks, embedded resources and structured content all count as what the tool returned
      const text = [...content.map((c) => c.text ?? c.resource?.text ?? c.resource?.uri ?? ''), result.structuredContent ? JSON.stringify(result.structuredContent) : ''].join('\n')
      this.gate.record(spec, text)
    }
    const r = this.release()
    return { toServer: r.toServer, toClient: [msg, ...r.toClient] }
  }
}
