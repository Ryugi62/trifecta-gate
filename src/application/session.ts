import { classifyTool } from '../domain/classify'
import { decide, emptyTaint, extractDestinations, shownDestination, unsafeAnswerLinks, type Decision, type Taint } from '../domain/policy'
import type { Leg, ToolSpec } from '../domain/types'

export interface GateEvent { step: number; tool: string; kind: 'result' | 'call' | 'confirm' | 'turn'; legs: Leg[]; decision?: Pick<Decision, 'action' | 'rule' | 'reason'> & { destinations: string[] }; ms?: number }

export interface GateOptions {
  allowlist?: string[]
  /** admin labels per tool name; replace the keyword classifier for that tool */
  labelOverrides?: Record<string, Leg[]>
  /** start as if private data were already in the conversation (e.g. a system prompt with internal data) */
  startPrivate?: boolean
  now?: () => number
}

const PII = /\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]?){13,19}\b|\b(?:password|passcode|pin|api[ _-]?key|secret|token)\b(?:\s+is)?\s*[:=]?\s*\S{4,}/i

/**
 * One agent conversation. Feed it every user turn and tool result; ask it before every tool call.
 * Keeps no raw private text: only hashed fingerprints and where each address first appeared.
 */
export class GateSession {
  readonly taint: Taint = emptyTaint()
  readonly log: GateEvent[] = []
  private readonly confirmed: string[] = []
  private turns: string[] = []
  private step = 0
  private readonly legCache = new Map<string, Set<Leg>>()
  private readonly opts: Required<Omit<GateOptions, 'labelOverrides'>> & { labelOverrides: Record<string, Leg[]> }

  constructor(instruction: string, allowlistOrOptions: string[] | GateOptions = [], now?: () => number, labelOverrides?: Record<string, Leg[]>) {
    const o: GateOptions = Array.isArray(allowlistOrOptions) ? { allowlist: allowlistOrOptions, now, labelOverrides } : allowlistOrOptions
    this.opts = { allowlist: o.allowlist ?? [], labelOverrides: o.labelOverrides ?? {}, startPrivate: o.startPrivate ?? false, now: o.now ?? (() => 0) }
    if (this.opts.startPrivate) this.taint.privateSeen = true
    this.addUserTurn(instruction)
  }

  get instruction(): string { return this.turns.join('\n') }
  get allowlist(): string[] { return this.opts.allowlist }

  /** Every user message is trusted for destinations; secrets the user typed are tracked as private. */
  addUserTurn(text: string): void {
    this.turns.push(text)
    if (PII.test(text)) { this.taint.privateSeen = true; this.taint.secrets.add(text) }
    if (this.turns.length > 1) this.log.push({ step: ++this.step, tool: '(user)', kind: 'turn', legs: [] })
  }

  legsOf(tool: ToolSpec): Set<Leg> {
    let l = this.legCache.get(tool.name)
    if (!l) { l = this.opts.labelOverrides[tool.name] ? new Set(this.opts.labelOverrides[tool.name]) : classifyTool(tool).legs; this.legCache.set(tool.name, l) }
    return l
  }

  check(tool: ToolSpec, args: Record<string, unknown>): Decision {
    const t0 = this.opts.now()
    const d = decide({ tool, args }, this.ctx(), this.legsOf(tool))
    this.log.push({ step: ++this.step, tool: tool.name, kind: 'call', legs: [...this.legsOf(tool)], decision: { action: d.action, rule: d.rule, reason: d.reason, destinations: d.destinations.map(shownDestination) }, ms: this.opts.now() - t0 })
    return d
  }

  /** The user approved one exact destination (address, URL or channel) for the rest of this conversation. */
  confirm(destination: string): void {
    this.confirmed.push(destination)
    this.log.push({ step: ++this.step, tool: '(user)', kind: 'confirm', legs: [], decision: { action: 'allow', rule: 'R1', reason: 'confirmed by the user', destinations: [destination] } })
  }

  record(tool: ToolSpec, resultText: string): void {
    const legs = this.legsOf(tool)
    // a tool nobody could label is treated as returning private data (fail closed)
    if (legs.has('private') || legs.size === 0) { this.taint.privateSeen = true; this.taint.secrets.add(resultText) }
    if (legs.has('untrusted') || legs.size === 0) this.taint.untrustedSeen = true
    const where = `${tool.name} (step ${this.step + 1})`
    for (const d of extractDestinations({ text: resultText, to: (resultText.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? []).join(','), channel: (resultText.match(/#[A-Za-z0-9][\w-]*/g) ?? []).join(',') })) {
      for (const k of [d.url, d.value, d.host]) if (k && !this.taint.origins.has(k)) this.taint.origins.set(k, where)
    }
    this.log.push({ step: ++this.step, tool: tool.name, kind: 'result', legs: [...legs] })
  }

  /** Links and images in the final answer that would send data to a host the user did not name. */
  unsafeAnswerLinks(answer: string): string[] { return unsafeAnswerLinks(answer, this.ctx()) }

  private ctx() { return { instruction: this.instruction, allowlist: this.opts.allowlist, confirmed: this.confirmed, taint: this.taint } }
}
