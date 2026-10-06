import { classifyTool } from '../domain/classify'
import { decide, emptyTaint, type Decision, type Taint } from '../domain/policy'
import type { Leg, ToolSpec } from '../domain/types'

export interface GateEvent { step: number; tool: string; kind: 'result' | 'call'; legs: Leg[]; decision?: Decision; ms?: number }

/** One agent run. Feed it every tool result and ask it before every tool call. */
export class GateSession {
  readonly taint: Taint = emptyTaint()
  readonly log: GateEvent[] = []
  private step = 0
  private readonly legCache = new Map<string, Set<Leg>>()

  /** labelOverrides: tool name -> legs, replacing the keyword classifier for that tool (e.g. an admin marks a tool as outbound). */
  constructor(readonly instruction: string, readonly allowlist: string[] = [], private readonly now: () => number = () => 0, private readonly labelOverrides: Record<string, Leg[]> = {}) {}

  legsOf(tool: ToolSpec): Set<Leg> {
    let l = this.legCache.get(tool.name)
    if (!l) { l = this.labelOverrides[tool.name] ? new Set(this.labelOverrides[tool.name]) : classifyTool(tool).legs; this.legCache.set(tool.name, l) }
    return l
  }

  check(tool: ToolSpec, args: Record<string, unknown>): Decision {
    const t0 = this.now()
    const d = decide({ tool, args }, { instruction: this.instruction, allowlist: this.allowlist, taint: this.taint }, this.legsOf(tool))
    this.log.push({ step: ++this.step, tool: tool.name, kind: 'call', legs: [...this.legsOf(tool)], decision: d, ms: this.now() - t0 })
    return d
  }

  record(tool: ToolSpec, resultText: string): void {
    const legs = this.legsOf(tool)
    if (legs.has('private')) { this.taint.privateSeen = true; this.taint.privateTexts.push(resultText) }
    if (legs.has('untrusted')) this.taint.untrustedSeen = true
    this.log.push({ step: ++this.step, tool: tool.name, kind: 'result', legs: [...legs] })
  }
}
