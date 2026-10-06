import { classifyTool } from './classify'
import type { ToolSpec } from './types'

export interface Destination { kind: 'email' | 'host' | 'name'; value: string; host?: string }

export interface Taint {
  privateSeen: boolean
  untrustedSeen: boolean
  /** raw text of private tool results, for the verbatim-fragment rule R4 */
  privateTexts: string[]
}
export const emptyTaint = (): Taint => ({ privateSeen: false, untrustedSeen: false, privateTexts: [] })

export interface Context { instruction: string; allowlist: string[]; taint: Taint }
export interface ProposedCall { tool: ToolSpec; args: Record<string, unknown> }
export type Rule = 'R0' | 'R1' | 'R2' | 'R3' | 'R4'
export interface Decision { action: 'allow' | 'block'; rule: Rule; reason: string; destinations: Array<Destination & { provenance: 'user' | 'content' }> }

const EMAIL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi
const URL_RE = /\bhttps?:\/\/[^\s"'<>)]+/gi
const HOST_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi
const DEST_KEYS = new Set(['to', 'cc', 'bcc', 'recipient', 'recipients', 'url', 'uri', 'endpoint', 'webhook', 'webhook_url', 'webhookurl', 'channel', 'channel_id', 'channelid', 'chat_id', 'chatid', 'phone', 'phone_number', 'email', 'email_address', 'address', 'target_url', 'callback_url', 'href', 'target', 'destination'])

const stripWww = (h: string) => h.toLowerCase().replace(/^www\./, '').replace(/\.$/, '')

export function normalizeDestination(raw: string): Destination {
  const s = raw.trim()
  const e = s.match(/^mailto:(.+)$/i)?.[1] ?? s
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(e)) {
    const v = e.toLowerCase()
    return { kind: 'email', value: v, host: v.split('@')[1] }
  }
  try {
    const u = new URL(/^[a-z]+:\/\//i.test(s) ? s : `https://${s}`)
    if (u.hostname.includes('.')) { const h = stripWww(u.hostname); return { kind: 'host', value: h, host: h } }
  } catch { /* not a url */ }
  return { kind: 'name', value: s.toLowerCase().replace(/^#/, '') }
}

function collectStrings(v: unknown, out: string[]): void {
  if (typeof v === 'string') out.push(v)
  else if (Array.isArray(v)) v.forEach((x) => collectStrings(x, out))
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => collectStrings(x, out))
}

export function extractDestinations(args: Record<string, unknown>): Destination[] {
  const out: Destination[] = []
  const seen = new Set<string>()
  const push = (d: Destination) => { const k = `${d.kind}:${d.value}`; if (!seen.has(k)) { seen.add(k); out.push(d) } }
  for (const [k, v] of Object.entries(args)) {
    if (!DEST_KEYS.has(k.toLowerCase())) continue
    const vals: string[] = []
    collectStrings(v, vals)
    for (const s of vals) for (const part of s.split(/[,;]\s*/).filter(Boolean)) push(normalizeDestination(part))
  }
  if (out.length === 0) {
    const vals: string[] = []
    collectStrings(args, vals)
    for (const s of vals) {
      for (const m of s.match(URL_RE) ?? []) push(normalizeDestination(m))
      for (const m of s.match(EMAIL) ?? []) push(normalizeDestination(m))
    }
  }
  return out
}

interface Trusted { emails: Set<string>; hosts: Set<string>; names: Set<string>; allow: string[] }

function trustedFrom(instruction: string, allowlist: string[]): Trusted {
  const emails = new Set((instruction.match(EMAIL) ?? []).map((x) => x.toLowerCase()))
  const noEmails = instruction.replace(EMAIL, ' ')
  const hosts = new Set<string>()
  for (const u of noEmails.match(URL_RE) ?? []) { try { hosts.add(stripWww(new URL(u).hostname)) } catch { /* skip */ } }
  for (const h of noEmails.replace(URL_RE, ' ').match(HOST_RE) ?? []) hosts.add(stripWww(h))
  const names = new Set(instruction.toLowerCase().split(/[^a-z0-9_#-]+/).filter((w) => w.length >= 2).map((w) => w.replace(/^#/, '')))
  return { emails, hosts, names, allow: allowlist.map((a) => a.toLowerCase().trim()) }
}

const underHost = (host: string, parent: string) => host === parent || host.endsWith(`.${parent}`)

function allowMatches(d: Destination, allow: string[]): boolean {
  for (const a of allow) {
    if (a.includes('@')) { if (d.kind === 'email' && d.value === a) return true; continue }
    const parent = a.replace(/^\*\./, '')
    if (d.host && underHost(d.host, parent)) return true
    if (d.kind === 'name' && d.value === a.replace(/^#/, '')) return true
  }
  return false
}

export function provenanceOf(d: Destination, t: Trusted): 'user' | 'content' {
  if (allowMatches(d, t.allow)) return 'user'
  if (d.kind === 'email') return t.emails.has(d.value) ? 'user' : 'content'
  if (d.kind === 'host') return [...t.hosts].some((h) => underHost(d.value, h)) ? 'user' : 'content'
  return t.names.has(d.value) ? 'user' : 'content'
}

function shingles(s: string, n: number): string[] {
  const t = s.replace(/\s+/g, ' ')
  const out: string[] = []
  for (let i = 0; i + n <= t.length; i++) out.push(t.slice(i, i + n))
  return out
}

/** Does any 12-char window of the outbound arguments appear verbatim in a private result? */
export function leaksPrivate(args: Record<string, unknown>, privateTexts: string[], n = 12): string | null {
  if (!privateTexts.length) return null
  const vals: string[] = []
  collectStrings(args, vals)
  const decoded = vals.map((v) => { try { return decodeURIComponent(v) } catch { return v } })
  const hay = privateTexts.map((p) => p.replace(/\s+/g, ' '))
  for (const v of decoded) for (const sh of shingles(v, n)) {
    if (!/[a-z0-9]{3}/i.test(sh)) continue
    if (hay.some((h) => h.includes(sh))) return sh
  }
  return null
}

export function decide(call: ProposedCall, ctx: Context, legsOverride?: ReadonlySet<string>): Decision {
  const legs = legsOverride ?? classifyTool(call.tool).legs
  if (!legs.has('outbound')) return { action: 'allow', rule: 'R0', reason: 'not an outbound tool', destinations: [] }
  const trusted = trustedFrom(ctx.instruction, ctx.allowlist)
  const dests = extractDestinations(call.args).map((d) => ({ ...d, provenance: provenanceOf(d, trusted) }))
  const fromContent = dests.filter((d) => d.provenance === 'content')
  const unknown = dests.length === 0
  if (!unknown && fromContent.length === 0) return { action: 'allow', rule: 'R1', reason: 'every destination came from the user or the allowlist', destinations: dests }
  const leaked = leaksPrivate(call.args, ctx.taint.privateTexts)
  if (leaked) return { action: 'block', rule: 'R4', reason: `arguments carry private text ("${leaked}") to a destination the user did not name`, destinations: dests }
  if (ctx.taint.privateSeen) {
    const who = unknown ? 'an unnamed destination' : fromContent.map((d) => d.value).join(', ')
    return { action: 'block', rule: 'R2', reason: `private data is in context and ${who} did not come from the user`, destinations: dests }
  }
  return { action: 'allow', rule: 'R3', reason: 'no private data read yet, nothing to leak', destinations: dests }
}
