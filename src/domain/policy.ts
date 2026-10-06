import { classifyTool, isInternalWrite } from './classify'
import { secretsIndex, type SecretIndex } from './secrets'
import type { ToolSpec } from './types'

/**
 * Provenance policy v2.
 * An outgoing call may only reach destinations the user wrote (or the admin allowlisted / the user confirmed),
 * once private data is in play. Destinations are read from every argument, including links inside message bodies.
 */

export interface Destination { kind: 'email' | 'host' | 'name'; value: string; host?: string; url?: string }
export type Provenance = 'user' | 'content'

export interface Taint {
  privateSeen: boolean
  untrustedSeen: boolean
  /** hashed windows + short secrets of private data (no raw text is kept) */
  secrets: SecretIndex
  /** where each address/host/channel first appeared in a tool result: value -> "tool (step n)" */
  origins: Map<string, string>
}
export const emptyTaint = (): Taint => ({ privateSeen: false, untrustedSeen: false, secrets: secretsIndex(), origins: new Map() })

export interface Context { instruction: string; allowlist: string[]; confirmed?: string[]; taint: Taint }
export interface ProposedCall { tool: ToolSpec; args: Record<string, unknown> }
export type Rule = 'R0' | 'R1' | 'R2' | 'R3' | 'R4' | 'R5'
export interface Decision {
  action: 'allow' | 'block'
  rule: Rule
  reason: string
  destinations: Array<Destination & { provenance: Provenance; origin?: string }>
  /** text for the host UI to show (written by the gate, not by the model) */
  confirmPrompt?: string
}

const EMAIL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi
const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]]+/gi
const HOST_RE = /(?<![@\w/.-])(?:[a-z0-9-]+\.)+[a-z]{2,}\b(?![@/])/gi
const DEST_KEY = /^(to|cc|bcc|bcc_list|cc_list|recipients?|recipient_email|recipient_emails|attendees?|invitees?|participants?|members?|share_with|shared_with|forward_to|forwarding|reply_to|assignees?|webhook(_url)?|url|uri|urls|endpoint|href|link|target(_url)?|callback(_url)?|channel(_id|_name)?|chat(_id)?|phone(_number)?|number|address|email(_address)?|emails|destination|host(name)?|domain|iban|account|user|users|user_id)$/i
const CONTENT_KEY = /^(body|text|content|message|msg|subject|description|note|notes|title|summary|comment|html|markdown|caption|prompt|query)$/i
/** platforms where anyone can publish or receive data: naming the host never trusts it (only an exact URL or the admin can) */
export const SHARED_HOSTS = ['google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'script.google.com', 'github.com', 'gist.github.com', 'raw.githubusercontent.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'notion.so', 'notion.site', 'medium.com', 'substack.com', 'dropbox.com', 'box.com', 'pastebin.com', 'hastebin.com', 'webhook.site', 'requestbin.com', 'pipedream.net', 'hooks.slack.com', 'discord.com', 'discordapp.com', 'amazonaws.com', 's3.amazonaws.com', 'blob.core.windows.net', 'storage.googleapis.com', 'ngrok.io', 'ngrok-free.app', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'herokuapp.com', 'glitch.me', 'replit.com', 'bit.ly', 'tinyurl.com', 't.co', 'airtable.com', 'typeform.com', 'jotform.com', 'surveymonkey.com', 'wordpress.com', 'blogspot.com', 'sharepoint.com', 'onedrive.live.com', '1drv.ms']
const FILE_EXT = new Set(['md', 'zip', 'py', 'rs', 'sh', 'ts', 'js', 'json', 'txt', 'csv', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'png', 'jpg', 'jpeg', 'gif', 'mov', 'mp4', 'mp3', 'yml', 'yaml', 'toml', 'log', 'ini', 'cfg', 'html', 'htm', 'css', 'xml', 'sql', 'db', 'tar', 'gz', 'tgz', 'rar', 'exe', 'dmg', 'pkg', 'jar', 'java', 'cpp', 'rb', 'php', 'swift', 'kt', 'lock', 'env', 'bak', 'tmp', 'svg', 'webp', 'heic', 'wav', 'eml', 'msg', 'ics', 'vcf', 'key', 'pem', 'crt', 'app', 'dev', 'sol', 'mov', 'cs', 'go', 'pl', 'ps1', 'bat', 'cmd'])

const stripWww = (h: string) => h.toLowerCase().replace(/^www\./, '').replace(/\.$/, '')
const cleanUrl = (u: string) => u.replace(/[.,;:!?)\]]+$/, '')
const normUrl = (u: string) => { try { const x = new URL(cleanUrl(u)); return `${x.protocol}//${stripWww(x.hostname)}${x.pathname.replace(/\/$/, '')}${x.search}${x.hash}`.toLowerCase() } catch { return cleanUrl(u).toLowerCase() } }
const isShared = (host: string) => SHARED_HOSTS.some((s) => host === s || host.endsWith(`.${s}`))

export function normalizeDestination(raw: string): Destination {
  const s = raw.trim()
  const e = s.match(/^mailto:(.+)$/i)?.[1] ?? s
  if (/^[^\s@/]+@[^\s@/]+\.[a-z]{2,}$/i.test(e)) { const v = e.toLowerCase(); return { kind: 'email', value: v, host: v.split('@')[1] } }
  if (/^[a-z]+:\/\//i.test(s) || /^(?:[a-z0-9-]+\.)+[a-z]{2,}(\/|$)/i.test(s)) {
    try {
      const u = new URL(/^[a-z]+:\/\//i.test(s) ? s : `https://${s}`)
      if (u.hostname.includes('.')) { const h = stripWww(u.hostname); return { kind: 'host', value: h, host: h, url: normUrl(u.href) } }
    } catch { /* not a url */ }
  }
  return { kind: 'name', value: s.toLowerCase().replace(/^[#@]/, '') }
}

function walk(v: unknown, key: string, out: Array<{ key: string; value: string }>): void {
  if (typeof v === 'string') out.push({ key, value: v })
  else if (Array.isArray(v)) v.forEach((x) => walk(x, key, out))
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, k, out)
}

/** URLs hidden in query strings (open redirects, ?to=https://…) are destinations too. */
function nestedUrls(u: string): string[] {
  try {
    const x = new URL(cleanUrl(u))
    const inner: string[] = []
    for (const v of x.searchParams.values()) for (const m of v.match(URL_RE) ?? []) inner.push(m, ...nestedUrls(m))
    return inner
  } catch { return [] }
}

export function extractDestinations(args: Record<string, unknown>): Destination[] {
  const out: Destination[] = []
  const seen = new Set<string>()
  const push = (d: Destination) => { const k = `${d.kind}:${d.url ?? d.value}`; if (!seen.has(k)) { seen.add(k); out.push(d) } }
  const vals: Array<{ key: string; value: string }> = []
  walk(args, '', vals)
  for (const { key, value } of vals) {
    if (DEST_KEY.test(key)) for (const part of value.split(/[,;]\s*/).filter(Boolean)) push(normalizeDestination(part))
    // links anywhere (message bodies included): previews, images and redirects fetch them
    for (const m of value.match(URL_RE) ?? []) { push(normalizeDestination(m)); for (const n of nestedUrls(m)) push(normalizeDestination(n)) }
    if (!CONTENT_KEY.test(key)) for (const m of value.match(EMAIL) ?? []) push(normalizeDestination(m))
  }
  return out
}

export interface Trusted { emails: Set<string>; hosts: Set<string>; urls: string[]; names: Set<string>; allow: string[]; confirmed: Set<string> }

export function trustedFrom(instruction: string, allowlist: string[], confirmed: string[] = []): Trusted {
  const emails = new Set((instruction.match(EMAIL) ?? []).map((x) => x.toLowerCase()))
  const noEmails = instruction.replace(EMAIL, ' ')
  const urls = (noEmails.match(URL_RE) ?? []).map(normUrl)
  const hosts = new Set<string>()
  for (const u of urls) { try { const h = stripWww(new URL(u).hostname); if (!isShared(h)) hosts.add(h) } catch { /* skip */ } }
  for (const h of noEmails.replace(URL_RE, ' ').match(HOST_RE) ?? []) {
    const host = stripWww(h)
    const tld = host.split('.').pop() ?? ''
    if (FILE_EXT.has(tld) || isShared(host)) continue
    hosts.add(host)
  }
  // channel / account names: marked (#name, @name, "name channel"), ID-like tokens, or capitalised names mid-sentence
  const names = new Set<string>()
  for (const m of instruction.matchAll(/(?:^|[\s(])[#@]([A-Za-z0-9][\w.-]*)/g)) names.add(m[1].replace(/[.,]$/, '').toLowerCase())
  for (const m of instruction.matchAll(/([A-Za-z0-9][\w-]*)\s+channel\b/gi)) names.add(m[1].toLowerCase())
  for (const m of noEmails.matchAll(/\b[A-Za-z0-9]*\d[A-Za-z0-9-]{4,}\b/g)) if (/[a-z]/i.test(m[0]) || m[0].length >= 6) names.add(m[0].toLowerCase())
  for (const sentence of instruction.split(/[.!?\n]+/)) {
    const words = sentence.trim().split(/\s+/)
    words.slice(1).forEach((w) => { const t = w.replace(/[^\w-]/g, ''); if (/^[A-Z][a-z]+$/.test(t)) names.add(t.toLowerCase()) })
  }
  return { emails, hosts, urls, names, allow: allowlist.map((a) => a.toLowerCase().trim()), confirmed: new Set(confirmed.map((c) => normalizeDestination(c)).map((d) => d.url ?? d.value)) }
}

const underHost = (host: string, parent: string) => host === parent || host.endsWith(`.${parent}`)

function allowMatches(d: Destination, allow: string[]): boolean {
  for (const a of allow) {
    if (a.includes('@')) { if (d.kind === 'email' && d.value === a) return true; continue }
    if (a.startsWith('#')) { if (d.kind === 'name' && d.value === a.slice(1)) return true; continue }
    if (a.startsWith('*.')) { const p = a.slice(2); if (d.host && underHost(d.host, p)) return true; continue }
    if (d.host && d.host === a) return true
    if (d.kind === 'name' && d.value === a) return true
  }
  return false
}

/** trusted only because the user named the bare host (weaker than an exact URL or the allowlist) */
export function bareHostTrust(d: Destination, t: Trusted): boolean {
  return d.kind === 'host' && t.hosts.has(d.value) && !/[?#]/.test(d.url ?? '') && !allowMatches(d, t.allow) && !t.urls.includes(d.url ?? '')
}

export function provenanceOf(d: Destination, t: Trusted): Provenance {
  if (t.confirmed.has(d.url ?? d.value) || (d.kind !== 'host' && t.confirmed.has(d.value))) return 'user'
  if (allowMatches(d, t.allow)) return 'user'
  if (d.kind === 'email') return t.emails.has(d.value) ? 'user' : 'content'
  if (d.kind === 'host') {
    const u = d.url ?? ''
    // the exact URL the user wrote, or a deeper path under it without a new query string
    if (t.urls.some((w) => u === w || (u.startsWith(w.replace(/[?#].*$/, '') + '/') && !/[?#]/.test(u.slice(w.length))))) return 'user'
    // a bare host the user named: that host only, no query/fragment that could carry data (R4 still checks the path)
    if (bareHostTrust(d, t)) return 'user'
    return 'content'
  }
  return t.names.has(d.value) ? 'user' : 'content'
}

function originOf(d: Destination, taint: Taint): string | undefined {
  return taint.origins.get(d.url ?? '') ?? taint.origins.get(d.value) ?? (d.host ? taint.origins.get(d.host) : undefined)
}

/** How a destination is shown to people and logs: never the query string or fragment, which may carry data. */
export function shownDestination(d: Destination): string {
  if (d.kind !== 'host' || !d.url) return d.value
  try { const u = new URL(d.url); return `${d.host}${u.pathname === '/' ? '' : u.pathname}${u.search || u.hash ? ' (with data in the link)' : ''}` } catch { return d.value }
}

export function decide(call: ProposedCall, ctx: Context, legsOverride?: ReadonlySet<string>): Decision {
  const legs = legsOverride ?? classifyTool(call.tool).legs
  const dests0 = extractDestinations(call.args)
  // tools nobody labelled: treat any address in their arguments as an outgoing destination (fail closed)
  const outbound = legs.has('outbound') || (legs.size === 0 && dests0.length > 0)
  if (!outbound) return { action: 'allow', rule: 'R0', reason: 'not an outbound tool', destinations: [] }
  const trusted = trustedFrom(ctx.instruction, ctx.allowlist, ctx.confirmed)
  const dests = dests0.map((d) => ({ ...d, provenance: provenanceOf(d, trusted), origin: originOf(d, ctx.taint) }))
  const fromContent = dests.filter((d) => d.provenance === 'content')
  const leak = ctx.taint.privateSeen ? ctx.taint.secrets.find(call.args) : null
  if (dests.length > 0 && fromContent.length === 0 && leak && dests.some((d) => bareHostTrust(d, trusted))) {
    return { action: 'block', rule: 'R4', reason: `the call carries private data (${leak}) in a URL path on a host the user only named in passing`, destinations: dests }
  }
  if (dests.length > 0 && fromContent.length === 0) return { action: 'allow', rule: 'R1', reason: 'every destination came from the user, the allowlist or a confirmation', destinations: dests }
  if (dests.length === 0 && isInternalWrite(call.tool)) return { action: 'allow', rule: 'R5', reason: 'writes to the user\'s own workspace with no outside recipient', destinations: [] }
  if (!ctx.taint.privateSeen) return { action: 'allow', rule: 'R3', reason: 'no private data in play yet, nothing to leak', destinations: dests }
  const who = fromContent.length ? fromContent.map(shownDestination).join(', ') : 'an unnamed destination'
  const where = fromContent.map((d) => d.origin).filter(Boolean)
  const confirmPrompt = fromContent.length
    ? `Your assistant wants to send data to ${who}. You did not name this address${where.length ? `; it first appeared in ${where.join(', ')}` : ''}. Allow it for this task?`
    : undefined
  if (leak) return { action: 'block', rule: 'R4', reason: `the call carries private data (${leak}) to ${who}, which the user did not name`, destinations: dests, confirmPrompt }
  return { action: 'block', rule: 'R2', reason: `private data is in play and ${who} did not come from the user`, destinations: dests, confirmPrompt }
}

/** Final answers can leak through rendered links and images (EchoLeak-style). Returns the URLs to strip. */
export function unsafeAnswerLinks(answer: string, ctx: Context): string[] {
  if (!ctx.taint.privateSeen) return []
  const trusted = trustedFrom(ctx.instruction, ctx.allowlist, ctx.confirmed)
  return (answer.match(URL_RE) ?? []).filter((u) => provenanceOf(normalizeDestination(u), trusted) === 'content')
}
