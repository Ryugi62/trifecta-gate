import { classifyTool, isFetchOnly, isInternalWrite } from './classify'
import { secretsIndex, type SecretIndex } from './secrets'
import type { ToolSpec } from './types'

/**
 * Provenance policy v2.
 * An outgoing call may only reach destinations the user wrote (or the admin allowlisted / the user confirmed),
 * once private data is in play. Destinations are read from every argument, including links inside message bodies.
 */

export interface Destination { kind: 'email' | 'host' | 'name'; value: string; host?: string; url?: string; key?: string }
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
export type Rule = 'R0' | 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6'
export interface Decision {
  action: 'allow' | 'block'
  rule: Rule
  reason: string
  destinations: Array<Destination & { provenance: Provenance; origin?: string }>
  /** text for the host UI to show (written by the gate, not by the model) */
  confirmPrompt?: string
}

const EMAIL = /[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,8}\.[a-z]{2,24}/gi
const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]]+/gi
const HOST_RE = /(?<![@\w/.-])(?:[A-Za-z0-9-]{1,63}\.){1,8}[a-z]{2,24}\b(?![@/])/g
const DEST_KEY = /^(to|cc|bcc|bcc_list|cc_list|recipients?|recipient_email|recipient_emails|attendees?|invitees?|participants?|members?|share_with|shared_with|forward_to|forwarding|reply_to|assignees?|webhook(_url)?|url|uri|urls|endpoint|href|link|target(_url)?|callback(_url)?|channel(_id|_name)?|chat(_id)?|phone(_number)?|number|address|email(_address)?|emails|destination|host(name)?|domain|ip|ip_address|server|iban|account|user|users|user_id|owner|repo|repository|org|organization|organisation|project|workspace|bucket|remote|team|username|handle|login|guest|guests|assignee|reviewer|followers?|cc_emails?|bcc_emails?)$/i
const CONTENT_KEY = /^(body|text|content|message|msg|subject|description|note|notes|title|summary|comment|html|markdown|caption|prompt|query|answer|payload|data)$/i
/** platforms where anyone can publish or receive data: naming the host never trusts it (only an exact URL or the admin can) */
export const SHARED_HOSTS = ['google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'script.google.com', 'github.com', 'gist.github.com', 'raw.githubusercontent.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'notion.so', 'notion.site', 'medium.com', 'substack.com', 'dropbox.com', 'box.com', 'pastebin.com', 'hastebin.com', 'webhook.site', 'requestbin.com', 'pipedream.net', 'hooks.slack.com', 'discord.com', 'discordapp.com', 'amazonaws.com', 's3.amazonaws.com', 'blob.core.windows.net', 'storage.googleapis.com', 'ngrok.io', 'ngrok-free.app', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'herokuapp.com', 'glitch.me', 'replit.com', 'bit.ly', 'tinyurl.com', 't.co', 'airtable.com', 'typeform.com', 'jotform.com', 'surveymonkey.com', 'wordpress.com', 'blogspot.com', 'sharepoint.com', 'onedrive.live.com', '1drv.ms']
const FILE_EXT = new Set(['md', 'zip', 'py', 'rs', 'sh', 'ts', 'js', 'json', 'txt', 'csv', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'png', 'jpg', 'jpeg', 'gif', 'mov', 'mp4', 'mp3', 'yml', 'yaml', 'toml', 'log', 'ini', 'cfg', 'html', 'htm', 'css', 'xml', 'sql', 'db', 'tar', 'gz', 'tgz', 'rar', 'exe', 'dmg', 'pkg', 'jar', 'java', 'cpp', 'rb', 'php', 'swift', 'kt', 'lock', 'env', 'bak', 'tmp', 'svg', 'webp', 'heic', 'wav', 'eml', 'msg', 'ics', 'vcf', 'key', 'pem', 'crt', 'app', 'dev', 'sol', 'mov', 'cs', 'go', 'pl', 'ps1', 'bat', 'cmd'])

const stripWww = (h: string) => h.toLowerCase().replace(/^www\./, '').replace(/\.$/, '')
const cleanUrl = (u: string) => u.replace(/[.,;:!?)\]'"’”]+$/, '')
const normUrl = (u: string) => { try { const x = new URL(cleanUrl(u)); return `https://${stripWww(x.hostname)}${x.pathname.replace(/\/$/, '')}${x.search}${x.hash}`.toLowerCase() } catch { return cleanUrl(u).toLowerCase() } }
const isShared = (host: string) => SHARED_HOSTS.some((s) => host === s || host.endsWith(`.${s}`))

export function normalizeDestination(raw: string): Destination {
  const s = cleanUrl(raw.trim())
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

const BARE_HOST = /\b(?:[a-z0-9-]{1,63}\.){1,8}[a-z]{2,24}(?::\d+)?\b|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/gi
const SCHEMELESS = /(?:^|[\s("'=])\/\/([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,8}[^\s"'<>)]{0,2048})/gi

export function extractDestinations(args: Record<string, unknown>): Destination[] {
  const out: Destination[] = []
  const seen = new Set<string>()
  const push = (d: Destination, key: string) => { const k = `${d.kind}:${d.url ?? d.value}`; if (!seen.has(k)) { seen.add(k); out.push({ ...d, key }) } }
  const vals: Array<{ key: string; value: string }> = []
  walk(args, '', vals)
  const ownerRepo = (() => { const o = vals.find((v) => /^(owner|org|organization|organisation)$/i.test(v.key))?.value; const r = vals.find((v) => /^(repo|repository|project)$/i.test(v.key))?.value; return o && r ? `${o}/${r}` : null })()
  if (ownerRepo) push({ kind: 'name', value: ownerRepo.toLowerCase() }, 'repo')
  for (const { key, value } of vals) {
    if (DEST_KEY.test(key) && !(ownerRepo && /^(owner|org|organization|organisation|repo|repository|project)$/i.test(key))) for (const part of value.split(/[,;]\s*/).filter(Boolean)) push(normalizeDestination(part), key)
    // links anywhere (message bodies included): previews, images and redirects fetch them; also //host and bare www.host links
    for (const m of value.match(URL_RE) ?? []) { push(normalizeDestination(m), key); for (const n of nestedUrls(m)) push(normalizeDestination(n), key) }
    for (const m of value.matchAll(SCHEMELESS)) push(normalizeDestination(`https://${m[1]}`), key)
    for (const m of value.match(/\bwww\.[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,8}[^\s"'<>)]{0,2048}/gi) ?? []) push(normalizeDestination(`https://${m}`), key)
    // scheme-less links with a path (evil.example/p.png?d=…): chat and mail clients turn them into previews
    for (const m of value.replace(URL_RE, ' ').match(/(?<![@\w/.-])(?:[a-z0-9-]{1,63}\.){1,8}[a-z]{2,24}\/[^\s"'<>)]{0,2048}/gi) ?? []) {
      const host = m.split('/')[0]; const tld = host.split('.').pop() ?? ''
      if (!FILE_EXT.has(tld.toLowerCase())) push(normalizeDestination(`https://${m}`), key)
    }
    if (!CONTENT_KEY.test(key)) {
      for (const m of value.match(EMAIL) ?? []) push(normalizeDestination(m), key)
      // bare host names and IP addresses in non-content fields (target_host: evil.example, 203.0.113.7:8443)
      if (!DEST_KEY.test(key)) for (const m of value.replace(URL_RE, ' ').replace(EMAIL, ' ').match(BARE_HOST) ?? []) {
        const tld = m.split(':')[0].split('.').pop() ?? ''
        if (/^\d+$/.test(tld) || !FILE_EXT.has(tld)) push(normalizeDestination(`https://${m}`), key)
      }
    }
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
  for (const m of instruction.matchAll(/['"‘“]?([A-Za-z0-9][\w-]*)['"’”]?\s+channel\b/gi)) names.add(m[1].toLowerCase())
  for (const m of instruction.matchAll(/channel\s+['"‘“]?([A-Za-z0-9][\w-]*)/gi)) names.add(m[1].toLowerCase())
  // anything the user put in quotes
  for (const m of instruction.matchAll(/['"‘“]([^'"’”\n]{2,60})['"’”]/g)) names.add(m[1].trim().toLowerCase().replace(/^#/, ''))
  // account-number-like tokens the user typed (IBANs): letters and digits, 10+ characters
  for (const m of noEmails.matchAll(/\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{10,34}\b/g)) names.add(m[0].toLowerCase())
  return { emails, hosts, urls, names, allow: allowlist.map((a) => a.toLowerCase().trim()), confirmed: new Set(confirmed.map((c) => normalizeDestination(c)).map((d) => d.url ?? d.value)) }
}

const underHost = (host: string, parent: string) => host === parent || host.endsWith(`.${parent}`)

function allowMatches(d: Destination, allow: string[]): boolean {
  for (const a of allow) {
    if (a.includes('@')) { if (d.kind === 'email' && d.value === a) return true; continue }
    // every channel/member of the organisation's own chat workspace: chat-type fields only, never payments, phones or repos
    if (a === '#*') { if (d.kind === 'name' && /^(channel|channel_id|channel_name|recipient|recipients|user|users|member|members|chat|chat_id|invitees?|participants?)$/i.test(d.key ?? '') && !/^[A-Z]{2}\d{2}/i.test(d.value) && !/^\+?[\d ()-]{7,}$/.test(d.value)) return true; continue }
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
export function shownDestination(d: Destination, forLog = false): string {
  // logs keep the domain but not the local part / long names, which could themselves carry data
  if (forLog && d.kind === 'email') return `${d.value.split('@')[0].slice(0, 1)}…@${d.host}`
  if (forLog && d.kind === 'name') return d.value.length > 24 ? `${d.value.slice(0, 12)}…` : d.value
  if (d.kind !== 'host' || !d.url) return d.value
  try { const u = new URL(d.url); return `${d.host}${u.pathname === '/' ? '' : u.pathname}${u.search || u.hash ? ' (with data in the link)' : ''}` } catch { return d.value }
}

export function decide(call: ProposedCall, ctx: Context, legsOverride?: ReadonlySet<string>): Decision {
  const legs = legsOverride ?? classifyTool(call.tool).legs
  const dests0 = extractDestinations(call.args)
  const trusted0 = trustedFrom(ctx.instruction, ctx.allowlist, ctx.confirmed)
  const contentUrl = dests0.some((d) => d.kind === 'host' && provenanceOf(d, trusted0) === 'content')
  // fail closed: unlabelled tools act as outbound once private data is in play (or when they carry an address);
  // writes into someone's repository/project are outbound; any tool handed a link nobody named is outbound after a private read
  const hasStringArg = JSON.stringify(call.args).includes('"') && Object.values(call.args).some((v) => typeof v === 'string' ? v.length > 0 : v !== null && typeof v === 'object')
  const outbound = legs.has('outbound') || (legs.size === 0 && ((ctx.taint.privateSeen && hasStringArg) || dests0.length > 0)) || dests0.some((d) => d.key === 'repo') || (ctx.taint.privateSeen && contentUrl)
  if (!outbound) return { action: 'allow', rule: 'R0', reason: 'not an outbound tool', destinations: [] }
  const trusted = trusted0
  const dests = dests0.map((d) => ({ ...d, provenance: provenanceOf(d, trusted), origin: originOf(d, ctx.taint) }))
  const fromContent = dests.filter((d) => d.provenance === 'content')
  const leak = ctx.taint.privateSeen ? ctx.taint.secrets.find(call.args) : null
  const urlLeak = ctx.taint.privateSeen && dests.some((d) => bareHostTrust(d, trusted)) ? ctx.taint.secrets.find({ urls: dests.filter((d) => bareHostTrust(d, trusted)).map((d) => d.url ?? '') }) : null
  if (dests.length > 0 && fromContent.length === 0 && urlLeak) {
    return { action: 'block', rule: 'R4', reason: `the call carries private data (${leak}) in a URL path on a host the user only named in passing`, destinations: dests }
  }
  if (dests.length > 0 && fromContent.length === 0) return { action: 'allow', rule: 'R1', reason: 'every destination came from the user, the allowlist or a confirmation', destinations: dests }
  const writesExisting = !/^(create|add|schedule|new|make)/i.test(call.tool.name)
  if (dests.length === 0 && isInternalWrite(call.tool) && !(writesExisting && leak)) return { action: 'allow', rule: 'R5', reason: 'writes to the user\'s own workspace with no outside recipient', destinations: [] }
  if (!ctx.taint.privateSeen) return { action: 'allow', rule: 'R3', reason: 'no private data in play yet, nothing to leak', destinations: dests }
  // R6: a fetch-only tool visiting a link copied character for character from content (no query string, not a shared platform)
  // sends nothing the agent chose; any link the agent built itself goes to the user
  if (isFetchOnly(call.tool) && fromContent.length > 0 && fromContent.every((d) => d.kind === 'host' && d.url && !/[?#]/.test(d.url) && !isShared(d.value) && ctx.taint.origins.has(d.url))) {
    return { action: 'allow', rule: 'R6', reason: 'visiting a link exactly as it appeared in content', destinations: dests }
  }
  const who = fromContent.length ? fromContent.map((d) => shownDestination(d)).join(', ') : 'an unnamed destination'
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
  const found = extractDestinations({ answer }).filter((d) => d.kind === 'host')
  return found.filter((d) => provenanceOf(d, trusted) === 'content').map((d) => d.url ?? d.value)
}
