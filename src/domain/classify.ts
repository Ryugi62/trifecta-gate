import { LEGS, type Classification, type Leg, type ToolSpec } from './types'

/** Words are matched as whole tokens; rules are data so the scanner and the web demo share them. */
export const RULES = {
  readVerbs: ['read', 'get', 'list', 'search', 'fetch', 'retrieve', 'returns', 'return', 'query', 'find', 'lookup', 'browse', 'scrape', 'view', 'download', 'open', 'select', 'export', 'load', 'crawl', 'extract', 'navigate', 'visit'],
  outboundVerbs: ['send', 'post', 'publish', 'reply', 'forward', 'share', 'upload', 'tweet', 'notify', 'invite', 'webhook', 'push', 'transfer', 'pay', 'dm', 'sms', 'broadcast', 'submit', 'email', 'message', 'comment', 'curl', 'request', 'navigate', 'browse', 'visit', 'fetch', 'download', 'http'],
  // verbs that only count as outbound when the tool can be pointed at an arbitrary address (url/endpoint param or url/http/web in name)
  addressOnlyVerbs: ['curl', 'request', 'navigate', 'browse', 'visit', 'fetch', 'download', 'http'],
  // verbs that only count as outbound when they are the tool's first name token or the description's first word
  leadOnlyVerbs: ['email', 'message', 'comment'],
  createTargets: ['issue', 'comment', 'pr', 'gist', 'page', 'post', 'tweet', 'message', 'invite', 'event', 'webhook', 'discussion', 'review'],
  destinationParams: ['to', 'cc', 'bcc', 'recipient', 'recipients', 'url', 'uri', 'endpoint', 'webhook', 'webhook_url', 'webhookurl', 'channel', 'channel_id', 'channelid', 'chat_id', 'chatid', 'phone', 'phone_number', 'email', 'email_address', 'address', 'target_url', 'callback_url', 'href'],
  addressParams: ['url', 'uri', 'endpoint', 'webhook', 'webhook_url', 'webhookurl', 'target_url', 'callback_url', 'href'],
  addressNameWords: ['url', 'http', 'https', 'web', 'webpage', 'website', 'browser', 'curl'],
  privateNouns: ['inbox', 'mailbox', 'email', 'emails', 'mail', 'mails', 'gmail', 'outlook', 'drive', 'file', 'files', 'document', 'documents', 'doc', 'docs', 'calendar', 'calendars', 'contact', 'contacts', 'note', 'notes', 'database', 'databases', 'db', 'sql', 'record', 'records', 'customer', 'customers', 'patient', 'patients', 'crm', 'account', 'accounts', 'secret', 'secrets', 'credential', 'credentials', 'password', 'passwords', 'env', 'memories', 'history', 'clipboard', 'filesystem', 'spreadsheet', 'spreadsheets', 'repository', 'repositories', 'repo', 'repos', 'dm', 'dms', 'chat', 'chats', 'transaction', 'transactions', 'invoice', 'invoices', 'payroll', 'hr', 'employee', 'employees', 'ticket', 'tickets', 'profile', 'profiles', 'bank', 'balance', 'balances', 'health', 'medical', 'payment', 'payments', 'order', 'orders', 'cart', 'carts', 'checkout', 'checkouts', 'transfer', 'transfers', 'charge', 'charges', 'card', 'cards', 'loan', 'loans', 'consent', 'consents', 'dispute', 'disputes', 'bill', 'bills', 'statement', 'statements', 'message', 'messages', 'conversation', 'conversations', 'thread', 'threads', 'event', 'events', 'meeting', 'meetings'],
  untrustedNouns: ['web', 'webpage', 'website', 'websites', 'url', 'urls', 'internet', 'html', 'rss', 'feed', 'feeds', 'inbox', 'mailbox', 'email', 'emails', 'mail', 'mails', 'gmail', 'outlook', 'issue', 'issues', 'comment', 'comments', 'pull', 'pr', 'prs', 'ticket', 'tickets', 'review', 'reviews', 'tweet', 'tweets', 'post', 'posts', 'reddit', 'news', 'article', 'articles', 'google', 'bing', 'duckduckgo', 'slack', 'discord', 'telegram', 'whatsapp', 'channel', 'channels', 'form', 'forms', 'submission', 'submissions', 'invite', 'invites', 'invitation', 'invitations', 'youtube', 'transcript', 'transcripts', 'scrape', 'crawl', 'browser', 'message', 'messages', 'paper', 'papers', 'pdf', 'arxiv', 'wikipedia', 'webhook', 'conversation', 'conversations', 'thread', 'threads'],
}

const set = (xs: string[]) => new Set(xs)
const R = {
  readVerbs: set(RULES.readVerbs), outboundVerbs: set(RULES.outboundVerbs), addressOnly: set(RULES.addressOnlyVerbs), leadOnly: set(RULES.leadOnlyVerbs),
  createTargets: set(RULES.createTargets), destinationParams: set(RULES.destinationParams), addressParams: set(RULES.addressParams),
  addressNameWords: set(RULES.addressNameWords), privateNouns: set(RULES.privateNouns), untrustedNouns: set(RULES.untrustedNouns),
}

export function nameTokens(name: string): string[] {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)
}
export function textTokens(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)
}

export function classifyTool(spec: ToolSpec): Classification {
  const nt = nameTokens(spec.name)
  const dt = textTokens(spec.description).slice(0, 60)
  const params = spec.params.map((p) => p.toLowerCase())
  const all = [...nt, ...dt]
  const evidence: Record<Leg, string[]> = { private: [], untrusted: [], outbound: [] }
  const add = (leg: Leg, why: string) => { if (!evidence[leg].includes(why)) evidence[leg].push(why) }

  const canAddress = params.some((p) => R.addressParams.has(p)) || nt.some((t) => R.addressNameWords.has(t))
  const lead = new Set([nt[0], dt[0]].filter(Boolean))

  // outbound
  for (const t of nt) {
    if (!R.outboundVerbs.has(t)) continue
    if (R.addressOnly.has(t) && !canAddress) continue
    if (R.leadOnly.has(t) && !lead.has(t)) continue
    add('outbound', `name:${t}`)
  }
  for (const t of dt.slice(0, 12)) {
    if (!R.outboundVerbs.has(t) || R.addressOnly.has(t) || R.leadOnly.has(t)) continue
    add('outbound', `desc:${t}`)
  }
  if (nt.includes('create') || nt.includes('add') || nt.includes('open')) {
    for (const t of nt) if (R.createTargets.has(t)) add('outbound', `name:create+${t}`)
  }
  const dateRange = params.includes('from') && params.includes('to')
  for (const p of params) if (R.destinationParams.has(p) && !(p === 'email' || p === 'address') && !(p === 'to' && dateRange)) add('outbound', `param:${p}`)
  if (canAddress && all.some((t) => R.readVerbs.has(t) || R.addressOnly.has(t))) add('outbound', 'param:url-capable')

  // reading legs need a read verb (or the tool takes a URL and returns content)
  const reads = all.some((t) => R.readVerbs.has(t)) || (canAddress && !evidence.outbound.some((e) => /send|post|publish|upload|reply|forward/.test(e)))
  if (reads) {
    const isSender = nt.some((t) => R.outboundVerbs.has(t) && !R.addressOnly.has(t) && !R.leadOnly.has(t))
    if (!isSender) {
      for (const t of all) if (R.privateNouns.has(t)) add('private', t)
      for (const t of all) if (R.untrustedNouns.has(t)) add('untrusted', t)
      if (canAddress) add('untrusted', 'url-capable')
    }
  }
  // fetching an arbitrary URL is not reading the user's private data
  if (canAddress && evidence.private.length && evidence.private.every((w) => ['user', 'code', 'file', 'files', 'document', 'documents', 'doc', 'docs'].includes(w)) && !nt.some((t) => R.privateNouns.has(t))) evidence.private = []

  const legs = new Set<Leg>(LEGS.filter((l) => evidence[l].length > 0))
  return { tool: spec.name, legs, evidence }
}

export interface ToolsetAnalysis {
  tools: Classification[]
  providers: Record<Leg, string[]>
  trifecta: boolean
}

export function analyzeToolset(specs: ToolSpec[]): ToolsetAnalysis {
  const tools = specs.map(classifyTool)
  const providers: Record<Leg, string[]> = { private: [], untrusted: [], outbound: [] }
  for (const c of tools) for (const l of c.legs) providers[l].push(c.tool)
  return { tools, providers, trifecta: LEGS.every((l) => providers[l].length > 0) }
}

export interface Fix { leg: Leg; tools: string[] }

/** Smallest removal that breaks the trifecta: the leg with the fewest providers (ties → outbound, the leak itself). */
export function suggestFix(specs: ToolSpec[]): Fix | null {
  const a = analyzeToolset(specs)
  if (!a.trifecta) return null
  const order: Leg[] = ['outbound', 'untrusted', 'private']
  let best: Leg = 'outbound'
  for (const l of order) if (a.providers[l].length < a.providers[best].length) best = l
  return { leg: best, tools: a.providers[best] }
}
