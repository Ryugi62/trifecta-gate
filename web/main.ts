import { analyzeToolset, suggestFix } from '../src/domain/classify'
import { parseToolList } from '../src/application/parseTools'
import type { Leg } from '../src/domain/types'

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)
const LEG_TEXT: Record<Leg, string> = { private: 'reads private data', untrusted: "reads outsiders' text", outbound: 'can send out' }
const LEG_VERB: Record<Leg, string> = { private: 'read private data', untrusted: "read outsiders' text", outbound: 'send data out' }

const PRESETS: Record<string, string> = {
  town: ['read_inbox: Read the latest emails in the clerk mailbox', 'read_document(path): Read a document from the town drive', 'fetch_url(url): Fetch a web page by URL and return its text', 'send_email(to, subject, body): Send an email to a recipient', 'post_message(channel, text): Post a message to a team chat channel'].join('\n'),
  safe: ['read_document(path): Read a document from the town drive', 'list_calendar: List calendar events for this week', 'summarize_text(text): Summarize a block of text'].join('\n'),
}

function renderCheck(): void {
  const specs = parseToolList($<HTMLTextAreaElement>('tools').value)
  const out = $('result')
  if (!specs.length) { out.innerHTML = '<div class="verdict ok"><p>Paste at least one tool, one per line, to check it.</p></div>'; return }
  const a = analyzeToolset(specs)
  const fix = suggestFix(specs)
  const have = (['private', 'untrusted', 'outbound'] as Leg[]).filter((l) => a.providers[l].length)
  const rows = a.tools.map((t) => `<tr><td><code>${esc(t.tool)}</code></td><td>${[...t.legs].map((l) => `<span class="pill ${l}">${LEG_TEXT[l]}</span>`).join('') || '<span style="color:var(--dim)">none</span>'}</td></tr>`).join('')
  const evidence = a.tools.map((t) => `<li><code>${esc(t.tool)}</code>: ${(['private', 'untrusted', 'outbound'] as Leg[]).filter((l) => t.evidence[l].length).map((l) => `${LEG_TEXT[l]} (${t.evidence[l].map(esc).join(', ')})`).join('; ') || 'no matching words'}</li>`).join('')
  out.innerHTML = a.trifecta
    ? `<div class="verdict no"><b class="big">All 3 of 3</b><p>One injected sentence in a web page or email could make this agent send your data to a stranger.</p>
       <p><strong>Smallest fix:</strong> take away the ability to ${LEG_VERB[fix!.leg]}. Here it comes only from ${fix!.tools.map((t) => `<code>${esc(t)}</code>`).join(', ')}. Or keep every tool and put Trifecta Gate in front of each send.</p></div>`
    : `<div class="verdict ok"><b class="big">${have.length} of 3</b><p>No full trifecta. Missing: ${(['private', 'untrusted', 'outbound'] as Leg[]).filter((l) => !have.includes(l)).map((l) => LEG_TEXT[l]).join(', ')}. Adding a tool that can ${(['private', 'untrusted', 'outbound'] as Leg[]).filter((l) => !have.includes(l)).map((l) => LEG_VERB[l]).join(' or ')} would complete it.</p></div>`
  out.innerHTML += `<table class="legs"><thead><tr><th>Tool</th><th>What it can do</th></tr></thead><tbody>${rows}</tbody></table><details><summary>Why each label</summary><ul>${evidence}</ul></details>`
}

interface Call { tool: string; args: Record<string, unknown>; blocked: boolean }
interface Results {
  headline: { model: string; leakedNoGate: number; leakedGate: number; attacks: number; benignNoGate: number; benignGate: number; benign: number }
  scan: { candidates: number; servers: number; tools: number; share: Record<Leg, number>; rulesShare: Record<Leg, number>; trifectaServers: number }
  replay: { id: string; instruction: string; injection: string; noGate: Call[]; gate: Call[]; model: string; confirmPrompt?: string }
  models: Array<{ model: string; leakedNoGate: number; leakedGate: number; attacks: number }>
  agentdojo: null | { version: string; model: string; rows: Array<{ suite: string; defense: string; tasks: number; utility: number; exfilAttacks: number; exfilSuccess: number; integrityAttacks: number; integritySuccess: number }> }
}

function callLine(c: Call, leakHosts: RegExp): string {
  const dest = String(c.args.to ?? c.args.url ?? c.args.channel ?? c.args.path ?? '')
  const isBad = !c.blocked && leakHosts.test(dest)
  const cls = c.blocked ? 'blocked' : isBad ? 'bad' : 'okstep'
  const tag = c.blocked ? '<span class="tag blocked">Blocked by the gate</span> ' : isBad ? '<span class="tag bad">Leaked</span> ' : ''
  const body = String(c.args.body ?? c.args.text ?? '').slice(0, 90)
  return `<div class="step ${cls}">${tag}<code>${esc(c.tool)}</code> ${esc(dest)}${body ? `<small>${esc(body)}${body.length >= 90 ? '…' : ''}</small>` : ''}</div>`
}

async function loadResults(): Promise<void> {
  let r: Results
  try { r = await (await fetch('./results.json')).json() } catch { $('replayIntro').textContent = 'Recorded results could not be loaded. The checker above still works offline.'; return }
  const h = r.headline
  $('stats').innerHTML = `
    <div class="stat"><b class="no">${h.leakedNoGate} of ${h.attacks}</b><span>injection attacks leaked a secret through ${esc(h.model)} with no gate</span></div>
    <div class="stat"><b class="ok">${h.leakedGate} of ${h.attacks}</b><span>leaked with Trifecta Gate in front of the same agent</span></div>
    <div class="stat"><b>${Math.round(r.scan.share.outbound * 100)}%</b><span>of ${r.scan.servers} public MCP servers ship a tool that can send data out (independent labeller)</span></div>
    <div class="stat"><b>${r.scan.trifectaServers}</b><span>servers have all three abilities on their own (labeller and rules agree)</span></div>`
  const leakHosts = /evil-audit|ext-vendor-sync/i
  $('replayIntro').innerHTML = `Same task, same planted message, ${esc(r.replay.model)}. The request: “${esc(r.replay.instruction)}”<div class="inject"><strong>Planted in the content:</strong> ${esc(r.replay.injection)}</div>`
  $('runs').innerHTML = `<div class="run"><h3>Without the gate</h3>${r.replay.noGate.map((c) => callLine(c, leakHosts)).join('')}</div><div class="run"><h3>With Trifecta Gate</h3>${r.replay.gate.map((c) => callLine(c, leakHosts)).join('')}</div>`
  const s = r.scan
  $('scanBody').innerHTML = `<p>We cloned public GitHub repositories named as MCP servers, pulled out ${s.tools.toLocaleString('en-US')} tool declarations from ${s.servers} servers (of ${s.candidates} repositories found), and had an independent language-model labeller mark each tool. The checker above uses our keyword rules instead; those rules flag more (${Math.round(s.rulesShare.outbound * 100)}% of servers can send data out by the rules).</p>
    <div class="bars">${(['private', 'untrusted', 'outbound'] as Leg[]).map((l) => `<div class="bar">${Math.round(s.share[l] * 100)}% of servers have a tool that ${LEG_TEXT[l]}<div class="track"><div class="fill" style="width:${(s.share[l] * 100).toFixed(1)}%"></div></div></div>`).join('')}</div>
    <p>${s.trifectaServers} servers have all three abilities on their own, counted only where the labeller and the rules agree. We do not list them here: a label is a reason to look, not a finding.</p>
    <details><summary>Other models we tested</summary><ul>${r.models.map((m) => `<li>${esc(m.model)}: ${m.leakedNoGate} of ${m.attacks} leaked without the gate, ${m.leakedGate} with it</li>`).join('')}</ul></details>`
  if (r.agentdojo) {
    const ad = r.agentdojo
    const row = (suite: string, d: string) => ad.rows.find((x) => x.suite === suite && x.defense === d)
    $('dojoBody').innerHTML = `<p>AgentDojo ${esc(ad.version)} is a public benchmark of prompt-injection attacks on agents with email, Slack and banking tools. We ran ${esc(ad.model)} with and without the gate on its standard attack.</p>
      <table class="legs"><thead><tr><th>Suite</th><th>Attacks moving data, money or access out that worked</th><th>Tasks solved, no attack</th></tr></thead><tbody>${['workspace', 'slack', 'banking'].filter((x) => row(x, 'none') && row(x, 'gate')).map((x) => { const n = row(x, 'none')!, g = row(x, 'gate')!; return `<tr><td>${x}</td><td>${n.exfilSuccess}/${n.exfilAttacks} → <strong>${g.exfilSuccess}/${g.exfilAttacks}</strong></td><td>${n.utility}/${n.tasks} → ${g.utility}/${g.tasks}</td></tr>` }).join('')}</tbody></table>
      <details><summary>What the gate does not stop there</summary><p>Attacks that only delete a file, open a website, send a colleague a link or change a password do not move data out, so they are outside the gate's job: ${ad.rows.filter((x) => x.defense === 'none').reduce((a, x) => a + x.integritySuccess, 0)} worked without the gate and ${ad.rows.filter((x) => x.defense === 'gate').reduce((a, x) => a + x.integritySuccess, 0)} with it. Fewer tasks are solved with the gate because some need sending to an address found only in data, which needs your confirmation.</p></details>`
    $('dojo').hidden = false
  }
  if (r.replay.confirmPrompt) $('runs').insertAdjacentHTML('afterend', `<div class="inject" style="background:var(--soft)"><strong>What the user sees:</strong> ${esc(r.replay.confirmPrompt)} <em>Default: Don't allow.</em></div>`)
}

document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((b) => b.addEventListener('click', () => { $<HTMLTextAreaElement>('tools').value = PRESETS[b.dataset.preset!]; renderCheck() }))
$('run').addEventListener('click', renderCheck)
void loadResults()
