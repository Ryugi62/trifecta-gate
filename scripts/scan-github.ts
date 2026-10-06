// Scan public MCP server repositories on GitHub: shallow-clone, extract tool declarations, classify legs, aggregate.
// usage: tsx scripts/scan-github.ts [maxRepos]
import { execFileSync, execFile } from 'node:child_process'
import { promisify } from 'node:util'
const pexec = promisify(execFile)
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { extractTools } from '../src/application/extract'
import { analyzeToolset, suggestFix } from '../src/domain/classify'

const max = Number(process.argv[2] ?? 250)
const cache = '.cache/repos'
mkdirSync(cache, { recursive: true })

interface Repo { fullName: string; stargazersCount: number; language: string; url: string; updatedAt: string; description: string }
const listFile = 'data/scan-repos.json'
let repos: Repo[]
if (existsSync(listFile)) repos = JSON.parse(readFileSync(listFile, 'utf8'))
else {
  const seen = new Map<string, Repo>()
  for (const topic of ['mcp-server', 'model-context-protocol', 'mcp']) {
    const j = JSON.parse(execFileSync('gh', ['search', 'repos', '--topic', topic, '--sort', 'stars', '--limit', '400', '--json', 'fullName,stargazersCount,language,url,updatedAt,description'], { encoding: 'utf8', maxBuffer: 64 << 20 })) as Repo[]
    for (const r of j) if (!seen.has(r.fullName)) seen.set(r.fullName, r)
  }
  repos = [...seen.values()].filter((r) => /mcp/i.test(r.fullName.split('/')[1])).sort((a, b) => b.stargazersCount - a.stargazersCount)
  writeFileSync(listFile, JSON.stringify(repos, null, 1))
}

const walk = (d: string, depth = 0): string[] => {
  if (depth > 8) return []
  let out: string[] = []
  for (const f of readdirSync(d)) {
    if (/^(node_modules|\.git|dist|build|vendor|test|tests|__tests__|examples?|docs?)$/.test(f)) continue
    const p = join(d, f)
    let st; try { st = statSync(p) } catch { continue }
    if (st.isDirectory()) out = out.concat(walk(p, depth + 1))
    else if (/\.(ts|js|mjs|py|go)$/.test(f) && !/\.d\.ts$|\.test\.|\.spec\.|\.min\.js$/.test(f) && st.size < 400_000) out.push(p)
  }
  return out
}

const results: Array<Record<string, unknown>> = []
let scanned = 0
let idx = 0
const pool = repos.slice(0, Math.round(max * 1.6))
async function worker() {
  while (idx < pool.length && scanned < max) {
    const r = pool[idx++]
    const dir = join(cache, r.fullName.replace('/', '__'))
    if (!existsSync(join(dir, '.git'))) {
      try { await pexec('git', ['clone', '--depth', '1', '--filter=blob:limit=200k', '--quiet', `https://github.com/${r.fullName}.git`, dir], { timeout: 120_000 }) } catch { continue }
    }
    const specs = walk(dir).flatMap((f) => { try { return extractTools(f, readFileSync(f, 'utf8')) } catch { return [] } })
    const uniq = [...new Map(specs.map((s) => [s.name, s])).values()]
    rmSync(dir, { recursive: true, force: true }) // keep only extracted specs (disk budget)
    if (uniq.length === 0 || scanned >= max) continue
    scanned++
    const a = analyzeToolset(uniq)
    results.push({ repo: r.fullName, stars: r.stargazersCount, language: r.language, tools: a.tools.map((t) => ({ name: t.tool, legs: [...t.legs], evidence: t.evidence })), specs: uniq, providers: a.providers, trifecta: a.trifecta, fix: suggestFix(uniq) })
    process.stdout.write(`${scanned}\t${r.fullName}\t${uniq.length} tools\t${a.trifecta ? 'TRIFECTA' : ''}\n`)
  }
}
await Promise.all(Array.from({ length: 6 }, worker))
results.sort((a, b) => (b.stars as number) - (a.stars as number))
writeFileSync('data/scan.json', JSON.stringify({ ranAt: new Date().toISOString(), candidates: repos.length, servers: results }, null, 1))
console.log('servers with tools:', scanned, 'of', idx, 'repos tried')
