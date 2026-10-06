import type { ToolSpec } from '../domain/types'

/** Extract MCP tool declarations from one source file (TypeScript/JavaScript, Python, Go). Heuristic, pure. */
export function extractTools(path: string, src: string): ToolSpec[] {
  const out: ToolSpec[] = []
  const seen = new Set<string>()
  const push = (name: string, description: string, params: string[]) => {
    if (!/^[A-Za-z][\w.-]{1,63}$/.test(name) || seen.has(name)) return
    seen.add(name); out.push({ name, description: description.replace(/\s+/g, ' ').trim().slice(0, 400), params: [...new Set(params)].slice(0, 20) })
  }
  const Q = `["'\`]`
  const str = `${Q}((?:[^"'\`\\\\]|\\\\.){0,600}?)${Q}`
  const after = (i: number) => src.slice(i, i + 1500)
  const propKeys = (chunk: string): string[] => {
    const p = chunk.search(/properties\s*[:=]\s*[{(]|z\.object\(\s*\{|inputSchema\s*:\s*\{/)
    if (p < 0) return [...chunk.slice(0, 700).matchAll(/["']?([a-zA-Z_]\w*)["']?\s*:\s*z\./g)].map((m) => m[1])
    const body = chunk.slice(p, p + 900)
    return [...body.matchAll(/["']?([a-zA-Z_][\w]*)["']?\s*:\s*(?:z\.|\{|["']?type|Type\.|\[)/g)].map((m) => m[1]).filter((k) => !['properties', 'type', 'description', 'inputSchema', 'items', 'object', 'required', 'enum', 'default', 'z'].includes(k))
  }
  if (/\.(ts|tsx|js|mjs|cjs)$/.test(path)) {
    for (const m of src.matchAll(new RegExp(`\\.tool\\(\\s*${str}\\s*,\\s*${str}`, 'g'))) push(m[1], m[2], propKeys(after(m.index ?? 0)))
    for (const m of src.matchAll(new RegExp(`registerTool\\(\\s*${str}\\s*,\\s*\\{[\\s\\S]{0,400}?description\\s*:\\s*${str}`, 'g'))) push(m[1], m[2], propKeys(after(m.index ?? 0)))
    for (const m of src.matchAll(new RegExp(`name\\s*:\\s*${str}\\s*,\\s*(?:title\\s*:\\s*${str}\\s*,\\s*)?description\\s*:\\s*${str}`, 'g'))) {
      const ctx = after(m.index ?? 0)
      if (/inputSchema|input_schema|parameters|schema\s*:|handler\s*[:(]|annotations/.test(ctx.slice(0, 1200))) push(m[1], m[3], propKeys(ctx))
    }
  }
  if (/\.py$/.test(path)) {
    for (const m of src.matchAll(/@(?:\w+\.)?tool\s*(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)[^:]*:\s*\n\s*(?:r|f)?("""|''')([\s\S]{0,600}?)\3/g)) {
      const params = m[2].split(',').map((x) => x.trim().split(/[:=\s]/)[0]).filter((x) => x && x !== 'self' && x !== 'ctx' && !x.startsWith('*'))
      push(m[1], m[4], params)
    }
    for (const m of src.matchAll(/@(?:\w+\.)?tool\s*\(\s*(?:name\s*=\s*)?["']([\w.-]+)["'][^)]*?description\s*=\s*["']([^"']{0,400})["']/g)) push(m[1], m[2], [])
    for (const m of src.matchAll(/Tool\(\s*name\s*=\s*["']([\w.-]+)["']\s*,\s*description\s*=\s*(?:\(?\s*)["']([^"']{0,400})["']/g)) push(m[1], m[2], propKeys(after(m.index ?? 0)))
  }
  if (/\.go$/.test(path)) {
    for (const m of src.matchAll(/NewTool\(\s*"([\w.-]+)"\s*,\s*(?:mcp\.)?WithDescription\(\s*(?:\w+\(\s*"[^"]*"\s*,\s*)?"((?:[^"\\]|\\.){0,400})"/g)) {
      const ctx = after(m.index ?? 0)
      push(m[1], m[2], [...ctx.slice(0, 1200).matchAll(/mcp\.With(?:String|Number|Boolean|Array|Object)\(\s*"(\w+)"/g)].map((x) => x[1]))
    }
  }
  return out
}
