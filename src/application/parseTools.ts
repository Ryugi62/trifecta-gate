import type { ToolSpec } from '../domain/types'

/** Accepts MCP `tools/list` JSON, an array of tools, or one tool per line ("name: description"). */
export function parseToolList(text: string): ToolSpec[] {
  const t = text.trim()
  if (!t) return []
  if (t.startsWith('{') || t.startsWith('[')) {
    try {
      const j = JSON.parse(t) as unknown
      const arr = Array.isArray(j) ? j : ((j as { tools?: unknown[]; result?: { tools?: unknown[] } }).tools ?? (j as { result?: { tools?: unknown[] } }).result?.tools ?? [])
      return (arr as Array<Record<string, unknown>>).filter((x) => typeof x?.name === 'string').map((x) => {
        const schema = (x.inputSchema ?? x.input_schema ?? x.parameters ?? {}) as { properties?: Record<string, unknown> }
        return { name: String(x.name), description: String(x.description ?? ''), params: Object.keys(schema.properties ?? {}) }
      })
    } catch { /* fall through to lines */ }
  }
  return t.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    const m = l.match(/^([A-Za-z][\w.-]*)\s*(?:\(([^)]*)\))?\s*[:\-–—]?\s*(.*)$/)
    if (!m) return null
    return { name: m[1], description: m[3] ?? '', params: (m[2] ?? '').split(',').map((p) => p.trim()).filter(Boolean) }
  }).filter((x): x is ToolSpec => !!x)
}
