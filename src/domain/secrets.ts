/**
 * Private-data fingerprints without keeping the text.
 * - every 12-character window of the NFKC-normalised, case-folded letters-and-digits (any script) private text, as a 53-bit hash
 * - short secrets (passwords, PINs, SSNs, card numbers, keys) found by pattern, kept as hashes too
 * Outgoing arguments are checked raw, URL-decoded, base64-decoded and hex-decoded, so case changes,
 * punctuation, encoding and splitting a secret across fields do not hide it.
 */
export const WINDOW = 12

// case-folded, compatibility-normalised letters and digits of any script (Hangul, Cyrillic…)
const norm = (s: string) => s.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '')

/** 53-bit fingerprint (two independent 32-bit FNV-style hashes), so false matches stay negligible at megabyte scale */
function hash(s: string, from: number, len: number): number {
  let a = 2166136261, b = 0x811c9dc5 ^ 0x5bd1e995
  for (let i = from; i < from + len; i++) { const c = s.charCodeAt(i); a = Math.imul(a ^ c, 16777619); b = Math.imul(b + c, 0x5bd1e995) ^ (b >>> 15) }
  return (a >>> 0) * 2097152 + ((b >>> 0) & 0x1fffff)
}

const SHORT_SECRET_PATTERNS: RegExp[] = [
  /\b(?:password|passcode|passwd|pwd|pin|api[ _-]?key|token|secret|code)\b(?:\s+is)?\s*[:=]?\s*(\S{4,})/gi,
  /\b\d{3}-\d{2}-\d{4}\b/g, // SSN
  /\b(?:\d[ -]?){13,19}\b/g, // card-like
  /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g, // IBAN-like
  /\b(?:sk|pk|ghp|xox[abp])[-_][A-Za-z0-9_-]{10,}\b/g, // API keys
]

function decodings(v: string): string[] {
  const out = [v]
  try { out.push(decodeURIComponent(v.replace(/\+/g, ' '))) } catch { /* keep */ }
  for (const tok of v.match(/[A-Za-z0-9+/_-]{12,}={0,2}/g) ?? []) {
    try {
      const b = tok.replace(/-/g, '+').replace(/_/g, '/')
      const d = typeof atob === 'function' ? atob(b + '='.repeat((4 - (b.length % 4)) % 4)) : ''
      if (/^[\x20-\x7e\s]{6,}$/.test(d)) out.push(d)
    } catch { /* not base64 */ }
  }
  for (const tok of v.match(/\b(?:[0-9a-f]{2}){8,}\b/gi) ?? []) {
    const d = tok.replace(/../g, (h) => String.fromCharCode(parseInt(h, 16)))
    if (/^[\x20-\x7e\s]+$/.test(d)) out.push(d)
  }
  return out
}

export interface SecretIndex {
  add(text: string): void
  /** a short description of what matched (never the matched text), or null */
  find(args: Record<string, unknown>): string | null
  readonly size: number
}

function strings(v: unknown, out: string[]): void {
  if (typeof v === 'string') out.push(v)
  else if (Array.isArray(v)) v.forEach((x) => strings(x, out))
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => strings(x, out))
}

export function secretsIndex(): SecretIndex {
  const windows = new Set<number>()
  const shorts = new Map<number, number>() // hash -> length
  return {
    add(text: string) {
      const n = norm(text)
      for (let i = 0; i + WINDOW <= n.length; i++) windows.add(hash(n, i, WINDOW))
      for (const re of SHORT_SECRET_PATTERNS) for (const m of text.matchAll(re)) {
        const s = norm(m[1] ?? m[0])
        if (s.length >= 4) shorts.set(hash(s, 0, s.length), s.length)
      }
    },
    find(args: Record<string, unknown>) {
      const vals: string[] = []
      strings(args, vals)
      const all = norm(vals.flatMap(decodings).join(' '))
      for (let i = 0; i + WINDOW <= all.length; i++) if (windows.has(hash(all, i, WINDOW))) return 'a 12-character run of private text'
      const lens = new Set(shorts.values())
      for (const L of lens) for (let i = 0; i + L <= all.length; i++) if (shorts.get(hash(all, i, L)) === L) return 'a password, key or ID number from private data'
      return null
    },
    get size() { return windows.size + shorts.size },
  }
}
