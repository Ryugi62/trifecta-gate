import { describe, it, expect } from 'vitest'
import { parseToolList } from '../src/application/parseTools'

describe('parseToolList', () => {
  it('reads MCP tools/list JSON', () => {
    const j = JSON.stringify({ tools: [{ name: 'send_email', description: 'Send mail', inputSchema: { type: 'object', properties: { to: {}, body: {} } } }] })
    expect(parseToolList(j)).toEqual([{ name: 'send_email', description: 'Send mail', params: ['to', 'body'] }])
  })
  it('reads one tool per line with optional params', () => {
    expect(parseToolList('fetch_url(url): Fetch a web page\nread_inbox - Read my email')).toEqual([
      { name: 'fetch_url', description: 'Fetch a web page', params: ['url'] },
      { name: 'read_inbox', description: 'Read my email', params: [] },
    ])
  })
})
