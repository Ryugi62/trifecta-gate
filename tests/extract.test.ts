import { describe, it, expect } from 'vitest'
import { extractTools } from '../src/application/extract'

describe('UC5 extractTools', () => {
  it('TypeScript server.tool with zod params', () => {
    const src = `server.tool("send_email", "Send an email to a recipient", { to: z.string(), body: z.string() }, async () => {})`
    expect(extractTools('a.ts', src)).toEqual([{ name: 'send_email', description: 'Send an email to a recipient', params: ['to', 'body'] }])
  })
  it('TypeScript ListTools object literal', () => {
    const src = `tools: [{ name: "fetch_url", description: "Fetch a URL", inputSchema: { type: "object", properties: { url: { type: "string" } } } }]`
    expect(extractTools('b.js', src)[0]).toMatchObject({ name: 'fetch_url', params: ['url'] })
  })
  it('Python FastMCP decorator with docstring', () => {
    const src = `@mcp.tool()\nasync def read_inbox(limit: int = 10) -> str:\n    """Read the latest emails in the mailbox."""\n    return ""`
    expect(extractTools('s.py', src)).toEqual([{ name: 'read_inbox', description: 'Read the latest emails in the mailbox.', params: ['limit'] }])
  })
  it('Go mcp-go NewTool', () => {
    const src = `mcp.NewTool("post_message", mcp.WithDescription("Post a message to a channel"), mcp.WithString("channel"), mcp.WithString("text"))`
    expect(extractTools('m.go', src)).toEqual([{ name: 'post_message', description: 'Post a message to a channel', params: ['channel', 'text'] }])
  })
  it('Go with translation helper', () => {
    const src = `mcp.NewTool("get_me", mcp.WithDescription(t("TOOL_GET_ME_DESCRIPTION", "Get details of the authenticated user")))`
    expect(extractTools('g.go', src)[0]).toMatchObject({ name: 'get_me', description: 'Get details of the authenticated user' })
  })
  it('ignores files without tools', () => {
    expect(extractTools('x.ts', 'const a = 1')).toEqual([])
  })
})
