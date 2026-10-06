export type Leg = 'private' | 'untrusted' | 'outbound'
export const LEGS: readonly Leg[] = ['private', 'untrusted', 'outbound']

export interface ToolSpec {
  name: string
  description: string
  params: string[]
  /** MCP tool annotations, when the server provides them */
  annotations?: { readOnlyHint?: boolean; openWorldHint?: boolean; destructiveHint?: boolean }
}

export interface Classification {
  tool: string
  legs: Set<Leg>
  evidence: Record<Leg, string[]>
}
