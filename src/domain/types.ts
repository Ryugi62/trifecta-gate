export type Leg = 'private' | 'untrusted' | 'outbound'
export const LEGS: readonly Leg[] = ['private', 'untrusted', 'outbound']

export interface ToolSpec {
  name: string
  description: string
  params: string[]
}

export interface Classification {
  tool: string
  legs: Set<Leg>
  evidence: Record<Leg, string[]>
}
