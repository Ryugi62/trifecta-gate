# Using the audit log in a SIEM

`scripts/mcp-proxy.ts --log audit.jsonl` writes one JSON event per gate decision (ECS-style field names). Each event carries
`prev_hash`/`hash` (SHA-256, or HMAC-SHA-256 when `TRIFECTA_AUDIT_KEY` is set); `scripts/verify-audit.ts` checks the chain.
Destinations are logged with the e-mail local part and long channel names shortened; query strings and private text never
appear. Blocked events carry `threat.framework: MITRE ATLAS` with `AML.T0051.001` (indirect prompt injection) and `AML.T0057`
(LLM data leakage).

## Sigma rule — an agent tried to send data to a destination nobody named
```yaml
title: AI agent send blocked by Trifecta Gate
id: 7b0c2f0e-4c1e-4c55-9d7e-trifecta-r2r4
status: experimental
description: An AI agent tried to send private data to a destination that came from outside content (rules R2/R4).
logsource:
  product: trifecta-gate
  service: mcp-proxy
detection:
  selection:
    event.outcome: block
    rule.id:
      - R2
      - R4
  condition: selection
falsepositives:
  - Replies to outside senders, payments to accounts found in bills (these need one user confirmation by design)
level: high
tags:
  - attack.exfiltration
  - atlas.aml.t0051.001
  - atlas.aml.t0057
```

## Elastic / KQL
```
event.outcome : "block" and rule.id : ("R2" or "R4")
```
Alert when the same tool is blocked three or more times in ten minutes (an agent repeatedly following a planted instruction):
```
event.outcome : "block" | stats count() by tool, bin(@timestamp, 10m) | where count >= 3
```

## Who owns what (small office)
- **Allowlist and tool labels:** the IT lead; changes reviewed by a second person (the office manager) and kept in version control.
- **Confirmations:** the person who gave the agent the task; every confirmation is an audit event (`event.action: confirm`).
- **Review:** weekly look at blocked events; a burst of blocks on one inbox or document points to a planted instruction to remove.
- **Frameworks:** OWASP Top 10 for LLM Applications 2025 (LLM01, LLM02, LLM06); MITRE ATLAS (AML.T0051.001, AML.T0057);
  NIST AI RMF — the gate is a MANAGE-function control (risk treatment) whose block log feeds MEASURE.
