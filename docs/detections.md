# Using the audit log in a SIEM

`scripts/mcp-proxy.ts --log audit.jsonl` writes one JSON event per gate decision (ECS-style field names) with a sequence number
`seq`, `prev_hash`/`hash` and a final `session_end` record. Set `TRIFECTA_AUDIT_KEY`: the chain is then HMAC-SHA-256 and a
writer without the key cannot recompute it (without a key it is plain SHA-256 and the proxy warns). `scripts/verify-audit.ts`
checks the chain and refuses a log without `session_end` (cut short). Ship events to the SIEM as they are written so the latest
hash lives outside the machine.
Destinations are logged with the e-mail local part and long channel names shortened; query strings and private text never
appear. Blocked events carry `threat.framework.name: MITRE ATLAS` and `threat.technique.id: [AML.T0051.001, AML.T0057]` (indirect prompt
injection, LLM data leakage).

## Sigma rule — an agent tried to send data to a destination nobody named
```yaml
title: AI agent send blocked by Trifecta Gate
id: 70d34a34-8028-4538-9f10-e3c4f206b2d6
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
```

## Elastic
Kibana query (KQL):
```
event.outcome : "block" and rule.id : ("R2" or "R4")
```
Three or more blocks on one tool in ten minutes (an agent repeatedly following a planted instruction), ES|QL:
```
FROM trifecta-audit
| WHERE event.outcome == "block"
| STATS blocks = COUNT(*) BY tool, bucket = BUCKET(@timestamp, 10 minutes)
| WHERE blocks >= 3
```

## Microsoft Sentinel (Kusto)
```
TrifectaAudit_CL
| where event_outcome_s == "block"
| summarize blocks = count() by tool_s, bin(TimeGenerated, 10m)
| where blocks >= 3
```

## Who owns what (small office)
- **Allowlist and tool labels:** the IT lead; changes reviewed by a second person (the office manager) and kept in version control.
- **Confirmations:** the person who gave the agent the task; every confirmation is an audit event (`event.action: confirm`).
- **Review:** weekly look at blocked events; a burst of blocks on one inbox or document points to a planted instruction to remove.
- **Frameworks:** OWASP Top 10 for LLM Applications 2025 (LLM01, LLM02, LLM06); MITRE ATLAS (AML.T0051.001, AML.T0057);
  NIST AI RMF — the gate is a MANAGE-function control (risk treatment) whose block log feeds MEASURE.
