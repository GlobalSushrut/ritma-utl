package tenant_lawbook

// Tenant lawbook schema mirroring crates/tenant_policy/src/lib.rs

Lawbook: {
  tenant_id: string & !=""
  policy_id: string & !=""
  version:   uint & >0
  description?: string
  meta?: [string]: _
  rules: [...Rule]
}

Rule: {
  name: string & !=""
  when: When
  action: RuleAction
}

When: {
  event_kind: string
  conditions?: [...Condition]
}

Condition: FieldEquals | FieldNotIn | FieldGreaterEqual

FieldEquals: {
  kind:  "field_equals"
  field: string
  value: _
}

FieldNotIn: {
  kind:   "field_not_in"
  field:  string
  values: [..._]
}

FieldGreaterEqual: {
  kind:      "field_greater_equal"
  field:     string
  threshold: _
}

RuleAction: {
  kind:     ActionKind
  reason?:  string
  evidence: [...EvidenceKind]
}

ActionKind: "allow" | "deny" | "rewrite" | "escalate"

EvidenceKind: "seal_digfile" | "must_log"

// High-risk event kinds should request evidence; this is a soft constraint
HighRiskEventKinds: [
  "record_access",
  "payment_tx",
  "ai_call",
]
