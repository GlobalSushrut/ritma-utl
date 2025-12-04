package policies

// Canonical schema for a tenant lawbook (CUE version of tenant_policy::Lawbook).

#Lawbook: {
    tenant_id: string & != ""
    policy_id: string & != ""
    version: int & >= 1
    description?: string
    meta?: [string]: _
    rules: [...#Rule]
}

#Rule: {
    name: string & != ""
    when: #When
    action: #RuleAction
}

#When: {
    event_kind: string
    // All conditions must hold (logical AND).
    conditions?: [...#Condition]
}

#Condition: {
    kind: "field_equals" | "field_not_in" | "field_greater_equal"
    field: string

    // field_equals: exact match on a field value.
    if kind == "field_equals" {
        value: _
    }

    // field_not_in: field value must not be in the list.
    if kind == "field_not_in" {
        values: [..._]
    }

    // field_greater_equal: numeric comparison.
    if kind == "field_greater_equal" {
        threshold: number
    }
}

#RuleAction: {
    kind: "allow" | "deny" | "rewrite" | "escalate"
    reason?: string
    // Evidence guarantees (e.g. seal dig, must log).
    evidence?: [...#EvidenceKind]
}

#EvidenceKind: "seal_digfile" | "must_log"
