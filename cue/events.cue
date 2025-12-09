package events

// Generic event envelope used by the policy engine (EngineEvent).

Event: {
  kind:   string
  fields: [string]: Value
}

Value:  string | number | bool

// Example specialized event shapes that map into Event.fields.

AICallEvent: {
  kind: "ai_call"
  fields: {
    tenant_id?: string
    model_id?:  string
    severity?:  string
    entropy?:   number
    // Additional arbitrary fields allowed
    [string]: Value
  }
}

PaymentTxEvent: {
  kind: "payment_tx"
  fields: {
    tenant_id?: string
    amount?:    number
    currency?:  string
    severity?:  string
    [string]:   Value
  }
}

RecordAccessEvent: {
  kind: "record_access"
  fields: {
    tenant_id?: string
    record_id?: string
    severity?:  string
    [string]:   Value
  }
}
