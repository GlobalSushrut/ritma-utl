package truthscript

// TruthScript policy schema mirroring crates/truthscript/src/lib.rs

Policy: {
  name:    string
  version: string
  rules: [...Rule]
}

Rule: {
  name: string
  when?: When
  actions: [...Action]
}

When: {
  event?:      string
  conditions?: [...Condition]
}

// Tagged union matching serde(tag="kind", rename_all="snake_case")
Condition: EventEquals | FieldEquals | FieldGreaterThan | EntropyGreaterThan | CountGreaterThan

EventEquals: {
  kind:  "event_equals"
  value: string
}

FieldEquals: {
  kind:  "field_equals"
  field: string
  value: string
}

FieldGreaterThan: {
  kind:      "field_greater_than"
  field:     string
  threshold: number
}

EntropyGreaterThan: {
  kind:      "entropy_greater_than"
  threshold: number
}

CountGreaterThan: {
  kind:      "count_greater_than"
  counter:   string
  threshold: int
}

// Actions the engine may take when a rule fires.
Action: SealCurrentDig
      | FlagForInvestigation
      | RequireDistilliumProof
      | RequireUnknownLogicCapsule
      | CaptureInput
      | CaptureOutput
      | RecordField
      | RequireSnarkProof
      | RequirePolicyEvalProof
      | RequireDigInclusionProof
      | Deny

SealCurrentDig: {
  kind: "seal_current_dig"
}

FlagForInvestigation: {
  kind:   "flag_for_investigation"
  reason: string
}

RequireDistilliumProof: {
  kind: "require_distillium_proof"
}

RequireUnknownLogicCapsule: {
  kind: "require_unknown_logic_capsule"
}

CaptureInput: {
  kind: "capture_input"
}

CaptureOutput: {
  kind: "capture_output"
}

RecordField: {
  kind:  "record_field"
  field: string
}

RequireSnarkProof: {
  kind: "require_snark_proof"
}

RequirePolicyEvalProof: {
  kind: "require_policy_eval_proof"
}

RequireDigInclusionProof: {
  kind: "require_dig_inclusion_proof"
}

Deny: {
  kind:   "deny"
  reason: string
}
