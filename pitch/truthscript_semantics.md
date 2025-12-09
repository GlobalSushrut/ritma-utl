# TruthScript Semantics (Engine-Level Specification)

This document describes the **concrete operational semantics** implemented by the Rust `policy_engine` crate and the `truthscript` data model. It is the source of truth for how events are evaluated against policies at runtime.

It is intentionally focused on the behavior of the engine, not on UI/editor representations.

---

## 1. Core Types

### 1.1 EngineEvent

An `EngineEvent` is:

- `kind: String` – e.g. `"ai_call"`, `"http_request"`, `"entropy_spike"`.
- `fields: BTreeMap<String, Value>` – arbitrary key/value map.

### 1.2 Value

`Value` is a tagged union:

- `String(String)`
- `Number(f64)`
- `Bool(bool)`

There is **no implicit coercion** between these variants inside the engine:

- A `String` is never interpreted as `Number` or `Bool`.
- A `Number` is never stringified for comparison.
- A `Bool` is only used for equality where explicitly modeled.

If a condition expects a specific variant and the field is missing or has a different variant, the condition evaluates to **false**.

### 1.3 Policy, Rules, and Actions

At runtime the engine holds a single `Policy`:

- `policy.name: String`
- `policy.version: String`
- `policy.rules: Vec<Rule>`

Each `Rule` has:

- `name: String`
- `when: Option<When>`
- `actions: Vec<Action>` (from the `truthscript::Action` enum)

The engine also maintains a mutable map of **counters**:

- `counters: BTreeMap<String, u64>` – used by `CountGreaterThan` conditions.

---

## 2. Rule Evaluation Order

Given an `EngineEvent`, the engine evaluates rules in **policy order**:

1. Start with `actions = []`.
2. For each `rule` in `policy.rules` in sequence:
   1. If `rule_matches(rule, event, counters)` is `false`, skip this rule.
   2. If `true`, append **all** actions from `rule.actions` to `actions`.
3. Return the accumulated `actions` (in policy order).

Notes:

- Rules **do not short-circuit** each other: multiple rules may fire for the same event.
- The **order of returned actions** is the same as the order of rules and actions in the policy.
- The engine itself is **stateless per evaluation** except for the `counters` map.

---

## 3. Rule Matching Semantics

A rule `R` matches an event `E` if and only if:

1. If `R.when` is `None` → the rule **always matches**.
2. If `R.when` is `Some(When { event: expected_event, conditions })`:
   1. If `expected_event` is `Some(s)` and `E.kind != s` → the rule **does not match**.
   2. Otherwise, all conditions in `conditions` must match.

### 3.1 When.event

- If `when.event` is `None` → the event kind is **not** checked.
- If `when.event` is `Some(expected)` → the event matches only if `E.kind == expected` (string equality).

### 3.2 Conditions List

Conditions are evaluated in **declaration order** and **short-circuit on first failure**:

- For each `cond` in `when.conditions`:
  - If `condition_matches(cond, event, counters)` is `false` → the rule does **not** match.
- If all conditions return `true` → the rule matches.

There is no OR/AND nesting at the engine level: any higher-level boolean structure must be encoded via multiple rules or more complex policies.

---

## 4. Condition Semantics

The `Condition` enum (from `truthscript`) is interpreted by the engine as follows.

### 4.1 EventEquals

```rust
Condition::EventEquals { value }
```

- Semantics: `event.kind == value` (string equality).
- If equal → `true`, else `false`.

### 4.2 FieldEquals

```rust
Condition::FieldEquals { field, value }
```

- Look up `event.fields.get(field)`.
- If the field exists and is `Value::String(s)` and `s == value` → `true`.
- In **all other cases** (missing field, non-string, mismatch) → `false`.

No implicit coercion occurs; numeric or boolean fields never satisfy `FieldEquals`.

### 4.3 FieldGreaterThan

```rust
Condition::FieldGreaterThan { field, threshold }
```

- Look up `event.fields.get(field)`.
- If the field exists and is `Value::Number(n)` and `n > threshold` → `true`.
- In **all other cases** (missing field, non-number, `n <= threshold`) → `false`.

### 4.4 EntropyGreaterThan

```rust
Condition::EntropyGreaterThan { threshold }
```

- Looks up the **special field** `"entropy"` in `event.fields`.
- If the field exists and is `Value::Number(n)` and `n > threshold` → `true`.
- Otherwise → `false`.

This is a convenience wrapper over `FieldGreaterThan { field: "entropy" }` with fixed field name.

### 4.5 CountGreaterThan (Stateful Counter)

```rust
Condition::CountGreaterThan { counter, threshold }
```

This is the only **stateful** condition: it both reads and updates the `counters` map.

Semantics for a given event:

1. Let `c = counters.entry(counter.clone()).or_insert(0)`.
2. Increment: `*c += 1`.
3. Condition returns `true` iff `*c > *threshold` **after** the increment.

Consequences:

- The first time the condition is evaluated for a given `counter` name, the counter moves from 0 to 1.
- For `threshold = 0`, the first evaluation returns `true` (1 > 0).
- For `threshold = 10`, the 11‑th successful evaluation for that counter name returns `true`.
- Counters are **global to the engine instance**, not per‑rule or per‑event kind.

---

## 5. Actions Semantics (Engine View)

The engine does **not** execute side effects itself; it only emits `EngineAction { rule_name, action }` values.

- For each matching rule, every `Action` in `rule.actions` is cloned into the result list.
- The meaning of actions (deny, flag, require proofs, record fields, etc.) is determined by the **caller** of the engine (e.g., `utld`), not by `policy_engine`.

Ordering:

- Actions are emitted in rule order, then action order.
- There is no deduplication or merging inside the engine.

---

## 6. Error Handling and Edge Cases

- Missing fields for `FieldEquals`, `FieldGreaterThan`, or `EntropyGreaterThan` → condition is `false` (no panic).
- Unexpected `Value` variants (e.g. string where number expected) → condition is `false`.
- Counters are never decremented; they only increase over the lifetime of the `PolicyEngine` instance.
- The engine does not mutate the incoming `EngineEvent`.

---

## 7. Intended Use for CUE and ZK

This semantics document is intended to be the reference for:

- **CUE schemas and validation**: CUE policies should only use condition patterns that map directly to the behavior defined here.
- **ZK circuits**: circuits like `HighThreatCircuit` and `HighThreatMerkleCircuit` must enforce constraints equivalent to the engine’s condition logic (e.g., numeric comparison semantics, thresholding).

Any future changes to `policy_engine` must keep this document in sync, or explicitly version the semantics so CUE + ZK tooling know which rules apply.
