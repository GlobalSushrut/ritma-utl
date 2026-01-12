# Ritma Niche Demos Runbook (Real Infra + Real CLI)

This document defines **5 niche demos** designed to feel product-ready while staying strictly truthful:

- Ritma is the **evidence substrate**.
- The “app/data” side is **mock behavior** (small, realistic workloads).
- The outputs are **real verifiable artifacts** produced by Ritma (**ProofPack**, **DigFile**, and/or **Evidence Package**), plus built-in CLI verification steps.

## Global rules (do not deviate)

- Demo **artifacts first**:
  - create artifact
  - show hash
  - verify
  - then show any UI/report
- Never claim “prevention” unless we truly block something.
- Always say “record/prove after the fact”, not “monitor”.

## Golden rule (shared demo spine)

Every demo must have the same 3-step shape:

1. Capture a time window (10–30s)
2. Emit a Proof Pack (artifacts + hashes)
3. Verify + Diff (prove integrity + compare runs)

If all 5 demos share this exact shape, the code explains the platform automatically.

## Shared demo contract (CLI + folder layout)

All demos should converge on the same verbs:

- `ritma capture --profile <demo> --seconds 20 --namespace <ns> --out <dir> [--interactive] [--json]`
- `ritma verify <proofpack_dir>`
- `ritma diff <proofpack_dir_a> <proofpack_dir_b>`

Each run should write a deterministic, fixed structure:

```
proofpacks/<demo-name>/<run-id>/
  manifest.json
  window.json
  events.ndjson
  graph.json
  findings.json
  compliance.json
  verify.txt
```

Notes:

- `findings.json` is allowed to be derived/heuristic, but it is never the “truth”.
- `compliance.json` exists only for Demo 5 (or is empty/omitted in other demos).

## Fusion strategy (one engine, five lenses)

You are not demoing features.
You are demoing **one system observed through five different failure lenses**.

Every demo must answer all 3 questions implicitly:

1. Where did this run? (K8s / runtime)
2. What did it do? (AI / process / network / package)
3. Can I defend this later? (forensics + compliance)

If a demo doesn’t answer all three, it’s incomplete.

Non-negotiables:

- One runtime window per run
- One Proof Pack format
- One verification path
- One diff story

Grounding sentence (use verbatim):

> “Each demo is intentionally incomplete alone — the completeness comes from the shared evidence layer underneath.”

## Prereqs (common to all demos)

- Bring up the local Ritma sidecars (real infra):
  - `ritma init` (if you don’t already have `ritma.sidecar.yml`)
  - `ritma up` (docker mode by default)
  - `ritma doctor` (confirm IndexDB is writable + runtime is running)

- Choose a namespace (one per demo run):
  - Example: `ns://demo/niche/<demo>/<date>`

- Verify tooling is available:
  - `ritma verify proof --path <proofpack_dir>`
  - `ritma verify --file <digfile.dig.json>`

## Artifact conventions (current implementation reality)

Today, the repo already supports:

- ProofPacks exported by the CLI (offline verifiable)
- DigFiles for deterministic record chaining (offline verifiable)

Until `ritma capture/verify/diff` wrappers are implemented, verification is:

- ProofPack: `ritma verify proof --path <proofpack_dir>`
- DigFile: `ritma verify --file <digfile.dig.json>`

---

# Demo 1: AI Forensic System Recorder

## Scenario (real-world)

An AI service running inside Kubernetes makes an unexpected decision.

You need to prove:

- where it ran (pod/image/node context)
- what it executed (model version, input/output)
- what it touched (network egress)
- whether it violated policy

## What we show (concrete)

In one window, show at least these dimensions:

- K8s:
  - pod lifecycle timeline
  - image digest
  - namespace/labels
- AI:
  - model version
  - input hash
  - output hash
- Network:
  - outbound call initiated by the AI pod/process
- Compliance:
  - “AI execution must not call external endpoints” (computed after execution)

Then repeat once with a different model version or a policy-violating outbound call, and diff the Proof Packs.

Minimal “AI execution event” fields the demo should record:

- `model_id` / `model_version`
- `prompt_hash` (never raw prompt by default)
- `tool_calls` (optional)
- `output_hash`
- `latency_ms`
- `policy_context` (allowed tools/data sources)

Minimal Kubernetes fields the demo should record:

- pod name/uid (raw or hashed)
- image digest
- node name (raw or hashed)
- restarts and termination reason (best-effort)

## What it proves (core truth)

- Non-repudiable execution record
- Drift evidence (model/version delta)
- Dispute resolution readiness

## Capture / Verify / Diff flow (target CLI contract)

- Capture:
  - `ritma capture --profile ai-recorder --seconds 20 --namespace <ns> --out <dir> --model <label> --prompt <text> [--interactive]`
- Verify:
  - `ritma verify <proofpack_dir>`
- Diff:
  - `ritma diff <proofpack_dir_a> <proofpack_dir_b>`

Artifacts written (per the contract):

- `window.json`
- `events.ndjson`
- `graph.json`
- `findings.json` (optional)
- `manifest.json` + hashes

Optional (AI-specific):

- `ai_execution.dig.json` (execution record chain)

Narration line (use verbatim):

> “This shows where the AI ran, what it executed, what it touched, and whether it violated policy — all from one evidence window.”

---

# Demo 2: Cyber Network Package Trace

## Scenario (real-world)

An ephemeral pod exists for ~20 seconds and leaks data externally. The pod is gone; logs are incomplete.

You need to prove:

- the pod existed (K8s timeline)
- what egress happened (network)
- which process/binary initiated it (package/runtime)
- whether it violated “no unknown egress” policy

## What we show

In one window, show at least these dimensions:

- K8s:
  - short-lived pod lifecycle
  - image digest
- Network:
  - unexpected external endpoint
  - timing + byte counts (best-effort)
- Package/runtime:
  - which binary/module path initiated the call (best-effort marker)
- Compliance:
  - “No unknown egress from prod namespace” (computed after execution)

Then rerun with a clean allowlisted endpoint, and diff.

Minimal network capture fields the demo should record:

- flow tuples (src/dst ip:port, proto)
- byte counts, start/end
- links to process/container where possible
- optional DNS summaries

Minimal package/runtime fields the demo should record:

- binary hash
- an execution marker for the egress path (best-effort)

## What it proves

- Post-incident attribution (process → destination)
- Evidence survives mutable logs

## Capture / Verify / Diff flow (target CLI contract)

- Capture:
  - `ritma capture --profile net-trace --seconds 20 --namespace <ns> --out <dir> --scenario normal|suspicious [--interactive]`
- Verify:
  - `ritma verify <proofpack_dir>`
- Diff:
  - `ritma diff <proofpack_dir_a> <proofpack_dir_b>`

Narration line:

> “Even when Kubernetes deletes the pod, the evidence survives.”

---

# Demo 3: Package / Dependency Trace (Runtime, not SBOM)

## Scenario (real-world)

After an incident, an auditor asks:

“Did vulnerable dependency X execute during the incident?”

This demo answers “yes/no with proof”, tied to runtime + K8s + AI context.

## What we show

In one window, show at least these dimensions:

- Package/runtime:
  - runtime execution markers (not just manifest/SBOM)
  - binary hash + build metadata
- AI:
  - whether AI flow invoked the vulnerable path (marker)
- K8s:
  - image digest for the pod that executed it
- Compliance/audit framing:
  - a report that answers “executed: yes/no” and points to evidence hashes

Then rerun in “clean” mode and diff.

Minimal dependency/runtime fields the demo should record:

- binary hash
- version/build metadata
- loaded libraries where possible
- execution markers for the “vulnerable module path”

## What it proves

- Executed vs present dependency distinction
- Liability reduction / audit clarity

## Capture / Verify / Diff flow (target CLI contract)

- Capture:
  - `ritma capture --profile dep-trace --seconds 20 --namespace <ns> --out <dir> --path safe|vulnerable [--interactive]`
- Verify:
  - `ritma verify <proofpack_dir>`
- Diff:
  - `ritma diff <proofpack_dir_a> <proofpack_dir_b>`

Narration line:

> “This turns ‘maybe vulnerable’ into ‘provably executed or not’.”

---

# Demo 4: Kubernetes Forensic Window

## Scenario (real-world)

A pod crash-loops right after AI inference, and there’s also a spike in outbound network activity.

You need post-mortem truth across:

- crash timeline
- AI execution just before crash
- outbound request spike attribution
- whether a stability/safety rule was violated

## What we show

In one window, show at least these dimensions:

- K8s:
  - crash loop timeline
  - image digest
- AI:
  - inference event just before crash
- Network:
  - outbound request spike
- Compliance:
  - a stability/safety rule evaluated after execution (PASS/FAIL)

Then run a clean baseline and diff.

Minimal k8s lifecycle fields the demo should record:

- pod create/delete, restarts
- container image digest
- node name (raw or hashed)
- namespace + labels
- process tree + net edges inside pod (best-effort)

## What it proves

- You can investigate after ephemeral infra is gone
- “Reality > dashboards” using cryptographic artifacts

## Capture / Verify / Diff flow (target CLI contract)

- Capture:
  - `ritma capture --profile k8s-window --seconds 20 --namespace <ns> --out <dir> --mode k8s|docker [--interactive]`
- Verify:
  - `ritma verify <proofpack_dir>`
- Diff:
  - `ritma diff <proofpack_dir_a> <proofpack_dir_b>`

Narration line:

> “This is post-mortem truth, not observability.”

---

# Demo 5: Compliance Infrastructure as Code (Evidence-derived)

## Scenario (real-world)

Regulator/auditor asks:

“Show me compliance for last week’s AI system behavior.”

This is a meta-demo: the other four demos collapse into compliance.

## What we show

In one window, show at least these dimensions:

- Compliance rules evaluated after execution
- Rules reference:
  - AI behavior
  - network flows
  - K8s context
  - package execution markers
- Compliance report links to proof packs (by hash/path)

Then capture a violating run and diff PASS vs FAIL.

Implement these three rules first:

- `no_unknown_egress`
- `no_privileged_container`
- `no_exec_in_prod`

## What it proves

- Compliance can be audited (evidence), not asserted (config)

## Capture / Verify / Diff flow (target CLI contract)

- Capture:
  - `ritma capture --profile compliance --seconds 20 --namespace <ns> --out <dir> --scenario pass|fail --rule <rule> [--interactive]`
- Verify:
  - `ritma verify <proofpack_dir>`
- Diff:
  - `ritma diff <proofpack_dir_a> <proofpack_dir_b>`

Narration line:

> “We don’t enforce compliance. We prove whether it happened.”

---

# Interaction model (tutorial UX)

All `ritma capture` commands should support:

- `--interactive`:
  - pauses between steps
  - prints “what just happened”
  - prints “what to verify next”
- `--json`:
  - machine-readable output including paths and hashes

Expected CLI output (non-JSON):

- The namespace used
- The window time range
- The exported ProofPack path
- The attestation hash
- The verify command to run

# Presentation approach (one engine, five lenses)

Positioning line:

> “These are five lenses. The engine is one: capture → proof pack → verify → diff.”

Best 2 to demo live (highest impact):

- Kubernetes forensic window
- AI forensic recorder

Then show outputs for the other three (network evidence, dependency runtime proof, compliance report).

What makes the demos feel polished:

- Deterministic outputs (same structure every time)
- Verification never flakes
- Diff is human-readable (Git-like summary)

# Implementation notes (for step 2)

- Reuse existing code paths:
  - sealing windows (`Orchestrator::run_window`)
  - exporting ProofPack (`ritma export proof` internals)
  - verification (`ritma verify proof`, `ritma verify --file`)

- Keep the “mock workload” honest:
  - a small Rust helper that performs deterministic behaviors (file open, net connect, “agent output”)
  - no fake “Ritma says” output; only real artifacts + hashes
