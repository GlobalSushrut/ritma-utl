"use client";

import { useEffect, useState } from "react";

type PolicySummary = {
  id: string;
  version: string;
  hash: string;
  created_at: number;
  framework: string;
  control_count: number;
};

type EvidenceKind =
  | "transition_logs"
  | "dig_files"
  | "policy_commit"
  | "merkle_proofs"
  | "micro_proofs"
  | "other";

type Control = {
  control_id: string;
  framework: string;
  intent: string;
  requirements: string[];
  evidence: EvidenceKind[];
  validation: {
    script: string;
  };
};

type PolicyDetail = {
  metadata: {
    id: string;
    version: string;
    hash: string;
    created_at: number;
  };
  controls: Control[];
};

type ControlChange = {
  control_id: string;
  base: Control;
  head: Control;
};

type PolicyDiff = {
  base: PolicySummary;
  head: PolicySummary;
  added_controls: Control[];
  removed_controls: Control[];
  changed_controls: ControlChange[];
};

const API_BASE =
  process.env.NEXT_PUBLIC_COMPLIANCE_API_BASE_URL ?? "http://127.0.0.1:8092";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [frameworkFilter, setFrameworkFilter] = useState<string | "all">("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<PolicyDetail | null>(
    null,
  );

  const [baseId, setBaseId] = useState<string | "">("");
  const [headId, setHeadId] = useState<string | "">("");
  const [diff, setDiff] = useState<PolicyDiff | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);

  const [reviewDecision, setReviewDecision] = useState("approve");
  const [reviewComment, setReviewComment] = useState("");
  const [reviewMessage, setReviewMessage] = useState<string | null>(null);
  const [reviewSubmitting, setReviewSubmitting] = useState(false);

  useEffect(() => {
    async function loadPolicies() {
      try {
        setLoading(true);
        setError(null);

        const headers: HeadersInit = {
          "x-user-id": "demo-user",
          "x-org-id": "demo-org",
          "x-roles": "org_owner",
        };

        const params = new URLSearchParams();
        if (frameworkFilter !== "all") {
          params.set("framework", frameworkFilter);
        }

        const url = `${API_BASE}/api/policies${
          params.toString() ? `?${params.toString()}` : ""
        }`;
        const resp = await fetch(url, { headers });
        if (!resp.ok) {
          throw new Error(`policies request failed: ${resp.status}`);
        }
        const data: PolicySummary[] = await resp.json();
        setPolicies(data);

        if (!selectedPolicyId && data.length > 0) {
          setSelectedPolicyId(data[0].id);
        }
      } catch (e: any) {
        setError(e.message ?? String(e));
      } finally {
        setLoading(false);
      }
    }

    loadPolicies();
  }, [frameworkFilter, selectedPolicyId]);

  useEffect(() => {
    async function loadDetail(id: string) {
      try {
        setSelectedDetail(null);

        const headers: HeadersInit = {
          "x-user-id": "demo-user",
          "x-org-id": "demo-org",
          "x-roles": "org_owner",
        };

        const resp = await fetch(`${API_BASE}/api/policies/${id}`, { headers });
        if (!resp.ok) {
          throw new Error(`policy detail request failed: ${resp.status}`);
        }
        const data: PolicyDetail = await resp.json();
        setSelectedDetail(data);
      } catch (e: any) {
        setError(e.message ?? String(e));
      }
    }

    if (selectedPolicyId) {
      loadDetail(selectedPolicyId);
    }
  }, [selectedPolicyId]);

  async function runDiff() {
    if (!baseId || !headId) {
      setDiffError("Select both base and head policies for diff.");
      return;
    }

    try {
      setDiffLoading(true);
      setDiffError(null);

      const headers: HeadersInit = {
        "x-user-id": "demo-user",
        "x-org-id": "demo-org",
        "x-roles": "org_owner",
      };

      const params = new URLSearchParams();
      params.set("base", baseId);
      params.set("head", headId);

      const resp = await fetch(
        `${API_BASE}/api/policies/diff?${params.toString()}`,
        { headers },
      );
      if (!resp.ok) {
        throw new Error(`diff request failed: ${resp.status}`);
      }
      const data: PolicyDiff = await resp.json();
      setDiff(data);
    } catch (e: any) {
      setDiffError(e.message ?? String(e));
    } finally {
      setDiffLoading(false);
    }
  }

  async function submitReview() {
    if (!selectedPolicyId) {
      setReviewMessage("Select a policy to review.");
      return;
    }

    try {
      setReviewSubmitting(true);
      setReviewMessage(null);

      const headers: HeadersInit = {
        "Content-Type": "application/json",
        "x-user-id": "demo-user",
        "x-org-id": "demo-org",
        "x-roles": "org_owner",
      };

      const body = JSON.stringify({
        reviewer: "demo-reviewer",
        decision: reviewDecision,
        comment: reviewComment,
      });

      const resp = await fetch(
        `${API_BASE}/api/policies/${selectedPolicyId}/review`,
        { method: "POST", headers, body },
      );
      if (!resp.ok) {
        throw new Error(`review request failed: ${resp.status}`);
      }

      setReviewMessage("Review submitted.");
      setReviewComment("");
    } catch (e: any) {
      setReviewMessage(e.message ?? String(e));
    } finally {
      setReviewSubmitting(false);
    }
  }

  const uniqueFrameworks = Array.from(
    new Set(policies.map((p: PolicySummary) => p.framework)),
  ).sort();

  const selectedPolicy = policies.find((p) => p.id === selectedPolicyId) || null;

  return (
    <main className="mx-auto max-w-6xl p-6 space-y-6">
      <header className="border-b border-slate-800 pb-4 mb-4 flex items-baseline justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Policy Workspace</h1>
          <p className="text-sm text-slate-400">
            TruthScript rulepacks with Git-like views and reviews.
          </p>
        </div>
      </header>

      {loading && <p className="text-slate-300">Loading policies...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Policies list */}
        <div className="lg:col-span-1 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Policies</h2>
            <select
              className="text-xs bg-slate-900 border border-slate-700 rounded px-2 py-1"
              value={frameworkFilter}
              onChange={(e) => setFrameworkFilter(e.target.value as any)}
            >
              <option value="all">All frameworks</option>
              {uniqueFrameworks.map((fw) => (
                <option key={fw} value={fw}>
                  {fw}
                </option>
              ))}
            </select>
          </div>

          <div className="mt-2 max-h-[22rem] overflow-y-auto">
            <ul className="space-y-1 text-sm">
              {policies.map((p: PolicySummary) => {
                const selected = p.id === selectedPolicyId;
                return (
                  <li
                    key={p.id}
                    className={`border border-slate-800 rounded px-2 py-1 cursor-pointer hover:bg-slate-900 ${
                      selected ? "bg-slate-900" : ""
                    }`}
                    onClick={() => setSelectedPolicyId(p.id)}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{p.id}</span>
                      <span className="text-xs text-slate-400">v{p.version}</span>
                    </div>
                    <div className="text-xs text-slate-500">
                      {p.framework} • {p.control_count} controls
                    </div>
                  </li>
                );
              })}
              {policies.length === 0 && !loading && (
                <li className="text-xs text-slate-500">No policies found.</li>
              )}
            </ul>
          </div>
        </div>

        {/* Policy detail and review */}
        <div className="lg:col-span-2 border border-slate-800 rounded-lg p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Policy detail</h2>
            {selectedPolicy && (
              <div className="text-xs text-slate-400">
                {selectedPolicy.framework} • {selectedPolicy.control_count} controls
              </div>
            )}
          </div>

          {selectedDetail ? (
            <div className="space-y-4">
              <div className="text-sm text-slate-300 space-y-1">
                <div>ID: {selectedDetail.metadata.id}</div>
                <div>Version: {selectedDetail.metadata.version}</div>
                <div>Hash: {selectedDetail.metadata.hash}</div>
                <div className="text-xs text-slate-500">
                  Created at:{" "}
                  {new Date(
                    selectedDetail.metadata.created_at * 1000,
                  ).toISOString()}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="border border-slate-800 rounded p-3 text-sm space-y-1">
                  <h3 className="font-semibold mb-1">Summary</h3>
                  <p className="text-slate-300">
                    This policy defines {selectedDetail.controls.length} controls for
                    framework {selectedDetail.metadata.id}.
                  </p>
                </div>

                <div className="border border-slate-800 rounded p-3 text-sm space-y-2">
                  <h3 className="font-semibold mb-1">Review</h3>
                  <div className="flex flex-col gap-2 text-xs">
                    <label className="flex items-center gap-2">
                      <span className="w-16">Decision</span>
                      <select
                        className="bg-slate-900 border border-slate-700 rounded px-2 py-1 flex-1"
                        value={reviewDecision}
                        onChange={(e) => setReviewDecision(e.target.value)}
                      >
                        <option value="approve">approve</option>
                        <option value="reject">reject</option>
                        <option value="needs_changes">needs_changes</option>
                      </select>
                    </label>
                    <label className="flex flex-col gap-1">
                      <span>Comment</span>
                      <textarea
                        className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs min-h-[4rem]"
                        value={reviewComment}
                        onChange={(e) => setReviewComment(e.target.value)}
                      />
                    </label>
                    <button
                      className="self-start bg-slate-100 text-slate-900 rounded px-3 py-1 font-medium hover:bg-white disabled:opacity-60"
                      onClick={submitReview}
                      disabled={reviewSubmitting}
                    >
                      {reviewSubmitting ? "Submitting..." : "Submit review"}
                    </button>
                    {reviewMessage && (
                      <p className="text-xs text-slate-400">{reviewMessage}</p>
                    )}
                  </div>
                </div>
              </div>

              <div className="border border-slate-800 rounded-lg p-3">
                <h3 className="text-sm font-semibold mb-2">Controls</h3>
                <div className="max-h-72 overflow-y-auto text-xs space-y-2">
                  {selectedDetail.controls.map((c: Control) => (
                    <div
                      key={c.control_id}
                      className="border border-slate-800 rounded p-2"
                    >
                      <div className="font-mono text-[11px] mb-1">
                        {c.control_id}
                      </div>
                      <div className="text-slate-200 mb-1">{c.intent}</div>
                      {c.requirements.length > 0 && (
                        <div className="text-[11px] text-slate-500 mb-1">
                          {c.requirements.join(" ")}
                        </div>
                      )}
                      <div className="text-[11px] text-slate-500">
                        Evidence: {c.evidence.join(", ")}
                      </div>
                    </div>
                  ))}
                  {selectedDetail.controls.length === 0 && (
                    <p className="text-slate-500">No controls in this policy.</p>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-500">
              Select a policy to see details.
            </p>
          )}
        </div>
      </section>

      <section className="border border-slate-800 rounded-lg p-4 space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <h2 className="text-lg font-semibold">Policy diff</h2>
          <div className="flex items-center gap-2 text-xs">
            <select
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1"
              value={baseId}
              onChange={(e) => setBaseId(e.target.value)}
            >
              <option value="">Base policy</option>
              {policies.map((p: PolicySummary) => (
                <option key={p.id} value={p.id}>
                  {p.id} (v{p.version})
                </option>
              ))}
            </select>
            <span className="text-slate-500">vs</span>
            <select
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1"
              value={headId}
              onChange={(e) => setHeadId(e.target.value)}
            >
              <option value="">Head policy</option>
              {policies.map((p: PolicySummary) => (
                <option key={p.id} value={p.id}>
                  {p.id} (v{p.version})
                </option>
              ))}
            </select>
            <button
              className="bg-slate-100 text-slate-900 rounded px-3 py-1 font-medium hover:bg-white disabled:opacity-60"
              onClick={runDiff}
              disabled={diffLoading}
            >
              {diffLoading ? "Running diff..." : "Run diff"}
            </button>
          </div>
        </div>

        {diffError && <p className="text-xs text-red-400">{diffError}</p>}

        {diff && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="border border-slate-800 rounded p-3">
              <h3 className="font-semibold mb-2">
                Added controls ({diff.added_controls.length})
              </h3>
              <ul className="space-y-1">
                {diff.added_controls.map((c: Control) => (
                  <li
                    key={c.control_id}
                    className="border border-emerald-900 rounded px-2 py-1"
                  >
                    <span className="font-mono">{c.control_id}</span>
                    <span className="ml-2 text-slate-300">{c.intent}</span>
                  </li>
                ))}
                {diff.added_controls.length === 0 && (
                  <li className="text-slate-500">None</li>
                )}
              </ul>
            </div>

            <div className="border border-slate-800 rounded p-3">
              <h3 className="font-semibold mb-2">
                Removed controls ({diff.removed_controls.length})
              </h3>
              <ul className="space-y-1">
                {diff.removed_controls.map((c: Control) => (
                  <li
                    key={c.control_id}
                    className="border border-red-900 rounded px-2 py-1"
                  >
                    <span className="font-mono">{c.control_id}</span>
                    <span className="ml-2 text-slate-300">{c.intent}</span>
                  </li>
                ))}
                {diff.removed_controls.length === 0 && (
                  <li className="text-slate-500">None</li>
                )}
              </ul>
            </div>

            <div className="border border-slate-800 rounded p-3">
              <h3 className="font-semibold mb-2">
                Changed controls ({diff.changed_controls.length})
              </h3>
              <ul className="space-y-1">
                {diff.changed_controls.map((c: ControlChange) => (
                  <li
                    key={c.control_id}
                    className="border border-yellow-900 rounded px-2 py-1"
                  >
                    <div className="font-mono mb-1">{c.control_id}</div>
                    <div className="text-slate-300">
                      <span className="text-slate-500">Base:</span> {c.base.intent}
                    </div>
                    <div className="text-slate-300">
                      <span className="text-slate-500">Head:</span> {c.head.intent}
                    </div>
                  </li>
                ))}
                {diff.changed_controls.length === 0 && (
                  <li className="text-slate-500">None</li>
                )}
              </ul>
            </div>
          </div>
        )}
      </section>
    </main>
  );
}
