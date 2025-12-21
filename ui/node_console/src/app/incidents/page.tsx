"use client";

import { useEffect, useState } from "react";

type Incident = {
  ts: number;
  tenant_id?: string | null;
  root_id: string;
  entity_id: string;
  event_kind: string;
  policy_decision: string;
  snark_high_threat_merkle_status?: string | null;
  policy_commit_id?: string | null;
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function IncidentsPage() {
  const [rows, setRows] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError(null);

        const resp = await fetch(`${API_BASE}/api/incidents?limit=200`);
        if (!resp.ok) {
          throw new Error(`request failed: ${resp.status}`);
        }
        const data: Incident[] = await resp.json();
        setRows(data);
      } catch (e: any) {
        setError(e.message ?? String(e));
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-6">
      <header className="border-b border-slate-800 pb-4 mb-4">
        <h1 className="text-2xl font-semibold">Incidents</h1>
        <p className="text-sm text-slate-400">
          High-impact enforcement events (denies and high-threat decisions) observed on this node.
        </p>
      </header>

      {loading && <p className="text-slate-300">Loading incidents...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      {!loading && rows.length === 0 && !error && (
        <p className="text-slate-400 text-sm">No incidents found.</p>
      )}

      {rows.length > 0 && (
        <section className="border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead className="bg-slate-900 text-slate-300">
                <tr>
                  <th className="px-3 py-2 text-left">Timestamp</th>
                  <th className="px-3 py-2 text-left">Tenant</th>
                  <th className="px-3 py-2 text-left">Root</th>
                  <th className="px-3 py-2 text-left">Entity</th>
                  <th className="px-3 py-2 text-left">Event</th>
                  <th className="px-3 py-2 text-left">Decision</th>
                  <th className="px-3 py-2 text-left">Threat</th>
                  <th className="px-3 py-2 text-left">Policy Commit</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={`${r.ts}-${r.root_id}-${r.entity_id}`} className="border-t border-slate-800">
                    <td className="px-3 py-1 text-slate-300">
                      {new Date(r.ts * 1000).toISOString()}
                    </td>
                    <td className="px-3 py-1 text-slate-400">
                      {r.tenant_id ?? "-"}
                    </td>
                    <td className="px-3 py-1 font-mono text-[11px] break-all">{r.root_id}</td>
                    <td className="px-3 py-1 font-mono text-[11px] break-all">{r.entity_id}</td>
                    <td className="px-3 py-1 text-slate-300">{r.event_kind}</td>
                    <td className="px-3 py-1 text-red-300">{r.policy_decision}</td>
                    <td className="px-3 py-1 text-slate-300">
                      {r.snark_high_threat_merkle_status ?? "-"}
                    </td>
                    <td className="px-3 py-1 font-mono text-[11px] break-all">
                      {r.policy_commit_id ?? "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </main>
  );
}
