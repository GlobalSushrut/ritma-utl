"use client";

import { useEffect, useState } from "react";

type EvidenceEntry = {
  file_id: string;
  root_id: string;
  tenant_id?: string | null;
  time_start: number;
  time_end: number;
  record_count: number;
  merkle_root: string;
  policy_name?: string | null;
  policy_version?: string | null;
  policy_decision?: string | null;
  storage_path?: string | null;
};

type EvidenceResult = {
  entry: EvidenceEntry;
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function EvidencePage() {
  const [rows, setRows] = useState<EvidenceResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError(null);

        const resp = await fetch(`${API_BASE}/api/evidence/search?limit=100`);
        if (!resp.ok) {
          throw new Error(`request failed: ${resp.status}`);
        }
        const data: EvidenceResult[] = await resp.json();
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
        <h1 className="text-2xl font-semibold">Evidence Index</h1>
        <p className="text-sm text-slate-400">
          Sealed dig files indexed on this node (from UTLD_DIG_INDEX_DB).
        </p>
      </header>

      {loading && <p className="text-slate-300">Loading evidence index...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      {!loading && rows.length === 0 && !error && (
        <p className="text-slate-400 text-sm">No evidence entries found.</p>
      )}

      {rows.length > 0 && (
        <section className="border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead className="bg-slate-900 text-slate-300">
                <tr>
                  <th className="px-3 py-2 text-left">Tenant</th>
                  <th className="px-3 py-2 text-left">File</th>
                  <th className="px-3 py-2 text-left">Root</th>
                  <th className="px-3 py-2 text-left">Time range</th>
                  <th className="px-3 py-2 text-left">Records</th>
                  <th className="px-3 py-2 text-left">Decision</th>
                  <th className="px-3 py-2 text-left">Policy</th>
                  <th className="px-3 py-2 text-left">Storage</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const e = r.entry;
                  return (
                    <tr
                      key={e.file_id}
                      className="border-t border-slate-800"
                    >
                      <td className="px-3 py-1 text-slate-400">
                        {e.tenant_id ?? "-"}
                      </td>
                      <td className="px-3 py-1 font-mono text-[11px] break-all">
                        {e.file_id}
                      </td>
                      <td className="px-3 py-1 font-mono text-[11px] break-all">
                        {e.root_id}
                      </td>
                      <td className="px-3 py-1 text-slate-300">
                        {new Date(e.time_start * 1000).toISOString()} –
                        <br />
                        {new Date(e.time_end * 1000).toISOString()}
                      </td>
                      <td className="px-3 py-1 text-slate-300">
                        {e.record_count}
                      </td>
                      <td className="px-3 py-1 text-slate-300">
                        {e.policy_decision ?? "-"}
                      </td>
                      <td className="px-3 py-1 text-slate-300">
                        {e.policy_name ?? "-"} {e.policy_version ?? ""}
                      </td>
                      <td className="px-3 py-1 font-mono text-[11px] break-all">
                        {e.storage_path ?? "-"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </main>
  );
}
