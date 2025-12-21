"use client";

import { useEffect, useState } from "react";

type SloEventRecord = {
  ts: number;
  component: string;
  operation: string;
  tenant_id?: string | null;
  target?: string | null;
  outcome: string;
  latency_ms?: number | null;
  error?: string | null;
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function SloPage() {
  const [events, setEvents] = useState<SloEventRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError(null);

        const resp = await fetch(`${API_BASE}/api/slo/events?limit=200`);
        if (!resp.ok) {
          throw new Error(`request failed: ${resp.status}`);
        }
        const data: SloEventRecord[] = await resp.json();
        setEvents(data);
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
        <h1 className="text-2xl font-semibold">Node SLO Events</h1>
        <p className="text-sm text-slate-400">
          Raw SLO events emitted by security_kit and UTLD components on this node.
        </p>
      </header>

      {loading && <p className="text-slate-300">Loading SLO events...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      {!loading && events.length === 0 && !error && (
        <p className="text-slate-400 text-sm">No SLO events found on this node.</p>
      )}

      {events.length > 0 && (
        <section className="border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead className="bg-slate-900 text-slate-300">
                <tr>
                  <th className="px-3 py-2 text-left">Timestamp</th>
                  <th className="px-3 py-2 text-left">Component</th>
                  <th className="px-3 py-2 text-left">Operation</th>
                  <th className="px-3 py-2 text-left">Outcome</th>
                  <th className="px-3 py-2 text-left">Latency (ms)</th>
                  <th className="px-3 py-2 text-left">Tenant</th>
                  <th className="px-3 py-2 text-left">Error</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={`${e.ts}-${e.component}-${e.operation}`} className="border-t border-slate-800">
                    <td className="px-3 py-1 text-slate-300">
                      {new Date(e.ts * 1000).toISOString()}
                    </td>
                    <td className="px-3 py-1 font-mono text-[11px] break-all">{e.component}</td>
                    <td className="px-3 py-1 font-mono text-[11px] break-all">{e.operation}</td>
                    <td className="px-3 py-1">
                      <span
                        className="inline-flex items-center rounded-full px-2 py-0.5 text-[11px]"
                      >
                        {e.outcome}
                      </span>
                    </td>
                    <td className="px-3 py-1 text-slate-300">
                      {e.latency_ms ?? "-"}
                    </td>
                    <td className="px-3 py-1 text-slate-400">{e.tenant_id ?? "-"}</td>
                    <td className="px-3 py-1 text-red-400 max-w-xs truncate">
                      {e.error ?? ""}
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
