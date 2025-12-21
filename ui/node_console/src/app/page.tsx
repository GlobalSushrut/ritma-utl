"use client";

import { useEffect, useState } from "react";

type NodeInfo = {
  id: string;
  org_id: string;
  tenant_id?: string | null;
  hostname?: string | null;
  labels: Record<string, string>;
  capabilities: string[];
  status: string;
  utld_version?: string | null;
  policy_version?: string | null;
  last_heartbeat_at?: number | null;
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function NodesPage() {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadNodes() {
      try {
        setLoading(true);
        setError(null);

        const headers: HeadersInit = {
          "x-user-id": "demo-user",
          "x-org-id": "demo-org",
          "x-roles": "org_owner",
        };

        const health = await fetch(`${API_BASE}/healthz`, { headers });
        if (!health.ok) {
          throw new Error(`health check failed: ${health.status}`);
        }

        const resp = await fetch(`${API_BASE}/api/nodes`, { headers });
        if (!resp.ok) {
          throw new Error(`nodes request failed: ${resp.status}`);
        }
        const data: NodeInfo[] = await resp.json();
        setNodes(data);
      } catch (e: any) {
        setError(e.message ?? String(e));
      } finally {
        setLoading(false);
      }
    }

    loadNodes();
  }, []);

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-6">
      <header className="border-b border-slate-800 pb-4 mb-4 flex items-baseline justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Node Console</h1>
          <p className="text-sm text-slate-400">
            Inventory of nodes, their health, and enforcement posture.
          </p>
        </div>
      </header>

      {loading && <p className="text-slate-300">Loading nodes...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      {!loading && nodes.length === 0 && !error && (
        <p className="text-slate-400 text-sm">
          No nodes registered yet. Start a node daemon to register, or call the
          <code className="mx-1">POST /api/nodes</code> endpoint.
        </p>
      )}

      {nodes.length > 0 && (
        <section className="border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-900 text-slate-300">
                <tr>
                  <th className="px-3 py-2 text-left font-semibold">Node ID</th>
                  <th className="px-3 py-2 text-left font-semibold">Org</th>
                  <th className="px-3 py-2 text-left font-semibold">Tenant</th>
                  <th className="px-3 py-2 text-left font-semibold">Hostname</th>
                  <th className="px-3 py-2 text-left font-semibold">Status</th>
                  <th className="px-3 py-2 text-left font-semibold">UTLD</th>
                  <th className="px-3 py-2 text-left font-semibold">Policy</th>
                  <th className="px-3 py-2 text-left font-semibold">Last heartbeat</th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((n) => (
                  <tr key={n.id} className="border-t border-slate-800">
                    <td className="px-3 py-2 font-mono text-xs break-all">
                      {n.id}
                    </td>
                    <td className="px-3 py-2">{n.org_id}</td>
                    <td className="px-3 py-2 text-slate-300">
                      {n.tenant_id ?? "-"}
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      {n.hostname ?? "-"}
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center rounded-full bg-emerald-900/40 px-2 py-0.5 text-xs text-emerald-300">
                        {n.status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      {n.utld_version ?? "-"}
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      {n.policy_version ?? "-"}
                    </td>
                    <td className="px-3 py-2 text-slate-400 text-xs">
                      {n.last_heartbeat_at
                        ? new Date(n.last_heartbeat_at * 1000).toISOString()
                        : "-"}
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
