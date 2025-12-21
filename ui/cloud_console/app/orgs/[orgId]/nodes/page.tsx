import { getNodesForOrg } from "@/lib/api";

type NodesPageProps = {
  params: { orgId: string };
};

export default async function OrgNodesPage({ params }: NodesPageProps) {
  const { orgId } = params;
  const nodes = await getNodesForOrg(orgId);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const STALE_SECONDS = 300;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Nodes / Wallet Consoles</h1>
        <p className="text-sm text-slate-400 mt-1">Registered nodes for org {orgId}.</p>
      </div>
      <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4 overflow-x-auto">
        <table className="min-w-full text-xs text-left">
          <thead className="text-slate-400 border-b border-white/10">
            <tr>
              <th className="py-2 pr-4">Node ID</th>
              <th className="py-2 pr-4">Label</th>
              <th className="py-2 pr-4">Region</th>
              <th className="py-2 pr-4">Capabilities</th>
              <th className="py-2 pr-4">Status</th>
              <th className="py-2 pr-4">Last heartbeat</th>
            </tr>
          </thead>
          <tbody className="text-slate-200">
            {nodes.length === 0 ? (
              <tr>
                <td className="py-3 pr-4" colSpan={6}>
                  <span className="text-slate-400">No nodes have been registered for this org yet.</span>
                </td>
              </tr>
            ) : (
              nodes.map((n) => (
                <tr key={n.id} className="border-t border-white/5">
                  <td className="py-2 pr-4 font-mono text-[11px]">{n.id}</td>
                  <td className="py-2 pr-4">{n.label ?? "-"}</td>
                  <td className="py-2 pr-4">{n.region ?? "-"}</td>
                  <td className="py-2 pr-4">{n.capabilities?.join(", ") ?? "-"}</td>
                  <td className="py-2 pr-4">
                    {n.last_heartbeat_at == null
                      ? "Unknown"
                      : nowSeconds - n.last_heartbeat_at <= STALE_SECONDS
                      ? "Online"
                      : "Stale"}
                  </td>
                  <td className="py-2 pr-4">
                    {n.last_heartbeat_at == null
                      ? "-"
                      : new Date(n.last_heartbeat_at * 1000).toISOString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
