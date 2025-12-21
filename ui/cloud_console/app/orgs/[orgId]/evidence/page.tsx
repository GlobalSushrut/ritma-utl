import { getEvidenceForOrg } from "@/lib/api";

type EvidencePageProps = {
  params: { orgId: string };
};

export default async function OrgEvidencePage({ params }: EvidencePageProps) {
  const { orgId } = params;
  const evidence = await getEvidenceForOrg(orgId);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Evidence Registry</h1>
        <p className="text-sm text-slate-400 mt-1">Evidence packages reported for org {orgId}.</p>
      </div>
      <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4 overflow-x-auto">
        <table className="min-w-full text-xs text-left">
          <thead className="text-slate-400 border-b border-white/10">
            <tr>
              <th className="py-2 pr-4">Package ID</th>
              <th className="py-2 pr-4">Tenant</th>
              <th className="py-2 pr-4">Node</th>
              <th className="py-2 pr-4">Scope</th>
              <th className="py-2 pr-4">Type</th>
              <th className="py-2 pr-4">Framework</th>
              <th className="py-2 pr-4">Signed</th>
              <th className="py-2 pr-4">Created At</th>
            </tr>
          </thead>
          <tbody className="text-slate-200">
            {evidence.length === 0 ? (
              <tr>
                <td className="py-3 pr-4" colSpan={8}>
                  <span className="text-slate-400">No evidence has been reported for this org yet.</span>
                </td>
              </tr>
            ) : (
              evidence.map((e) => (
                <tr key={e.package_id} className="border-t border-white/5">
                  <td className="py-2 pr-4 font-mono text-[11px]">{e.package_id}</td>
                  <td className="py-2 pr-4">{e.tenant_id}</td>
                  <td className="py-2 pr-4">{e.node_id}</td>
                  <td className="py-2 pr-4">{e.scope}</td>
                  <td className="py-2 pr-4">{e.report_type ?? "-"}</td>
                  <td className="py-2 pr-4">{e.framework ?? "-"}</td>
                  <td className="py-2 pr-4">{e.signed ? "yes" : "no"}</td>
                  <td className="py-2 pr-4">
                    {new Date(e.created_at * 1000).toISOString()}
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
