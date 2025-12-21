import { getReportsForOrg } from "@/lib/api";
import { GenerateReportButton } from "./GenerateReportButton";

type ReportsPageProps = {
  params: { orgId: string };
};

export default async function OrgReportsPage({ params }: ReportsPageProps) {
  const { orgId } = params;
  const reports = await getReportsForOrg(orgId);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Reports</h1>
        <p className="text-sm text-slate-400 mt-1">
          Compliance reports generated for org {orgId}, backed by evidence manifests.
        </p>
        <GenerateReportButton orgId={orgId} />
      </div>
      <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4 overflow-x-auto text-xs">
        <table className="min-w-full text-left">
          <thead className="text-slate-400 border-b border-white/10">
            <tr>
              <th className="py-2 pr-4">Report ID</th>
              <th className="py-2 pr-4">Tenant</th>
              <th className="py-2 pr-4">Scope</th>
              <th className="py-2 pr-4">Framework</th>
              <th className="py-2 pr-4">Evidence Count</th>
              <th className="py-2 pr-4">Created At</th>
              <th className="py-2 pr-4">Actions</th>
            </tr>
          </thead>
          <tbody className="text-slate-200">
            {reports.length === 0 ? (
              <tr>
                <td className="py-3 pr-4" colSpan={7}>
                  <span className="text-slate-400">No reports have been generated for this org yet.</span>
                </td>
              </tr>
            ) : (
              reports.map((r) => (
                <tr key={r.id} className="border-t border-white/5">
                  <td className="py-2 pr-4 font-mono text-[11px]">{r.id}</td>
                  <td className="py-2 pr-4">{r.tenant_id ?? "all"}</td>
                  <td className="py-2 pr-4">{r.scope}</td>
                  <td className="py-2 pr-4">{r.framework ?? "-"}</td>
                  <td className="py-2 pr-4">{r.evidence_ids.length}</td>
                  <td className="py-2 pr-4">{new Date(r.created_at * 1000).toISOString()}</td>
                  <td className="py-2 pr-4">
                    <a
                      href={`/api/reports/${encodeURIComponent(r.id)}/manifest`}
                      className="text-ritma-teal hover:underline"
                    >
                      Download JSON
                    </a>
                    <span className="mx-1 text-slate-600">|</span>
                    <a
                      href={`/api/reports/${encodeURIComponent(r.id)}/bundle`}
                      className="text-ritma-orange hover:underline"
                    >
                      Generate PDF+Proof (stub)
                    </a>
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
