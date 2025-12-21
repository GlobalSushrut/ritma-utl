import { getTenantsForOrg } from "@/lib/api";

type TenantsPageProps = {
  params: { orgId: string };
};

export default async function OrgTenantsPage({ params }: TenantsPageProps) {
  const { orgId } = params;
  const tenants = await getTenantsForOrg(orgId);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Tenants</h1>
        <p className="text-sm text-slate-400 mt-1">All tenants for org {orgId}.</p>
      </div>
      <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4 overflow-x-auto">
        <table className="min-w-full text-xs text-left">
          <thead className="text-slate-400 border-b border-white/10">
            <tr>
              <th className="py-2 pr-4">Tenant</th>
              <th className="py-2 pr-4">Status</th>
              <th className="py-2 pr-4">Open Incidents</th>
              <th className="py-2 pr-4">Last Activity</th>
            </tr>
          </thead>
          <tbody className="text-slate-200">
            {tenants.length === 0 ? (
              <tr>
                <td className="py-3 pr-4" colSpan={4}>
                  <span className="text-slate-400">No tenants have been registered for this org yet.</span>
                </td>
              </tr>
            ) : (
              tenants.map((t) => (
                <tr key={t.id} className="border-t border-white/5">
                  <td className="py-2 pr-4">{t.name}</td>
                  <td className="py-2 pr-4">--</td>
                  <td className="py-2 pr-4">--</td>
                  <td className="py-2 pr-4">--</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
