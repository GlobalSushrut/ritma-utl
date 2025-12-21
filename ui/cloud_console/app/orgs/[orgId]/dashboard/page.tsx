import { getOrgOverview, getSloSummary } from "@/lib/api";

type DashboardPageProps = {
  params: { orgId: string };
};

export default async function OrgDashboardPage({ params }: DashboardPageProps) {
  const { orgId } = params;

  const [overview, slo] = await Promise.all([
    getOrgOverview(orgId),
    getSloSummary(orgId),
  ]);

  const tenantCount = overview ? overview.tenant_count.toString() : "--";
  const nodeCount = overview ? overview.node_count.toString() : "--";
  const evidenceCount = overview ? overview.evidence_count.toString() : "--";
  const totalSlo = slo.reduce((sum, s) => sum + s.total_count, 0).toString();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Org Overview</h1>
        <p className="text-sm text-slate-400 mt-1">
          High-level posture for org <span className="font-mono text-slate-200">{orgId}</span>.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="text-xs text-slate-400">Tenants</div>
          <div className="mt-2 text-2xl font-semibold text-slate-50">{tenantCount}</div>
        </div>
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="text-xs text-slate-400">Nodes</div>
          <div className="mt-2 text-2xl font-semibold text-slate-50">{nodeCount}</div>
        </div>
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="text-xs text-slate-400">Evidence Packages</div>
          <div className="mt-2 text-2xl font-semibold text-slate-50">{evidenceCount}</div>
        </div>
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="text-xs text-slate-400">SLO Signals</div>
          <div className="mt-2 text-2xl font-semibold text-slate-50">{totalSlo}</div>
        </div>
      </div>
      <div className="rounded-ritma-card border border-white/10 bg-white/5 p-6 min-h-[200px]">
        <div className="text-sm font-medium text-slate-200 mb-2">Activity & SLO Trends</div>
        <p className="text-xs text-slate-400">
          Graphs and time-series for decisions, connector validation, evidence build/sign, and compliance
          health will appear here, powered by SLO summaries from the ritma_cloud control plane.
        </p>
      </div>
    </div>
  );
}
