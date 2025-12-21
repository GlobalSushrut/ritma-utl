type HealthPageProps = {
  params: { orgId: string };
};

export default function OrgHealthPage({ params }: HealthPageProps) {
  const { orgId } = params;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">SLO & Health</h1>
        <p className="text-sm text-slate-400 mt-1">Aggregated SLO signals for org {orgId}.</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4 min-h-[160px]">
          <div className="text-xs text-slate-400 mb-2">Connector Validation</div>
          <div className="text-xs text-slate-400">SLO tiles and error budgets will appear here.</div>
        </div>
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4 min-h-[160px]">
          <div className="text-xs text-slate-400 mb-2">Evidence & Compliance</div>
          <div className="text-xs text-slate-400">SLO summaries and failure modes will appear here.</div>
        </div>
      </div>
    </div>
  );
}
