type SettingsPageProps = {
  params: { orgId: string };
};

export default function OrgSettingsPage({ params }: SettingsPageProps) {
  const { orgId } = params;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Settings</h1>
        <p className="text-sm text-slate-400 mt-1">Org-level configuration for {orgId}.</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="font-medium text-slate-200 mb-1">Keys & Signing</div>
          <p className="text-slate-400">
            Key inventory from nodes (hashed IDs only) will appear here so CISOs can audit which keys
            exist and are in use.
          </p>
        </div>
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="font-medium text-slate-200 mb-1">Integrations</div>
          <p className="text-slate-400">
            SIEM, SOAR, and witness network integration settings will surface here as the products
            evolve.
          </p>
        </div>
      </div>
    </div>
  );
}
