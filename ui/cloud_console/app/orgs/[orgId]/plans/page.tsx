import { getOrgFeatures, getUsageForOrg } from "@/lib/api";

type PlansPageProps = {
  params: { orgId: string };
};

export default async function OrgPlansPage({ params }: PlansPageProps) {
  const { orgId } = params;
  const [usage, features] = await Promise.all([
    getUsageForOrg(orgId),
    getOrgFeatures(orgId).catch(() => null as any),
  ]);

  const planName = features?.plan ?? "unassigned";
  const ritmaCloudEnabled = features?.ritma_cloud ?? false;
  const compliancePacksEnabled = features?.compliance_packs ?? false;
  const forensicsVaultEnabled = features?.forensics_vault ?? false;

  const tenants = usage?.tenants ?? 0;
  const nodes = usage?.nodes ?? 0;
  const evidence = usage?.evidence ?? 0;
  const sloEvents = usage?.slo_events ?? 0;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-slate-50">Plans & Products</h1>
        <p className="text-sm text-slate-400 mt-1">
          Enabled Ritma products and features for org {orgId}.
        </p>
        <p className="text-xs text-slate-400 mt-2">
          Plan:
          <span className="ml-1 text-slate-200 font-medium">{planName}</span>
          <span className="mx-2 text-slate-600">|</span>
          Tenants: <span className="text-slate-200">{tenants}</span>
          <span className="mx-1 text-slate-600">·</span>
          Nodes: <span className="text-slate-200">{nodes}</span>
          <span className="mx-1 text-slate-600">·</span>
          Evidence: <span className="text-slate-200">{evidence}</span>
          <span className="mx-1 text-slate-600">·</span>
          SLO events: <span className="text-slate-200">{sloEvents}</span>
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="text-slate-300 font-medium mb-1">Ritma Cloud</div>
          <div className="text-slate-400">Managed UTLD clusters & control plane.</div>
          <div className="mt-2 text-ritma-teal">
            Status: {ritmaCloudEnabled ? "Enabled" : "Disabled"}
          </div>
        </div>
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="text-slate-300 font-medium mb-1">Compliance Packs</div>
          <div className="text-slate-400">Industry rulepacks and evidence mapping.</div>
          <div className="mt-2 text-ritma-teal">
            Status: {compliancePacksEnabled ? "Enabled" : "Disabled"}
          </div>
        </div>
        <div className="rounded-ritma-card border border-white/10 bg-white/5 p-4">
          <div className="text-slate-300 font-medium mb-1">Forensics Vault</div>
          <div className="text-slate-400">Cold storage & replay of incidents.</div>
          <div className="mt-2 text-ritma-teal">
            Status: {forensicsVaultEnabled ? "Enabled" : "Disabled"}
          </div>
        </div>
      </div>
    </div>
  );
}
