const RITMA_CLOUD_URL =
  process.env.NEXT_PUBLIC_RITMA_CLOUD_URL ?? "http://localhost:8088";

export interface OrgOverview {
  org_id: string;
  org_name: string;
  tenant_count: number;
  node_count: number;
  evidence_count: number;
}

export interface SloOverview {
  org_id: string;
  tenant_id: string | null;
  component: string;
  operation: string;
  outcome: string;
  total_count: number;
}

export interface EvidenceSummary {
  package_id: string;
  org_id: string;
  tenant_id: string;
  node_id: string;
  scope: string;
  report_type: string | null;
  framework: string | null;
  signed: boolean;
  created_at: number;
}

export interface TenantInfo {
  id: string;
  org_id: string;
  name: string;
}

export interface NodeWalletInfo {
  id: string;
  org_id: string;
  label: string | null;
  region: string | null;
  capabilities: string[];
  last_heartbeat_at: number | null;
}

export interface ReportSummary {
  id: string;
  org_id: string;
  tenant_id: string | null;
  scope: string;
  framework: string | null;
  evidence_ids: string[];
  created_at: number;
}

export interface UsageSummary {
  org_id: string;
  org_name: string;
  tenants: number;
  nodes: number;
  evidence: number;
  slo_events: number;
}

export interface OrgFeatures {
  org_id: string;
  plan: string | null;
  ritma_cloud: boolean;
  compliance_pdf_packs: boolean;
  policy_studio_pro: boolean;
  forensics_vault: boolean;
  witness_network: boolean;
  ai_guardrail_packs: boolean;
  auditor_portal: boolean;
  ritma_shield: boolean;
  compliance_packs: boolean;
  event_replay_engine: boolean;
  secrets_kms: boolean;
  secure_inference_runtime: boolean;
  integrations_pack: boolean;
  enterprise_support: boolean;
  appliance: boolean;
  log_ingest_saas: boolean;
  zk_proof_service: boolean;
  truthscript_marketplace: boolean;
  cluster_insurance: boolean;
  industry_blueprints: boolean;
}

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${RITMA_CLOUD_URL}${path}`, {
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error(`ritma_cloud request failed: ${res.status} ${res.statusText}`);
  }

  return (await res.json()) as T;
}

export async function getOrgOverview(orgId: string): Promise<OrgOverview | null> {
  const data = await fetchJson<OrgOverview[]>("/overview");
  return data.find((o) => o.org_id === orgId) ?? null;
}

export async function getSloSummary(orgId: string): Promise<SloOverview[]> {
  const data = await fetchJson<SloOverview[]>("/slo/summary");
  return data.filter((s) => s.org_id === orgId);
}

export async function getEvidenceForOrg(orgId: string): Promise<EvidenceSummary[]> {
  const data = await fetchJson<EvidenceSummary[]>("/evidence");
  return data.filter((e) => e.org_id === orgId);
}

export async function getTenantsForOrg(orgId: string): Promise<TenantInfo[]> {
  const data = await fetchJson<TenantInfo[]>("/tenants");
  return data.filter((t) => t.org_id === orgId);
}

export async function getNodesForOrg(orgId: string): Promise<NodeWalletInfo[]> {
  const data = await fetchJson<NodeWalletInfo[]>(`/nodes?org_id=${encodeURIComponent(orgId)}`);
  return data;
}

export async function getReportsForOrg(orgId: string): Promise<ReportSummary[]> {
  const data = await fetchJson<ReportSummary[]>("/reports");
  return data.filter((r) => r.org_id === orgId);
}

export async function getUsageForOrg(orgId: string): Promise<UsageSummary | null> {
  const data = await fetchJson<UsageSummary[]>("/usage");
  return data.find((u) => u.org_id === orgId) ?? null;
}

export async function getOrgFeatures(orgId: string): Promise<OrgFeatures> {
  return fetchJson<OrgFeatures>(`/orgs/${encodeURIComponent(orgId)}/features`);
}
