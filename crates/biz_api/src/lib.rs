use core_types::UID;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifier for a commercial Ritma Cloud product.
///
/// These map directly to the 26 products described in
/// `pitch/business_architecture.md`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProductId {
    // Platform & Witnessing (P1–P6)
    ManagedUtldClusters,
    GlobalWitnessNetwork,
    ExternalAnchoringService,
    TruthSnapshotScheduler,
    ComplianceReportingEngine,
    KeyAndSecretOrchestration,

    // Policy & Governance (G1–G7)
    PolicyStudio,
    PolicyGovernanceLedger,
    LawbookControlLibrary,
    PolicySimulationService,
    PolicyCiCdIntegration,
    PolicyMarketplace,
    RegulatorAuditorPortal,

    // AI & Behavioral Security (A1–A6)
    AiGuardrailPack,
    EntropyAnalyticsDrift,
    UnknownLogicRegistry,
    DistilliumMicroProofService,
    TrustAgreementService,
    AnomalyDetectionService,

    // Evidence & Forensics (E1–E4)
    ManagedEvidenceVault,
    ForensicSearchEDiscovery,
    IncidentReplayTimeline,
    EvidenceExportBundling,

    // Access, Portals & Integrations (X1–X3)
    TenantAdminConsole,
    DeveloperApiGateway,
    MsspPartnerConsole,
}

/// High-level plan tier for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Community,
    Team,
    Enterprise,
    Sovereign,
    /// Custom-named tier (e.g. "internal", "beta", or bespoke contracts).
    Custom {
        label: String,
    },
}

/// Which metric is being limited or metered.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Decisions,       // count of DecisionEvents
    DigFiles,        // count of DigFiles sealed
    StorageBytes,    // logical bytes stored in managed vaults
    SnapshotExports, // count of truth snapshot exports
    ApiCalls,        // external API calls into Ritma Cloud
}

/// A quota or soft limit for a given metric.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quota {
    pub metric: MetricKind,
    /// Optional limit; None means unlimited / not enforced.
    pub limit: Option<u64>,
}

/// Per-product configuration within a plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanProductConfig {
    pub product: ProductId,
    /// Whether this product is enabled for the plan.
    pub enabled: bool,
    /// Optional quotas for usage dimensions.
    #[serde(default)]
    pub quotas: Vec<Quota>,
}

/// A subscription plan (e.g. community, team, enterprise) and its product set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanConfig {
    pub plan_id: String,
    pub tier: PlanTier,
    #[serde(default)]
    pub products: Vec<PlanProductConfig>,
}

/// Tenant configuration tying an organization to a plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantConfig {
    /// Internal Ritma tenant identifier (string-based, e.g. "acme").
    pub tenant_id: String,
    /// Optional external ID/slug used by the customer.
    pub external_id: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Current subscription plan.
    pub plan: PlanConfig,
}

/// A single usage event emitted by utld / tooling for business analytics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageEvent {
    /// Unix timestamp (seconds since epoch).
    pub ts: u64,
    /// Tenant on whose behalf the action occurred.
    pub tenant_id: String,
    /// Product that should be credited with this usage.
    pub product: ProductId,
    /// Metric kind (decisions, DigFiles, etc.).
    pub metric: MetricKind,
    /// Quantity consumed (e.g. 1 decision, N bytes).
    pub quantity: u64,
    /// Optional root context (e.g. dig root id).
    pub root_id: Option<UID>,
    /// Optional entity context (e.g. entity id within a root).
    pub entity_id: Option<UID>,
    /// Optional free-form note for debugging / analytics.
    pub note: Option<String>,
}

/// Trait implemented by business-side plugins that consume usage events.
///
/// In open-source deployments this can be a no-op or local logger.  
/// In Ritma Cloud this would be implemented by metering / billing services.
pub trait BusinessPlugin: Send + Sync {
    /// Called whenever a usage event is emitted.
    fn on_usage_event(&self, event: &UsageEvent);

    /// Optional flush hook for plugins that buffer events.
    fn flush(&self) {}
}

/// Load a list of PlanConfig records from a JSON file.
///
/// The expected format is a JSON array of objects matching PlanConfig.
pub fn load_plans_from_file(path: &str) -> Result<Vec<PlanConfig>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read plans file {path}: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("failed to parse plans file {path}: {e}"))
}

/// Load a list of TenantConfig records from a JSON file.
///
/// The expected format is a JSON array of objects matching TenantConfig.
pub fn load_tenants_from_file(path: &str) -> Result<Vec<TenantConfig>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read tenants file {path}: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("failed to parse tenants file {path}: {e}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PricingRule {
    pub plan_id: String,
    pub metric: MetricKind,
    pub included_quantity: u64,
    pub unit_quantity: u64,
    pub unit_price_cents: u64,
    pub unit_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvoiceLine {
    pub metric: Option<MetricKind>,
    pub description: String,
    pub quantity: u64,
    pub unit_price_cents: u64,
    pub total_cents: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvoiceDraft {
    pub tenant_id: String,
    pub plan_id: String,
    pub period_start_ts: u64,
    pub period_end_ts: u64,
    pub currency: String,
    pub base_price_cents: u64,
    pub lines: Vec<InvoiceLine>,
    pub subtotal_cents: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn compute_invoice_draft_for_month(
    tenant_id: &str,
    plan_id: &str,
    period_start_ts: u64,
    period_end_ts: u64,
    currency: &str,
    base_price_cents: u64,
    usage: &[(ProductId, MetricKind, u64)],
    pricing_rules: &[PricingRule],
) -> InvoiceDraft {
    let mut usage_by_metric: HashMap<MetricKind, u64> = HashMap::new();
    for (_, metric, qty) in usage {
        let entry = usage_by_metric.entry(*metric).or_insert(0);
        *entry = entry.saturating_add(*qty);
    }

    let mut rules_by_metric: HashMap<MetricKind, &PricingRule> = HashMap::new();
    for rule in pricing_rules {
        if rule.plan_id == plan_id {
            rules_by_metric.insert(rule.metric, rule);
        }
    }

    let mut lines = Vec::new();
    let mut subtotal_cents = base_price_cents;

    if base_price_cents > 0 {
        lines.push(InvoiceLine {
            metric: None,
            description: "base_subscription".to_string(),
            quantity: 1,
            unit_price_cents: base_price_cents,
            total_cents: base_price_cents,
        });
    }

    for (metric, quantity) in usage_by_metric {
        if let Some(rule) = rules_by_metric.get(&metric) {
            let rule = *rule;
            if quantity <= rule.included_quantity {
                continue;
            }

            let over_raw = quantity - rule.included_quantity;
            let units = if rule.unit_quantity == 0 {
                0
            } else {
                over_raw.div_ceil(rule.unit_quantity)
            };

            if units == 0 {
                continue;
            }

            let line_total = units.saturating_mul(rule.unit_price_cents);
            subtotal_cents = subtotal_cents.saturating_add(line_total);

            lines.push(InvoiceLine {
                metric: Some(metric),
                description: rule.unit_label.clone(),
                quantity: units,
                unit_price_cents: rule.unit_price_cents,
                total_cents: line_total,
            });
        }
    }

    InvoiceDraft {
        tenant_id: tenant_id.to_string(),
        plan_id: plan_id.to_string(),
        period_start_ts,
        period_end_ts,
        currency: currency.to_string(),
        base_price_cents,
        lines,
        subtotal_cents,
    }
}

pub trait PaymentProvider {
    type Error;

    fn ensure_customer(&self, external_customer_id: &str) -> Result<String, Self::Error>;

    fn create_invoice(
        &self,
        provider_customer_id: &str,
        draft: &InvoiceDraft,
    ) -> Result<String, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_tenant_config() {
        let plan = PlanConfig {
            plan_id: "enterprise_eu".to_string(),
            tier: PlanTier::Enterprise,
            products: vec![PlanProductConfig {
                product: ProductId::ManagedUtldClusters,
                enabled: true,
                quotas: vec![Quota {
                    metric: MetricKind::Decisions,
                    limit: Some(1_000_000),
                }],
            }],
        };

        let tenant = TenantConfig {
            tenant_id: "acme".to_string(),
            external_id: Some("acme-external".to_string()),
            name: "Acme Corp".to_string(),
            plan,
        };

        let json = serde_json::to_string(&tenant).unwrap();
        let back: TenantConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(tenant.name, back.name);
        assert_eq!(tenant.plan.plan_id, back.plan.plan_id);
    }

    #[test]
    fn usage_event_serializes() {
        let ev = UsageEvent {
            ts: 1_700_000_000,
            tenant_id: "acme".to_string(),
            product: ProductId::ManagedUtldClusters,
            metric: MetricKind::Decisions,
            quantity: 1,
            root_id: None,
            entity_id: None,
            note: Some("test".to_string()),
        };

        let _json = serde_json::to_string(&ev).unwrap();
    }

    #[test]
    fn load_roundtrip_plans_and_tenants() {
        let plan = PlanConfig {
            plan_id: "team_test".to_string(),
            tier: PlanTier::Team,
            products: vec![PlanProductConfig {
                product: ProductId::ManagedUtldClusters,
                enabled: true,
                quotas: vec![],
            }],
        };

        let tenant = TenantConfig {
            tenant_id: "acme".to_string(),
            external_id: None,
            name: "Acme".to_string(),
            plan: plan.clone(),
        };

        let plans_json = serde_json::to_string(&vec![plan]).unwrap();
        let tenants_json = serde_json::to_string(&vec![tenant]).unwrap();

        let tmpdir = tempfile::tempdir().unwrap();
        let plans_path = tmpdir.path().join("plans.json");
        let tenants_path = tmpdir.path().join("tenants.json");

        std::fs::write(&plans_path, plans_json).unwrap();
        std::fs::write(&tenants_path, tenants_json).unwrap();

        let loaded_plans = load_plans_from_file(plans_path.to_str().unwrap()).unwrap();
        let loaded_tenants = load_tenants_from_file(tenants_path.to_str().unwrap()).unwrap();

        assert_eq!(loaded_plans.len(), 1);
        assert_eq!(loaded_tenants.len(), 1);
        assert_eq!(loaded_tenants[0].tenant_id, "acme");
    }

    #[test]
    fn compute_invoice_with_overage() {
        let pricing = vec![PricingRule {
            plan_id: "standard".to_string(),
            metric: MetricKind::Decisions,
            included_quantity: 100,
            unit_quantity: 10,
            unit_price_cents: 40,
            unit_label: "decisions_per_10".to_string(),
        }];

        let usage = vec![(
            ProductId::ManagedUtldClusters,
            MetricKind::Decisions,
            150u64,
        )];

        let draft = compute_invoice_draft_for_month(
            "tenant1", "standard", 1, 31, "usd", 1_000, &usage, &pricing,
        );

        assert_eq!(draft.tenant_id, "tenant1");
        assert_eq!(draft.plan_id, "standard");
        assert_eq!(draft.base_price_cents, 1_000);
        assert_eq!(draft.lines.len(), 2);

        let overage_line = draft
            .lines
            .iter()
            .find(|l| l.metric == Some(MetricKind::Decisions))
            .unwrap();

        assert_eq!(overage_line.quantity, 5);
        assert_eq!(overage_line.unit_price_cents, 40);
        assert_eq!(overage_line.total_cents, 200);
        assert_eq!(draft.subtotal_cents, 1_200);
    }
}
