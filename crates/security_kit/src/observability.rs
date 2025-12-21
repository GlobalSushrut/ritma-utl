use clock::TimeTick;
use tracing::event;

/// Emit a generic SLO event via `tracing`.
///
/// Host applications can wire `tracing-subscriber` to Prometheus or OpenTelemetry
/// exporters to turn these into metrics and alerts.
pub fn emit_slo_event(
    component: &'static str,
    operation: &'static str,
    tenant_id: Option<&str>,
    target: Option<&str>,
    outcome: &'static str, // "ok" or "error"
    latency_ms: Option<u64>,
    error: Option<&str>,
) {
    let ts = TimeTick::now().raw_time;

    event!(
        target: "security_kit::slo",
        tracing::Level::INFO,
        slo_ts = ts,
        slo_component = component,
        slo_operation = operation,
        slo_tenant = tenant_id.unwrap_or(""),
        slo_target = target.unwrap_or(""),
        slo_outcome = outcome,
        slo_latency_ms = latency_ms.unwrap_or(0),
        slo_error = error.unwrap_or(""),
        "security_kit_slo_event",
    );
}
