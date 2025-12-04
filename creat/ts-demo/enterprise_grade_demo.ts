// Enterprise-grade multi-tenant demo using the UTL HTTP SDK.
// Requires:
//   - utld started with: UTLD_POLICY=creat/policies/enterprise_policy.json
//   - utl_http running with token auth (UTLD_API_TOKEN) and metrics enabled.

import { UtlHttpClient } from '../ts-sdk/utl-sdk';

declare const process: { exit(code?: number): void; env: { [key: string]: string | undefined } };

type TenantId = 'acme' | 'globex';

interface TenantConfig {
  id: TenantId;
  rootId: number;
  fileId: number;
}

const TENANTS: TenantConfig[] = [
  { id: 'acme', rootId: 100, fileId: 1 },
  { id: 'globex', rootId: 200, fileId: 1 },
];

async function runTenantEnterpriseFlows(client: UtlHttpClient, cfg: TenantConfig) {
  const zeroHash = '0'.repeat(64);

  console.log(`[enterprise] [${cfg.id}] registering root...`);
  await client.registerRoot({
    root_id: cfg.rootId,
    root_hash: zeroHash,
    tx_hook: cfg.rootId,
    params: {
      tenant_id: cfg.id,
      service: `${cfg.id}_service`,
      env: 'prod',
    },
  });

  // --- AI audit: safe call should be logged and captured ---
  console.log(`[enterprise] [${cfg.id}] AI safe call (should be allowed & audited)...`);
  const aiInputSafe = { user_id: `${cfg.id}-user-safe`, features: { risk_score: 0.7 } };
  const aiOutputSafe = { approved: true, reason: 'score_ok' };

  await client.recordTransition({
    entity_id: 1000 + cfg.rootId,
    root_id: cfg.rootId,
    signature: '00',
    data: JSON.stringify({ kind: 'ai_call', input: aiInputSafe, output: aiOutputSafe }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: `model:${cfg.id}/demo_v1`,
    wall: 'prod',
    params: {
      tenant_id: cfg.id,
      event_kind: 'ai_call',
      model_version: 'demo_v1',
      risk_score: '0.7',
      risk_bucket: 'low',
    },
  });

  // --- AI audit: high-risk call should be denied by policy ---
  console.log(`[enterprise] [${cfg.id}] AI high-risk call (should be denied by policy)...`);
  const aiInputRisk = { user_id: `${cfg.id}-user-risk`, features: { risk_score: 0.99 } };
  const aiOutputRisk = { approved: false, reason: 'score_too_high' };

  try {
    await client.recordTransition({
      entity_id: 1001 + cfg.rootId,
      root_id: cfg.rootId,
      signature: '00',
      data: JSON.stringify({ kind: 'ai_call', input: aiInputRisk, output: aiOutputRisk }),
      addr_heap_hash: zeroHash,
      hook_hash: zeroHash,
      logic_ref: `model:${cfg.id}/demo_v1`,
      wall: 'prod',
      params: {
        tenant_id: cfg.id,
        event_kind: 'ai_call',
        model_version: 'demo_v1',
        risk_score: '0.99',
        risk_bucket: 'high',
      },
    });
    console.log(`[enterprise] [${cfg.id}] HIGH-RISK AI call unexpectedly allowed (check policy wiring).`);
  } catch (err: any) {
    console.error(`[enterprise] [${cfg.id}] HIGH-RISK AI call denied as expected:`, err?.message ?? err);
  }

  // --- Log hardening: ERROR burst to trigger dig seal & SNARK ---
  console.log(`[enterprise] [${cfg.id}] sending ERROR burst to trigger seal_on_error_burst...`);
  for (let i = 0; i < 12; i++) {
    await client.recordTransition({
      entity_id: 2000 + cfg.rootId + i,
      root_id: cfg.rootId,
      signature: '00',
      data: JSON.stringify({ message: `error ${i}`, code: 'E_DEMO_ENTERPRISE' }),
      addr_heap_hash: zeroHash,
      hook_hash: zeroHash,
      logic_ref: `service:${cfg.id}_api`,
      wall: 'prod',
      params: {
        tenant_id: cfg.id,
        event_kind: 'log_event',
        severity: 'ERROR',
      },
    });
  }
  console.log(`[enterprise] [${cfg.id}] PAYMENT safe transaction (should be allowed)...`);
  const paymentSafe = { tx_id: `${cfg.id}-tx-safe`, amount: 50, currency: 'USD' };
  await client.recordTransition({
    entity_id: 4000 + cfg.rootId,
    root_id: cfg.rootId,
    signature: '00',
    data: JSON.stringify(paymentSafe),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: `payments:${cfg.id}_processor`,
    wall: 'prod',
    params: {
      tenant_id: cfg.id,
      event_kind: 'payment_tx',
      amount_bucket: 'normal',
      risk_bucket: 'low',
      merchant_id: `${cfg.id}-merchant-1`,
    },
  });

  console.log(`[enterprise] [${cfg.id}] PAYMENT high-risk transaction (should be denied by policy)...`);
  const paymentRisk = { tx_id: `${cfg.id}-tx-risk`, amount: 10000, currency: 'USD' };
  try {
    await client.recordTransition({
      entity_id: 4001 + cfg.rootId,
      root_id: cfg.rootId,
      signature: '00',
      data: JSON.stringify(paymentRisk),
      addr_heap_hash: zeroHash,
      hook_hash: zeroHash,
      logic_ref: `payments:${cfg.id}_processor`,
      wall: 'prod',
      params: {
        tenant_id: cfg.id,
        event_kind: 'payment_tx',
        amount_bucket: 'large',
        risk_bucket: 'high',
        merchant_id: `${cfg.id}-merchant-1`,
      },
    });
    console.log(
      `[enterprise] [${cfg.id}] HIGH-RISK PAYMENT unexpectedly allowed (check policy wiring).`,
    );
  } catch (err: any) {
    console.error(
      `[enterprise] [${cfg.id}] HIGH-RISK PAYMENT denied as expected:`,
      err?.message ?? err,
    );
  }

  // --- Access audit: PHI READ should be captured and proofed ---
  console.log(`[enterprise] [${cfg.id}] PHI READ (doctor) should be captured + proofed...`);
  await client.recordTransition({
    entity_id: 3000 + cfg.rootId,
    root_id: cfg.rootId,
    signature: '00',
    data: JSON.stringify({ record_id: `${cfg.id}-patient-1`, action: 'READ' }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: 'ehr:v1',
    wall: 'prod',
    params: {
      tenant_id: cfg.id,
      event_kind: 'record_access',
      data_class: 'PHI',
      action: 'READ',
      actor_id: `${cfg.id}-doctor-1`,
      actor_role: 'doctor',
    },
  });

  // --- Access audit: unauthorized WRITE should be denied ---
  console.log(`[enterprise] [${cfg.id}] PHI WRITE by guest (should be denied + dig sealed)...`);
  try {
    await client.recordTransition({
      entity_id: 3001 + cfg.rootId,
      root_id: cfg.rootId,
      signature: '00',
      data: JSON.stringify({ record_id: `${cfg.id}-patient-1`, action: 'WRITE' }),
      addr_heap_hash: zeroHash,
      hook_hash: zeroHash,
      logic_ref: 'ehr:v1',
      wall: 'prod',
      params: {
        tenant_id: cfg.id,
        event_kind: 'record_access',
        data_class: 'PHI',
        action: 'WRITE',
        actor_id: `${cfg.id}-guest-1`,
        actor_role: 'guest',
      },
    });
    console.log(`[enterprise] [${cfg.id}] UNAUTHORIZED WRITE unexpectedly allowed (check policy wiring).`);
  } catch (err: any) {
    console.error(`[enterprise] [${cfg.id}] UNAUTHORIZED WRITE denied as expected:`, err?.message ?? err);
  }

  // --- Dig + entropy summaries ---
  console.log(`[enterprise] [${cfg.id}] building DigFile summary after policy actions...`);
  const now = Math.floor(Date.now() / 1000);
  const dig = await client.buildDig({
    root_id: cfg.rootId,
    file_id: cfg.fileId,
    time_start: now - 3600,
    time_end: now + 3600,
  });
  console.log(`[enterprise] [${cfg.id}] Dig summary:`, dig);

  console.log(`[enterprise] [${cfg.id}] building entropy bin...`);
  const entropy = await client.buildEntropy({ root_id: cfg.rootId, bin_id: 1 });
  console.log(`[enterprise] [${cfg.id}] Entropy summary:`, entropy);
}

async function fetchMetricsEnterprise(): Promise<void> {
  const base = process.env?.UTL_HTTP_BASE ?? 'http://127.0.0.1:8080';
  const token = process.env?.UTL_HTTP_TOKEN;
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;

  console.log('[enterprise] fetching /metrics...');
  const res = await fetch(`${base}/metrics`, { headers });
  const text = await res.text();
  console.log('[enterprise] /metrics response:\n' + text);
}

async function main() {
  const client = new UtlHttpClient();

  console.log('[enterprise] health check...');
  const health = await client.health();
  console.log('[enterprise] health:', health);

  for (const t of TENANTS) {
    await runTenantEnterpriseFlows(client, t);
  }

  await fetchMetricsEnterprise();

  console.log('[enterprise] enterprise-grade demo completed.');
}

main().catch((err) => {
  console.error('[enterprise] demo failed:', err);
  process.exit(1);
});
