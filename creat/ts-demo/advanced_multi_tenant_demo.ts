// Advanced multi-tenant enterprise demo using the UTL HTTP SDK.
// Demonstrates multiple tenants, different event types, and metrics.

import { UtlHttpClient } from '../ts-sdk/utl-sdk';

declare const process: { exit(code?: number): void; env: { [key: string]: string | undefined } };

type TenantId = 'acme' | 'globex';

interface TenantConfig {
  id: TenantId;
  rootId: number;
  fileId: number;
}

const TENANTS: TenantConfig[] = [
  { id: 'acme', rootId: 10, fileId: 1 },
  { id: 'globex', rootId: 20, fileId: 1 },
];

async function runTenantFlows(client: UtlHttpClient, cfg: TenantConfig) {
  const zeroHash = '0'.repeat(64);

  console.log(`[demo] [${cfg.id}] registering root...`);
  await client.registerRoot({
    root_id: cfg.rootId,
    root_hash: zeroHash,
    tx_hook: cfg.rootId,
    params: {
      tenant_id: cfg.id,
      service: `${cfg.id}_service`,
    },
  });

  console.log(`[demo] [${cfg.id}] recording AI decision...`);
  const aiInput = { user_id: `${cfg.id}-user`, features: { risk_score: 0.8 } };
  const aiOutput = { approved: true, reason: 'score_ok' };

  await client.recordTransition({
    entity_id: 1000 + cfg.rootId,
    root_id: cfg.rootId,
    signature: '00',
    data: JSON.stringify({ kind: 'ai_call', input: aiInput, output: aiOutput }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: `model:${cfg.id}/v1`,
    wall: 'prod',
    params: {
      tenant_id: cfg.id,
      event_kind: 'ai_call',
      model_version: 'v1',
    },
  });

  console.log(`[demo] [${cfg.id}] recording ERROR log burst...`);
  for (let i = 0; i < 5; i++) {
    await client.recordTransition({
      entity_id: 2000 + cfg.rootId + i,
      root_id: cfg.rootId,
      signature: '00',
      data: JSON.stringify({ message: `error ${i}`, code: 'E_DEMO' }),
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

  console.log(`[demo] [${cfg.id}] recording PHI access events...`);
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

  // Attempt unauthorized write to trigger policy deny if configured.
  console.log(`[demo] [${cfg.id}] recording unauthorized WRITE, may be denied by policy...`);
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
    console.log(`[demo] [${cfg.id}] unauthorized WRITE was accepted (no deny policy in place).`);
  } catch (err: any) {
    console.error(`[demo] [${cfg.id}] unauthorized WRITE denied as expected:`, err?.message ?? err);
  }

  console.log(`[demo] [${cfg.id}] building DigFile summary...`);
  const now = Math.floor(Date.now() / 1000);
  const dig = await client.buildDig({
    root_id: cfg.rootId,
    file_id: cfg.fileId,
    time_start: now - 3600,
    time_end: now + 3600,
  });
  console.log(`[demo] [${cfg.id}] Dig summary:`, dig);

  console.log(`[demo] [${cfg.id}] building entropy bin...`);
  const entropy = await client.buildEntropy({ root_id: cfg.rootId, bin_id: 1 });
  console.log(`[demo] [${cfg.id}] Entropy summary:`, entropy);
}

async function fetchMetrics(): Promise<void> {
  const base = process.env?.UTL_HTTP_BASE ?? 'http://127.0.0.1:8080';
  const token = process.env?.UTL_HTTP_TOKEN;
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;

  console.log('[demo] fetching /metrics...');
  const res = await fetch(`${base}/metrics`, { headers });
  const text = await res.text();
  console.log('[demo] /metrics response:\n' + text);
}

async function main() {
  const client = new UtlHttpClient();

  console.log('[demo] health check...');
  const health = await client.health();
  console.log('[demo] health:', health);

  for (const t of TENANTS) {
    await runTenantFlows(client, t);
  }

  await fetchMetrics();

  console.log('[demo] advanced multi-tenant demo completed.');
}

main().catch((err) => {
  console.error('[demo] advanced demo failed:', err);
  process.exit(1);
});
