// Security-focused HTTP/auth style demo using the UTL HTTP SDK.
// Requires:
//   - utld started with: UTLD_POLICY=creat/policies/security_policy.json
//   - utl_http running with token auth (UTLD_API_TOKEN) and metrics enabled.

import { UtlHttpClient } from '../ts-sdk/utl-sdk';

declare const process: { exit(code?: number): void; env: { [key: string]: string | undefined } };

interface TenantConfig {
  id: string;
  rootId: number;
  fileId: number;
}

const TENANTS: TenantConfig[] = [{ id: 'acme', rootId: 300, fileId: 1 }];

async function runSecurityFlows(client: UtlHttpClient, cfg: TenantConfig) {
  const zeroHash = '0'.repeat(64);

  console.log(`[security] [${cfg.id}] registering root...`);
  await client.registerRoot({
    root_id: cfg.rootId,
    root_hash: zeroHash,
    tx_hook: cfg.rootId,
    params: {
      tenant_id: cfg.id,
      service: `${cfg.id}_security`,
      env: 'prod',
    },
  });

  // --- Safe HTTP request ---
  console.log(`[security] [${cfg.id}] sending safe HTTP request...`);
  await client.recordTransition({
    entity_id: 5000 + cfg.rootId,
    root_id: cfg.rootId,
    signature: '00',
    data: JSON.stringify({ path: '/v1/patient/search', q: 'normal' }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: `http:${cfg.id}_api`,
    wall: 'prod',
    params: {
      tenant_id: cfg.id,
      event_kind: 'http_request',
      method: 'GET',
      path: '/v1/patient/search',
      client_ip: '203.0.113.10',
      waf_detected: 'none',
      src_did: `did:ritma:svc:${cfg.id}:public_api`,
      dst_did: `did:ritma:svc:${cfg.id}:ehr_db`,
      src_zone: `did:ritma:zone:${cfg.id}:public`,
      dst_zone: `did:ritma:zone:${cfg.id}:internal`,
      actor_did: `did:ritma:id:${cfg.id}:user-safe`,
    },
  });

  // --- WAF SQL injection block ---
  console.log(`[security] [${cfg.id}] sending SQL injection attempt (should be denied by policy)...`);
  const sqlInjectionPayload = { path: '/v1/patient/search', q: "' OR 1=1 --" };
  try {
    await client.recordTransition({
      entity_id: 5001 + cfg.rootId,
      root_id: cfg.rootId,
      signature: '00',
      data: JSON.stringify(sqlInjectionPayload),
      addr_heap_hash: zeroHash,
      hook_hash: zeroHash,
      logic_ref: `http:${cfg.id}_api`,
      wall: 'prod',
      params: {
        tenant_id: cfg.id,
        event_kind: 'http_request',
        method: 'GET',
        path: '/v1/patient/search',
        client_ip: '198.51.100.99',
        waf_detected: 'sql_injection',
        src_did: `did:ritma:svc:${cfg.id}:public_api`,
        dst_did: `did:ritma:svc:${cfg.id}:ehr_db`,
        src_zone: `did:ritma:zone:${cfg.id}:public`,
        dst_zone: `did:ritma:zone:${cfg.id}:internal`,
        actor_did: `did:ritma:id:${cfg.id}:attacker`,
      },
    });
    console.log(
      `[security] [${cfg.id}] SQL injection attempt unexpectedly allowed (check security_policy wiring).`,
    );
  } catch (err: any) {
    console.error(
      `[security] [${cfg.id}] SQL injection blocked as expected:`,
      err?.message ?? err,
    );
  }

  // --- Rate limit burst on patient search ---
  console.log(`[security] [${cfg.id}] sending burst of patient search requests to trigger rate limit...`);
  for (let i = 0; i < 12; i++) {
    try {
      await client.recordTransition({
        entity_id: 5100 + cfg.rootId + i,
        root_id: cfg.rootId,
        signature: '00',
        data: JSON.stringify({ path: '/v1/patient/search', q: `burst-${i}` }),
        addr_heap_hash: zeroHash,
        hook_hash: zeroHash,
        logic_ref: `http:${cfg.id}_api`,
        wall: 'prod',
        params: {
          tenant_id: cfg.id,
          event_kind: 'http_request',
          method: 'GET',
          path: '/v1/patient/search',
          client_ip: '203.0.113.10',
          src_did: `did:ritma:svc:${cfg.id}:public_api`,
          dst_did: `did:ritma:svc:${cfg.id}:ehr_db`,
          src_zone: `did:ritma:zone:${cfg.id}:public`,
          dst_zone: `did:ritma:zone:${cfg.id}:internal`,
          actor_did: `did:ritma:id:${cfg.id}:user-burst`,
        },
      });
    } catch (err: any) {
      console.error(
        `[security] [${cfg.id}] rate-limited patient search request (as expected after threshold):`,
        err?.message ?? err,
      );
      break;
    }
  }

  // --- Auth brute-force attempts ---
  console.log(`[security] [${cfg.id}] sending auth attempts to trigger brute-force detector...`);

  // Safe login (should be allowed)
  await client.recordTransition({
    entity_id: 5200 + cfg.rootId,
    root_id: cfg.rootId,
    signature: '00',
    data: JSON.stringify({ actor: 'user-auth-safe', action: 'login', outcome: 'success' }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: `auth:${cfg.id}_idp`,
    wall: 'prod',
    params: {
      tenant_id: cfg.id,
      event_kind: 'auth_attempt',
      actor_did: `did:ritma:id:${cfg.id}:user-auth-safe`,
      client_ip: '203.0.113.20',
      success: 'true',
      failed_attempts_last_10_min: '0',
      src_did: `did:ritma:svc:${cfg.id}:auth_service`,
      dst_did: `did:ritma:svc:${cfg.id}:ehr_db`,
      src_zone: `did:ritma:zone:${cfg.id}:public`,
      dst_zone: `did:ritma:zone:${cfg.id}:internal`,
    },
  });

  // Failed attempts that should start raising suspicion.
  for (let i = 1; i <= 7; i++) {
    const failedCount = i;
    try {
      await client.recordTransition({
        entity_id: 5210 + cfg.rootId + i,
        root_id: cfg.rootId,
        signature: '00',
        data: JSON.stringify({ actor: 'user-auth-bf', action: 'login', attempt: i, outcome: 'failure' }),
        addr_heap_hash: zeroHash,
        hook_hash: zeroHash,
        logic_ref: `auth:${cfg.id}_idp`,
        wall: 'prod',
        params: {
          tenant_id: cfg.id,
          event_kind: 'auth_attempt',
          actor_did: `did:ritma:id:${cfg.id}:user-auth-bf`,
          client_ip: '198.51.100.50',
          success: 'false',
          failed_attempts_last_10_min: String(failedCount),
          src_did: `did:ritma:svc:${cfg.id}:auth_service`,
          dst_did: `did:ritma:svc:${cfg.id}:ehr_db`,
          src_zone: `did:ritma:zone:${cfg.id}:public`,
          dst_zone: `did:ritma:zone:${cfg.id}:internal`,
        },
      });
    } catch (err: any) {
      console.error(
        `[security] [${cfg.id}] auth brute-force blocked at attempt ${i} (as expected):`,
        err?.message ?? err,
      );
      break;
    }
  }

  // --- Dig summary ---
  console.log(`[security] [${cfg.id}] building DigFile summary...`);
  const now = Math.floor(Date.now() / 1000);
  const dig = await client.buildDig({
    root_id: cfg.rootId,
    file_id: cfg.fileId,
    time_start: now - 3600,
    time_end: now + 3600,
  });
  console.log(`[security] [${cfg.id}] Dig summary:`, dig);
}

async function main() {
  const client = new UtlHttpClient();

  console.log('[security] health check...');
  const health = await client.health();
  console.log('[security] health:', health);

  for (const t of TENANTS) {
    await runSecurityFlows(client, t);
  }

  console.log('[security] security firewall demo completed.');
}

main().catch((err) => {
  console.error('[security] demo failed:', err);
  process.exit(1);
});
