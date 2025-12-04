// Data access audit demo using the UTL HTTP SDK.
// Simulates reads and writes to sensitive records.

import { UtlHttpClient } from '../ts-sdk/utl-sdk';
declare const process: { exit(code?: number): void };

async function main() {
  const client = new UtlHttpClient();

  const rootId = 3;
  const fileId = 1;
  const zeroHash = '0'.repeat(64);

  console.log('[access-demo] Registering access root...');
  await client.registerRoot({
    root_id: rootId,
    root_hash: zeroHash,
    tx_hook: rootId,
    params: { service: 'access_demo' },
  });

  console.log('[access-demo] Recording allowed PHI read by doctor...');
  await client.recordTransition({
    entity_id: 1,
    root_id: rootId,
    signature: '00',
    data: JSON.stringify({ record_id: 'patient-123', action: 'READ' }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: 'ehr:demo',
    wall: 'prod',
    params: {
      event_kind: 'record_access',
      data_class: 'PHI',
      action: 'READ',
      actor_id: 'doctor-42',
      actor_role: 'doctor',
    },
  });

  console.log('[access-demo] Attempting unauthorized WRITE by guest...');
  await client.recordTransition({
    entity_id: 2,
    root_id: rootId,
    signature: '00',
    data: JSON.stringify({ record_id: 'patient-123', action: 'WRITE' }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: 'ehr:demo',
    wall: 'prod',
    params: {
      event_kind: 'record_access',
      data_class: 'PHI',
      action: 'WRITE',
      actor_id: 'guest-99',
      actor_role: 'guest',
    },
  }).catch((err) => {
    console.error('[access-demo] Expected denial for guest WRITE:', err.message);
  });

  console.log('[access-demo] Building DigFile summary...');
  const now = Math.floor(Date.now() / 1000);
  const dig = await client.buildDig({
    root_id: rootId,
    file_id: fileId,
    time_start: now - 3600,
    time_end: now + 3600,
  });

  console.log('[access-demo] Dig summary:', dig);

  console.log('[access-demo] Building entropy bin...');
  const entropy = await client.buildEntropy({ root_id: rootId, bin_id: 1 });
  console.log('[access-demo] Entropy summary:', entropy);

  console.log('[access-demo] Completed.');
}

main().catch((err) => {
  console.error('[access-demo] Failed:', err);
  process.exit(1);
});
