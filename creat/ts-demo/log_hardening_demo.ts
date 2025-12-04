// Log hardening demo using the UTL HTTP SDK.
// Simulates application logs flowing into UTL.

import { UtlHttpClient } from '../ts-sdk/utl-sdk';
declare const process: { exit(code?: number): void };

async function main() {
  const client = new UtlHttpClient();

  const rootId = 2;
  const fileId = 1;
  const zeroHash = '0'.repeat(64);

  console.log('[log-demo] Registering log root...');
  await client.registerRoot({
    root_id: rootId,
    root_hash: zeroHash,
    tx_hook: rootId,
    params: { service: 'log_demo' },
  });

  console.log('[log-demo] Sending INFO logs...');
  for (let i = 0; i < 5; i++) {
    await client.recordTransition({
      entity_id: i,
      root_id: rootId,
      signature: '00',
      data: JSON.stringify({ message: `info log ${i}` }),
      addr_heap_hash: zeroHash,
      hook_hash: zeroHash,
      logic_ref: 'service:log_demo',
      wall: 'prod',
      params: {
        event_kind: 'log_event',
        severity: 'INFO',
        service: 'log_demo',
      },
    });
  }

  console.log('[log-demo] Sending ERROR burst...');
  for (let i = 0; i < 12; i++) {
    await client.recordTransition({
      entity_id: 100 + i,
      root_id: rootId,
      signature: '00',
      data: JSON.stringify({ message: `error log ${i}` }),
      addr_heap_hash: zeroHash,
      hook_hash: zeroHash,
      logic_ref: 'service:log_demo',
      wall: 'prod',
      params: {
        event_kind: 'log_event',
        severity: 'ERROR',
        service: 'log_demo',
      },
    });
  }

  console.log('[log-demo] Building DigFile summary after error burst...');
  const now = Math.floor(Date.now() / 1000);
  const dig = await client.buildDig({
    root_id: rootId,
    file_id: fileId,
    time_start: now - 3600,
    time_end: now + 3600,
  });

  console.log('[log-demo] Dig summary:', dig);

  console.log('[log-demo] Building entropy bin...');
  const entropy = await client.buildEntropy({ root_id: rootId, bin_id: 1 });
  console.log('[log-demo] Entropy summary:', entropy);

  console.log('[log-demo] Completed.');
}

main().catch((err) => {
  console.error('[log-demo] Failed:', err);
  process.exit(1);
});
