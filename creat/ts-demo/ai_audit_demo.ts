// Simple end-to-end AI audit demo using the UTL HTTP SDK.
// This script assumes:
// 1) utld is running and utl_http is running in front of it.
// 2) A policy file may be loaded separately to enforce behavior.

import { UtlHttpClient } from '../ts-sdk/utl-sdk';
declare const process: { exit(code?: number): void };

async function main() {
  const client = new UtlHttpClient();

  console.log('Checking health...');
  const health = await client.health();
  console.log('health:', health);

  // Demo values.
  const rootId = 1;
  const fileId = 1;

  // Minimal root_hash: 32 bytes of zero.
  const zeroHash = '0'.repeat(64);

  console.log('Registering root...');
  await client.registerRoot({
    root_id: rootId,
    root_hash: zeroHash,
    tx_hook: rootId,
    params: { service: 'ai_decision_demo' },
  });

  console.log('Recording AI decision transition...');
  const input = { user_id: 'user-123', features: { risk_score: 0.7 } };
  const output = { approved: true, reason: 'score_above_threshold' };

  await client.recordTransition({
    entity_id: 42,
    root_id: rootId,
    signature: '00', // placeholder demo signature
    data: JSON.stringify({ input, output }),
    addr_heap_hash: zeroHash,
    hook_hash: zeroHash,
    logic_ref: 'model:demo/v1',
    wall: 'prod',
    params: {
      event_kind: 'ai_call',
      model_version: 'demo_v1',
      user_id: input.user_id,
    },
  });

  console.log('Building DigFile summary...');
  const now = Math.floor(Date.now() / 1000);
  const dig = await client.buildDig({
    root_id: rootId,
    file_id: fileId,
    time_start: now - 3600,
    time_end: now + 3600,
  });

  console.log('Dig summary:', dig);

  console.log('Building entropy bin...');
  const entropy = await client.buildEntropy({ root_id: rootId, bin_id: 1 });
  console.log('Entropy summary:', entropy);

  console.log('AI audit demo completed.');
}

main().catch((err) => {
  console.error('AI audit demo failed:', err);
  process.exit(1);
});
