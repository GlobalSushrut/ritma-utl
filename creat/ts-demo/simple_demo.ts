// Simple demo to test basic UTL functionality
import { UtlHttpClient } from '../ts-sdk/utl-sdk';

declare const process: { exit(code?: number): void; env: { [key: string]: string | undefined } };

async function main() {
  const client = new UtlHttpClient();

  console.log('[demo] health check...');
  const health = await client.health();
  console.log('[demo] health:', health);

  console.log('[demo] listing roots...');
  const roots = await client.listRoots();
  console.log('[demo] roots:', roots);

  console.log('[demo] fetching /metrics...');
  const base = process.env?.UTL_HTTP_BASE ?? 'http://127.0.0.1:8080';
  const token = process.env?.UTL_HTTP_TOKEN;
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  
  const res = await fetch(`${base}/metrics`, { headers });
  const text = await res.text();
  console.log('[demo] /metrics:\n' + text);

  console.log('[demo] simple demo completed.');
}

main().catch((err) => {
  console.error('[demo] failed:', err);
  process.exit(1);
});
