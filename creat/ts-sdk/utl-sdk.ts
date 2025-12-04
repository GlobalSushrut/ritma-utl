// Minimal TypeScript SDK for the UTL HTTP gateway.
// Assumes the HTTP service (utl_http) is running and reachable.

declare const process: { env: Record<string, string | undefined> };

export interface RegisterRootRequest {
  root_id: number;
  root_hash: string; // 32-byte hex string
  tx_hook?: number;
  params?: Record<string, string>;
}

export interface RecordTransitionRequest {
  entity_id: number;
  root_id: number;
  signature: string; // hex string
  data: string; // UTF-8 string payload
  addr_heap_hash: string; // 32-byte hex
  hook_hash: string; // 32-byte hex
  logic_ref: string;
  wall: string;
  params?: Record<string, string>;
}

export interface DigBuildRequest {
  root_id: number;
  file_id: number;
  time_start: number;
  time_end: number;
}

export interface EntropyRequest {
  root_id: number;
  bin_id: number;
}

export interface HealthResponse {
  status: string;
}

export interface RootsResponse {
  root_ids: number[];
}

export interface DigSummaryResponse {
  root_id: number;
  file_id: number;
  merkle_root: string; // hex
  record_count: number;
}

export interface EntropyResponse {
  root_id: number;
  bin_id: number;
  local_entropy: number;
}

export class UtlHttpClient {
  readonly baseUrl: string;
  readonly authToken?: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl ?? process.env.UTL_HTTP_BASE ?? 'http://127.0.0.1:8080';
    this.authToken = process.env.UTL_HTTP_TOKEN;
  }

  async health(): Promise<HealthResponse> {
    const res = await fetch(`${this.baseUrl}/health`);
    if (!res.ok) throw new Error(`health failed: ${res.status}`);
    return (await res.json()) as HealthResponse;
  }

  async listRoots(): Promise<RootsResponse> {
    const res = await fetch(`${this.baseUrl}/roots`);
    if (!res.ok) throw new Error(`listRoots failed: ${res.status}`);
    return (await res.json()) as RootsResponse;
  }

  async registerRoot(body: RegisterRootRequest): Promise<void> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.authToken) headers['Authorization'] = `Bearer ${this.authToken}`;
    const res = await fetch(`${this.baseUrl}/roots`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`registerRoot failed: ${res.status} ${text}`);
    }
  }

  async recordTransition(body: RecordTransitionRequest): Promise<void> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.authToken) headers['Authorization'] = `Bearer ${this.authToken}`;
    const res = await fetch(`${this.baseUrl}/transitions`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`recordTransition failed: ${res.status} ${text}`);
    }
  }

  async buildDig(body: DigBuildRequest): Promise<DigSummaryResponse> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.authToken) headers['Authorization'] = `Bearer ${this.authToken}`;
    const res = await fetch(`${this.baseUrl}/dig`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`buildDig failed: ${res.status} ${text}`);
    }
    return (await res.json()) as DigSummaryResponse;
  }

  async buildEntropy(body: EntropyRequest): Promise<EntropyResponse> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.authToken) headers['Authorization'] = `Bearer ${this.authToken}`;
    const res = await fetch(`${this.baseUrl}/entropy`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`buildEntropy failed: ${res.status} ${text}`);
    }
    return (await res.json()) as EntropyResponse;
  }
}
