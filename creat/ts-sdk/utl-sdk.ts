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

export class UtlHttpError extends Error {
  readonly status: number;
  readonly method: string;
  readonly path: string;
  readonly body: unknown;

  constructor(args: { status: number; method: string; path: string; body: unknown }) {
    super(`${args.method} ${args.path} failed: ${args.status}`);
    this.status = args.status;
    this.method = args.method;
    this.path = args.path;
    this.body = args.body;
  }
}

export interface UtlHttpClientOptions {
  baseUrl?: string;
  token?: string;
  tenantId?: string;
  timeoutMs?: number;
  retries?: number;
}

export class UtlHttpClient {
  readonly baseUrl: string;
  readonly authToken?: string;
  readonly tenantId?: string;
  readonly timeoutMs: number;
  readonly retries: number;

  constructor(baseUrlOrOpts?: string | UtlHttpClientOptions) {
    const opts: UtlHttpClientOptions =
      typeof baseUrlOrOpts === 'string' || baseUrlOrOpts == null ? { baseUrl: baseUrlOrOpts } : baseUrlOrOpts;
    this.baseUrl = opts.baseUrl ?? process.env.UTL_HTTP_BASE ?? 'http://127.0.0.1:8080';
    this.authToken = opts.token ?? process.env.UTL_HTTP_TOKEN;
    this.tenantId = opts.tenantId ?? process.env.UTL_HTTP_TENANT_ID;
    this.timeoutMs = opts.timeoutMs ?? 10000;
    this.retries = opts.retries ?? 2;
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;

    const headers: Record<string, string> = {};
    if (body != null) headers['Content-Type'] = 'application/json';
    if (this.authToken) headers['Authorization'] = `Bearer ${this.authToken}`;
    if (this.tenantId) headers['x-tenant-id'] = this.tenantId;

    let lastErr: unknown = null;
    const attempts = Math.max(0, this.retries) + 1;
    for (let i = 0; i < attempts; i++) {
      const controller = typeof AbortController !== 'undefined' ? new AbortController() : undefined;
      const timeout = controller
        ? setTimeout(() => {
            try {
              controller.abort();
            } catch (_) {
              // ignore
            }
          }, this.timeoutMs)
        : undefined;

      try {
        const res = await fetch(url, {
          method,
          headers,
          body: body == null ? undefined : JSON.stringify(body),
          signal: controller?.signal,
        });

        const text = await res.text();
        const parsed = text ? (() => {
          try {
            return JSON.parse(text);
          } catch (_) {
            return text;
          }
        })() : null;

        if (!res.ok) {
          const retryable = method === 'GET' && (res.status === 429 || res.status === 502 || res.status === 503 || res.status === 504);
          if (retryable && i + 1 < attempts) {
            await this.sleep(200 * Math.pow(2, i));
            continue;
          }
          throw new UtlHttpError({ status: res.status, method, path, body: parsed });
        }

        return parsed as T;
      } catch (e) {
        lastErr = e;
        const retryable = method === 'GET';
        if (retryable && i + 1 < attempts) {
          await this.sleep(200 * Math.pow(2, i));
          continue;
        }
        throw e;
      } finally {
        if (timeout) clearTimeout(timeout);
      }
    }

    throw lastErr;
  }

  async health(): Promise<HealthResponse> {
    return await this.request<HealthResponse>('GET', '/health');
  }

  async listRoots(): Promise<RootsResponse> {
    return await this.request<RootsResponse>('GET', '/roots');
  }

  async registerRoot(body: RegisterRootRequest): Promise<void> {
    const params = { ...(body.params ?? {}) };
    if (this.tenantId && params['tenant_id'] == null) params['tenant_id'] = this.tenantId;
    await this.request<void>('POST', '/roots', { ...body, params });
  }

  async recordTransition(body: RecordTransitionRequest): Promise<void> {
    const params = { ...(body.params ?? {}) };
    if (this.tenantId && params['tenant_id'] == null) params['tenant_id'] = this.tenantId;
    await this.request<void>('POST', '/transitions', { ...body, params });
  }

  async buildDig(body: DigBuildRequest): Promise<DigSummaryResponse> {
    return await this.request<DigSummaryResponse>('POST', '/dig', body);
  }

  async buildEntropy(body: EntropyRequest): Promise<EntropyResponse> {
    return await this.request<EntropyResponse>('POST', '/entropy', body);
  }
}
