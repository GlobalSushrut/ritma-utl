// Minimal Node.js SDK for the UTL HTTP gateway.
// Requires Node 18+ (built-in fetch) or a global fetch polyfill.

class UtlHttpClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl || process.env.UTL_HTTP_BASE || 'http://127.0.0.1:8080';
    this.token = process.env.UTL_HTTP_TOKEN;
  }

  async _request(path, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    const res = await fetch(this.baseUrl + path, {
      headers,
      ...options,
    });
    const text = await res.text();
    let body;
    try {
      body = text ? JSON.parse(text) : null;
    } catch (_) {
      body = text;
    }
    if (!res.ok) {
      const msg = typeof body === 'string' ? body : JSON.stringify(body);
      throw new Error(`${options.method || 'GET'} ${path} failed: ${res.status} ${msg}`);
    }
    return body;
  }

  async health() {
    return this._request('/health');
  }

  async listRoots() {
    return /** @type {{ root_ids: number[] }} */ (await this._request('/roots'));
  }

  async registerRoot(body) {
    await this._request('/roots', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async recordTransition(body) {
    await this._request('/transitions', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  async buildDig(body) {
    return /** @type {{ root_id: number; file_id: number; merkle_root: string; record_count: number }} */ (
      await this._request('/dig', {
        method: 'POST',
        body: JSON.stringify(body),
      })
    );
  }

  async buildEntropy(body) {
    return /** @type {{ root_id: number; bin_id: number; local_entropy: number }} */ (
      await this._request('/entropy', {
        method: 'POST',
        body: JSON.stringify(body),
      })
    );
  }
}

module.exports = { UtlHttpClient };
