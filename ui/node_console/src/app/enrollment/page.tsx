"use client";

import { useEffect, useState } from "react";

type EnrollmentToken = {
  id: string;
  created_at: number;
  note?: string | null;
};

type EnrollmentTokensResponse = {
  tokens: EnrollmentToken[];
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function EnrollmentPage() {
  const [tokens, setTokens] = useState<EnrollmentToken[]>([]);
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function refresh() {
    try {
      setLoading(true);
      setError(null);

      const resp = await fetch(`${API_BASE}/api/enrollment/tokens`);
      if (!resp.ok) {
        throw new Error(`request failed: ${resp.status}`);
      }
      const data: EnrollmentTokensResponse = await resp.json();
      setTokens(data.tokens);
    } catch (e: any) {
      setError(e.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function createToken(ev: React.FormEvent) {
    ev.preventDefault();
    try {
      setCreating(true);
      setError(null);

      const resp = await fetch(`${API_BASE}/api/enrollment/tokens`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ note: note || null }),
      });
      if (!resp.ok) {
        throw new Error(`request failed: ${resp.status}`);
      }
      const tok: EnrollmentToken = await resp.json();
      setTokens((prev) => [tok, ...prev]);
      setNote("");
    } catch (e: any) {
      setError(e.message ?? String(e));
    } finally {
      setCreating(false);
    }
  }

  return (
    <main className="mx-auto max-w-4xl p-6 space-y-6">
      <header className="border-b border-slate-800 pb-4 mb-4">
        <h1 className="text-2xl font-semibold">Enrollment Tokens</h1>
        <p className="text-sm text-slate-400">
          Local tokens a node operator can use to enroll new agents into this node
          console / UTLD stack.
        </p>
      </header>

      {loading && <p className="text-slate-300">Loading tokens...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      <section className="border border-slate-800 rounded-lg p-4 space-y-4">
        <h2 className="text-sm font-semibold text-slate-200">
          Create Enrollment Token
        </h2>
        <form onSubmit={createToken} className="space-y-3 text-sm">
          <div className="space-y-1">
            <label className="block text-slate-300 text-xs">
              Note (optional)
            </label>
            <input
              className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100 outline-none focus:border-slate-400"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Where or why this token is used"
            />
          </div>
          <button
            type="submit"
            disabled={creating}
            className="inline-flex items-center rounded bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-60"
          >
            {creating ? "Creating..." : "Create token"}
          </button>
        </form>
      </section>

      <section className="border border-slate-800 rounded-lg overflow-hidden">
        <header className="bg-slate-900 px-3 py-2 text-xs text-slate-300">
          Existing tokens
        </header>
        {tokens.length === 0 ? (
          <p className="px-3 py-2 text-xs text-slate-400">
            No tokens yet. Create one above.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead className="bg-slate-900 text-slate-300">
                <tr>
                  <th className="px-3 py-2 text-left">Created at</th>
                  <th className="px-3 py-2 text-left">Token ID</th>
                  <th className="px-3 py-2 text-left">Note</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => (
                  <tr key={t.id} className="border-t border-slate-800">
                    <td className="px-3 py-1 text-slate-300">
                      {new Date(t.created_at * 1000).toISOString()}
                    </td>
                    <td className="px-3 py-1 font-mono text-[11px] break-all">
                      {t.id}
                    </td>
                    <td className="px-3 py-1 text-slate-300">
                      {t.note ?? "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
