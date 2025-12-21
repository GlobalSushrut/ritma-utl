"use client";

import { useEffect, useState } from "react";

type WalletInfo = {
  key_id: string;
  key_hash: string;
  label?: string | null;
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function WalletPage() {
  const [wallet, setWallet] = useState<WalletInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError(null);

        const resp = await fetch(`${API_BASE}/api/wallet`);
        if (!resp.ok) {
          throw new Error(`request failed: ${resp.status}`);
        }
        const data: WalletInfo = await resp.json();
        setWallet(data);
      } catch (e: any) {
        setError(e.message ?? String(e));
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  return (
    <main className="mx-auto max-w-3xl p-6 space-y-6">
      <header className="border-b border-slate-800 pb-4 mb-4">
        <h1 className="text-2xl font-semibold">Node Wallet</h1>
        <p className="text-sm text-slate-400">
          Key material used by this node, derived from the local node keystore and env.
        </p>
      </header>

      {loading && <p className="text-slate-300">Loading wallet info...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      {!loading && !wallet && !error && (
        <p className="text-slate-400 text-sm">No wallet information available.</p>
      )}

      {wallet && (
        <section className="border border-slate-800 rounded-lg p-4 space-y-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Key ID</h2>
            <p className="font-mono text-xs break-all text-slate-300">
              {wallet.key_id}
            </p>
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Key Hash</h2>
            <p className="font-mono text-xs break-all text-slate-300">
              {wallet.key_hash}
            </p>
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Label</h2>
            <p className="text-slate-300 text-sm">{wallet.label ?? "-"}</p>
          </div>
        </section>
      )}
    </main>
  );
}
