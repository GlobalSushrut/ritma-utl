"use client";

import { useEffect, useState } from "react";

type ConfigInfo = {
  node_controller_listen_addr: string;
  tutld_compliance_index_path: string;
  tutld_slo_events_path: string;
  tutld_decision_events_path: string;
  tutld_dig_index_db_path: string;
  node_log_paths: string[];
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function ConfigPage() {
  const [config, setConfig] = useState<ConfigInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError(null);

        const resp = await fetch(`${API_BASE}/api/config`);
        if (!resp.ok) {
          throw new Error(`request failed: ${resp.status}`);
        }
        const data: ConfigInfo = await resp.json();
        setConfig(data);
      } catch (e: any) {
        setError(e.message ?? String(e));
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  return (
    <main className="mx-auto max-w-4xl p-6 space-y-6">
      <header className="border-b border-slate-800 pb-4 mb-4">
        <h1 className="text-2xl font-semibold">Node Console Config</h1>
        <p className="text-sm text-slate-400">
          Effective configuration and key file paths for this node-local console.
        </p>
      </header>

      {loading && <p className="text-slate-300">Loading config...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      {!loading && !config && !error && (
        <p className="text-slate-400 text-sm">No config information available.</p>
      )}

      {config && (
        <section className="space-y-4">
          <div className="border border-slate-800 rounded-lg p-4 space-y-2">
            <h2 className="text-sm font-semibold text-slate-200">
              Node Controller
            </h2>
            <div className="text-xs text-slate-300">
              <div className="font-medium text-slate-400">Listen address</div>
              <div className="font-mono break-all">
                {config.node_controller_listen_addr}
              </div>
            </div>
          </div>

          <div className="border border-slate-800 rounded-lg p-4 space-y-2">
            <h2 className="text-sm font-semibold text-slate-200">
              UTLD / SecurityKit Files
            </h2>
            <dl className="grid gap-2 text-xs text-slate-300">
              <div>
                <dt className="font-medium text-slate-400">
                  UTLD_COMPLIANCE_INDEX
                </dt>
                <dd className="font-mono break-all">
                  {config.tutld_compliance_index_path}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-400">UTLD_SLO_EVENTS</dt>
                <dd className="font-mono break-all">
                  {config.tutld_slo_events_path}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-400">
                  UTLD_DECISION_EVENTS
                </dt>
                <dd className="font-mono break-all">
                  {config.tutld_decision_events_path}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-slate-400">UTLD_DIG_INDEX_DB</dt>
                <dd className="font-mono break-all">
                  {config.tutld_dig_index_db_path}
                </dd>
              </div>
            </dl>
          </div>

          <div className="border border-slate-800 rounded-lg p-4 space-y-2">
            <h2 className="text-sm font-semibold text-slate-200">Log Paths</h2>
            {config.node_log_paths.length === 0 ? (
              <p className="text-xs text-slate-400">
                No log paths configured (NODE_LOG_PATHS env).
              </p>
            ) : (
              <ul className="list-disc pl-5 text-xs text-slate-300">
                {config.node_log_paths.map((p) => (
                  <li key={p} className="font-mono break-all">
                    {p}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      )}
    </main>
  );
}
