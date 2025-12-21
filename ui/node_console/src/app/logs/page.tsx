"use client";

import { useEffect, useState } from "react";

type LogChunk = {
  path: string;
  lines: string[];
};

const API_BASE =
  process.env.NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL ?? "http://127.0.0.1:8093";

export default function LogsPage() {
  const [chunks, setChunks] = useState<LogChunk[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError(null);

        const resp = await fetch(`${API_BASE}/api/logs?limit=200`);
        if (!resp.ok) {
          throw new Error(`request failed: ${resp.status}`);
        }
        const data: LogChunk[] = await resp.json();
        setChunks(data);
      } catch (e: any) {
        setError(e.message ?? String(e));
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  return (
    <main className="mx-auto max-w-5xl p-6 space-y-6">
      <header className="border-b border-slate-800 pb-4 mb-4">
        <h1 className="text-2xl font-semibold">Node Logs</h1>
        <p className="text-sm text-slate-400">
          Tail of key log files on this node. Configure paths with NODE_LOG_PATHS.
        </p>
      </header>

      {loading && <p className="text-slate-300">Loading logs...</p>}
      {error && <p className="text-red-400">Error: {error}</p>}

      {!loading && chunks.length === 0 && !error && (
        <p className="text-slate-400 text-sm">No log files readable for the configured paths.</p>
      )}

      {chunks.map((chunk) => (
        <section
          key={chunk.path}
          className="border border-slate-800 rounded-lg overflow-hidden"
        >
          <header className="bg-slate-900 px-3 py-2 text-xs font-mono text-slate-300 flex items-center justify-between">
            <span className="truncate">{chunk.path}</span>
          </header>
          <pre className="max-h-96 overflow-auto bg-slate-950 p-3 text-[11px] leading-snug text-slate-200">
            {chunk.lines.join("\n")}
          </pre>
        </section>
      ))}
    </main>
  );
}
