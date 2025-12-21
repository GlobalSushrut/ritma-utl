"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

interface GenerateReportButtonProps {
  orgId: string;
}

export function GenerateReportButton({ orgId }: GenerateReportButtonProps) {
  const router = useRouter();
  const [scope, setScope] = useState("global");
  const [tenantId, setTenantId] = useState("");
  const [framework, setFramework] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/reports", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          org_id: orgId,
          tenant_id: tenantId || null,
          scope: scope || "global",
          framework: framework || null,
        }),
      });

      if (!res.ok) {
        let message = `Request failed: ${res.status}`;
        try {
          const data = await res.json();
          if (typeof data?.error === "string") {
            message = data.error;
          }
        } catch {
          // ignore JSON parse errors
        }
        throw new Error(message);
      }

      router.refresh();
    } catch (err: any) {
      setError(err?.message ?? "Failed to generate report");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="mt-4 mb-3 flex flex-wrap items-end gap-3 text-xs text-slate-200"
    >
      <div className="flex flex-col gap-1">
        <label className="text-[11px] text-slate-400">Scope</label>
        <input
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          placeholder="e.g. global or pci-segment"
          className="rounded-md bg-ritma-graphite border border-white/10 px-2 py-1 text-[11px] outline-none focus:ring-1 focus:ring-ritma-orange/70"
        />
      </div>
      <div className="flex flex-col gap-1">
        <label className="text-[11px] text-slate-400">Tenant (optional)</label>
        <input
          value={tenantId}
          onChange={(e) => setTenantId(e.target.value)}
          placeholder="tenant id"
          className="rounded-md bg-ritma-graphite border border-white/10 px-2 py-1 text-[11px] outline-none focus:ring-1 focus:ring-ritma-orange/70"
        />
      </div>
      <div className="flex flex-col gap-1">
        <label className="text-[11px] text-slate-400">Framework (optional)</label>
        <input
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          placeholder="e.g. soc2, iso27001"
          className="rounded-md bg-ritma-graphite border border-white/10 px-2 py-1 text-[11px] outline-none focus:ring-1 focus:ring-ritma-orange/70"
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        className="inline-flex items-center justify-center px-3 py-1.5 rounded-ritma-button bg-ritma-orange text-ritma-bg-void text-[11px] font-medium hover:brightness-110 disabled:opacity-60 disabled:cursor-not-allowed transition"
      >
        {loading ? "Generating…" : "Generate report"}
      </button>
      {error && (
        <div className="basis-full text-[11px] text-ritma-red mt-1">{error}</div>
      )}
    </form>
  );
}
