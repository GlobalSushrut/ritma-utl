import type { ReactNode } from "react";
import Link from "next/link";

type OrgLayoutProps = {
  children: ReactNode;
  params: { orgId: string };
};

export default function OrgLayout({ children, params }: OrgLayoutProps) {
  const { orgId } = params;

  const base = `/orgs/${orgId}`;

  return (
    <div className="min-h-screen flex bg-ritma-bg-void text-slate-100">
      <aside className="w-60 border-r border-white/10 bg-ritma-graphite/60 backdrop-blur flex flex-col">
        <div className="h-16 flex items-center px-4 border-b border-white/10">
          <span className="text-sm font-semibold text-ritma-orange">Ritma Cloud</span>
        </div>
        <nav className="flex-1 py-4 space-y-1 text-sm">
          <Link href={`${base}/dashboard`} className="block px-4 py-2 hover:bg-white/5">
            Overview
          </Link>
          <Link href={`${base}/tenants`} className="block px-4 py-2 hover:bg-white/5">
            Tenants
          </Link>
          <Link href={`${base}/nodes`} className="block px-4 py-2 hover:bg-white/5">
            Nodes
          </Link>
          <Link href={`${base}/evidence`} className="block px-4 py-2 hover:bg-white/5">
            Evidence
          </Link>
          <Link href={`${base}/reports`} className="block px-4 py-2 hover:bg-white/5">
            Reports
          </Link>
          <Link href={`${base}/health`} className="block px-4 py-2 hover:bg-white/5">
            Health & SLOs
          </Link>
          <Link href={`${base}/plans`} className="block px-4 py-2 hover:bg-white/5">
            Plans & Products
          </Link>
          <Link href={`${base}/settings`} className="block px-4 py-2 hover:bg-white/5">
            Settings
          </Link>
        </nav>
      </aside>
      <main className="flex-1 min-h-screen flex flex-col">
        <header className="h-16 border-b border-white/10 flex items-center justify-between px-6 bg-ritma-bg-void/80 backdrop-blur">
          <div className="text-xs text-slate-400">
            Org ID
            <span className="ml-2 inline-flex items-center rounded-full border border-white/15 px-2 py-0.5 text-[11px] text-slate-200">
              {orgId}
            </span>
          </div>
          <div className="text-xs text-slate-400">
            Ritma Cloud Business Console
          </div>
        </header>
        <section className="flex-1 px-6 py-4 overflow-y-auto">{children}</section>
      </main>
    </div>
  );
}
