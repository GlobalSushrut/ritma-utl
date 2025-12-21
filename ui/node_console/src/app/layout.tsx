import type { Metadata } from "next";
import "./globals.css";

const cloudUrl = process.env.NEXT_PUBLIC_CLOUD_CONSOLE_URL ?? "#";
const complianceUrl = process.env.NEXT_PUBLIC_COMPLIANCE_CONSOLE_URL ?? "#";
const nodeUrl = process.env.NEXT_PUBLIC_NODE_CONSOLE_URL ?? "#";

export const metadata: Metadata = {
  title: "Ritma Node Console",
  description: "Node inventory, health, and enforcement view",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100">
        <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3 text-sm">
            <div className="font-semibold tracking-tight">
              Ritma Console
            </div>
            <nav className="flex items-center gap-4 text-slate-300">
              <a href={cloudUrl} className="hover:text-white">
                Cloud
              </a>
              <a href={complianceUrl} className="hover:text-white">
                Compliance
              </a>
              <a href={nodeUrl} className="hover:text-white">
                Nodes
              </a>
            </nav>
          </div>
        </header>
        <main className="min-h-[calc(100vh-3rem)]">
          {children}
        </main>
      </body>
    </html>
  );
}
