import Link from "next/link";

export default function HeroPage() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center px-6 py-12 bg-gradient-to-b from-ritma-bg-void to-ritma-graphite">
      <div className="max-w-5xl w-full flex flex-col md:flex-row gap-10 items-center">
        <div className="flex-1 space-y-6">
          <h1 className="text-4xl md:text-5xl font-semibold tracking-tight text-slate-50">
            Ritma Cloud
          </h1>
          <p className="text-lg text-slate-300 max-w-xl">
            Kalis mind, Cloudflares polish, and Vantages observability  all wrapped into a forensic, neon-void
            intelligence console for modern CISOs.
          </p>
          <ul className="text-sm text-slate-400 space-y-1">
            <li>ICR  Immutable Compliance & Evidence</li>
            <li>UTLD  Universal Truth Layer for security decisions</li>
            <li>Observability-first SLOs across connectors, evidence, and compliance</li>
          </ul>
          <div className="flex flex-wrap gap-4 pt-4">
            <Link
              href="/orgs/demo/dashboard"
              className="inline-flex items-center justify-center px-5 py-2.5 rounded-ritma-button bg-ritma-orange text-ritma-bg-void text-sm font-medium hover:brightness-110 transition"
            >
              Continue to console
            </Link>
          </div>
        </div>
        <div className="flex-1 w-full max-w-md">
          <div className="rounded-ritma-card border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
            <h2 className="text-sm font-medium text-slate-200 mb-4">Sign in</h2>
            <form className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs text-slate-300">Email</label>
                <input
                  type="email"
                  className="w-full rounded-md bg-ritma-graphite border border-white/10 px-3 py-2 text-sm text-slate-100 outline-none focus:ring-2 focus:ring-ritma-orange/70"
                  placeholder="ciso@example.com"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-slate-300">Password</label>
                <input
                  type="password"
                  className="w-full rounded-md bg-ritma-graphite border border-white/10 px-3 py-2 text-sm text-slate-100 outline-none focus:ring-2 focus:ring-ritma-orange/70"
                  placeholder="••••••••"
                />
              </div>
              <button
                type="submit"
                className="w-full rounded-ritma-button bg-ritma-orange text-ritma-bg-void text-sm font-medium py-2.5 hover:brightness-110 transition"
              >
                Sign in
              </button>
            </form>
          </div>
        </div>
      </div>
    </main>
  );
}
