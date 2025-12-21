# Ritma Node Wallet Console (Local)

This folder will contain the **local, Grafana-style Node "Wallet" Console** UI.

- Runs alongside `utld` / `utl_http` / `security_kit` on a node or cluster.
- Binds to the node's wallet / DID.
- Focuses on:
  - Per-node SLOs.
  - Connectors & dry-run.
  - Kernel / CLI terminal.
  - Node-local evidence & compliance.
  - Node logs and traces.

A separate React/Next.js app (or a lighter Vite/SPA) can be added here later, reusing the same Tailwind theme and component system as the Cloud Business Console.
