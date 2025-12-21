# UTL Deployment & SRE Reference

This directory contains **reference, not prescriptive**, deployment artifacts for
running UTL in an enterprise setting.

## 1. Single-Node Sandbox Topology

For pilots and local sandboxes, run:

- `utld` as a long-lived daemon (systemd or a simple supervisor)
- `utl_http` as an HTTP front-end on the same host
- `utl_cli` on operator workstations, pointing at the same Unix socket / HTTP base

Minimal pattern:

1. Start `utld` with env:
   - `UTLD_SOCKET=/tmp/utld.sock`
   - `UTLD_POLICY` (JSON policy)
   - `UTLD_POLICY_COMMIT_ID` (policy commit id)

2. Start `utl_http` with env:
   - `UTLD_SOCKET=/tmp/utld.sock`
   - `UTLD_HTTP_ADDR=0.0.0.0:8080`

3. Use `utl_cli`:
   - `utl roots-list`, `utl tx-record`, `utl dig-build` for core flows
   - `utl compliance-check`, `utl compliance-drift`, `utl policy-simulate`
   - `utl search-decisions`, `utl search-digs`, `utl search-compliance`

## 2. Kubernetes Topology (Reference)

For multi-tenant or production-like environments, one reference pattern is:

- **DaemonSet** (or sidecar) for `utld` on nodes that host protected workloads.
- **Deployment** for `utl_http` as a control-plane API in a dedicated namespace.

`utl_http` talks to `utld` via a Unix socket volume or TCP tunnel, depending on
how you package the images. The provided manifest assumes both processes run in
the **same pod** for simplicity.

## 3. Observability

- `utl_http` exposes `/health` and `/metrics`.
- `utld` logs to stderr; you can ship logs to your logging stack.

Recommended next steps:

- Configure Prometheus to scrape `/metrics` from the `utl_http` Service.
- Add log shipping (Fluent Bit, Vector, etc.) to centralize `utld`/`utl_http` logs.
- Define SLOs/SLIs per tenant and per product (e.g. decision latency, error rate).
