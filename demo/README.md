# Ritma Node Console Demo

This demo shows the *node-local* capabilities of Ritma using the `node_controller_api` backend and the Node Console UI.

It wires the console to **real files on disk**:

- SLO events (JSONL)
- Decision events / incidents (JSONL)
- Evidence index (SQLite dig index)
- Node logs (plain text)
- Wallet info (env / keystore)
- Enrollment tokens & node inventory (in-memory, via API)

The demo is intentionally simple and does **not** require a running cluster; it just uses sample data plus the existing `dig_index.sqlite` and `decision_events.jsonl` in this repo.

---

## 1. One-time setup

From the repo root (`ritma/`):

```bash
# 1) Ensure Rust and Node are installed.
# 2) Build dependencies at least once.
cargo build

# 3) Install Node Console dependencies.
cd ui/node_console
npm install
cd ../..
```

---

## 2. Seed demo data (SLO + logs)

This folder already contains sample files:

- `demo/slo_events.demo.jsonl` – a few fake SLO events.
- `demo/utld.demo.log` – a small log file.

You can inspect or edit them if you like.

---

## 3. Start the node_controller_api with demo paths

In a terminal from the repo root:

```bash
cd /home/umesh/Documents/connector/ritma

# Point node_controller_api at the demo/local files
export UTLD_SLO_EVENTS="$(pwd)/demo/slo_events.demo.jsonl"
# Reuse real decision events + dig index already in the repo
export UTLD_DECISION_EVENTS="$(pwd)/decision_events.jsonl"
export UTLD_DIG_INDEX_DB="$(pwd)/dig_index.sqlite"

# Log paths for the /logs page
export NODE_LOG_PATHS="$(pwd)/demo/utld.demo.log"

# Wallet info for the /wallet page (fallback if no keystore is configured)
export RITMA_KEY_ID="demo-node-key"
export RITMA_KEY_HASH="0123456789abcdef0123456789abcdef"
export RITMA_KEY_LABEL="Demo node key"

# (Optional) override listen address if you want something different
# export NODE_CONTROLLER_LISTEN_ADDR="0.0.0.0:8093"

# Run the node controller API
cargo run -p node_controller_api
```

Leave this process running.

---

## 4. Register a demo node

In a **second** terminal, after the API is listening on `127.0.0.1:8093`:

```bash
cd /home/umesh/Documents/connector/ritma

curl -sS -X POST "http://127.0.0.1:8093/api/nodes" \
  -H 'Content-Type: application/json' \
  -H 'x-user-id: demo-user' \
  -H 'x-org-id: demo-org' \
  -H 'x-roles: org_owner' \
  -d '{
    "org_id": "demo-org",
    "tenant_id": "tenant-a",
    "hostname": "demo-node-1",
    "labels": {"env": "demo", "region": "local"},
    "capabilities": ["utld", "security_kit", "connectors"]
  }' | jq .
```

The response JSON contains the generated `id` for this node. You can use it to send a heartbeat if you like (optional):

```bash
NODE_ID="<paste-id-here>"

curl -sS -X POST "http://127.0.0.1:8093/api/nodes/${NODE_ID}/heartbeat" \
  -H 'Content-Type: application/json' \
  -H 'x-user-id: demo-user' \
  -H 'x-org-id: demo-org' \
  -H 'x-roles: org_owner' \
  -d '{
    "status": "online",
    "utld_version": "0.1.0-demo",
    "policy_version": "demo-commit-1"
  }' | jq .
```

Now the **Nodes** page in the Node Console will show this node.

---

## 5. Start the Node Console UI

In a **third** terminal:

```bash
cd /home/umesh/Documents/connector/ritma/ui/node_console

# Tell the UI where the node_controller_api is
export NEXT_PUBLIC_NODE_CONTROLLER_BASE_URL="http://127.0.0.1:8093"

npm run dev
```

Open `http://localhost:3000` in your browser.

---

## 6. What to click through

With the above running and envs set, the Node Console pages should show real data:

- **`/` (Nodes)** – shows the demo node you registered.
- **`/slo`** – reads `demo/slo_events.demo.jsonl`.
- **`/incidents`** – reads `decision_events.jsonl` from repo root.
- **`/evidence`** – reads `dig_index.sqlite` from repo root.
- **`/wallet`** – shows `RITMA_KEY_ID` / `RITMA_KEY_HASH` / `RITMA_KEY_LABEL`.
- **`/logs`** – tails `demo/utld.demo.log`.
- **`/config`** – shows the effective paths and log settings.
- **`/enrollment`** – lets you create local enrollment tokens.

This gives you a complete node-local “Grafana-style” walkthrough of Ritma’s core artifacts without needing any external cloud setup.

From here you can:

- Swap in real `UTLD_*` paths for live data.
- Point Cloud/Compliance consoles at the same files for a full multi-console story.
