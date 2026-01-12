#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker/compose.sidecar.yml"

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return 0
  fi
  echo "missing docker compose (plugin) or docker-compose" >&2
  return 1
}

cmd="${1:-}"
shift || true

case "${cmd}" in
  up)
    : "${RITMA_NODE_ID:?set RITMA_NODE_ID (e.g. export RITMA_NODE_ID=$(hostname))}"
    if [[ "${EUID}" -eq 0 ]]; then
      mkdir -p /var/lib/ritma /run/ritma/locks
      chmod 700 /var/lib/ritma /run/ritma/locks
    else
      echo "warning: not running as root; ensure /var/lib/ritma and /run/ritma/locks exist and are writable (recommended perms: 0700)" >&2
    fi
    c=$(compose_cmd)
    exec ${c} -f "${COMPOSE_FILE}" up -d --build "$@"
    ;;
  down)
    c=$(compose_cmd)
    exec ${c} -f "${COMPOSE_FILE}" down "$@"
    ;;
  ps)
    c=$(compose_cmd)
    exec ${c} -f "${COMPOSE_FILE}" ps "$@"
    ;;
  logs)
    c=$(compose_cmd)
    exec ${c} -f "${COMPOSE_FILE}" logs -f --tail=200 "$@"
    ;;
  *)
    echo "usage: ${0} {up|down|ps|logs} [compose args...]" >&2
    exit 2
    ;;
 esac
