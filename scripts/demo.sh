#!/bin/bash
# Ritma Demo Script
# Run after: sudo apt install ritma
# Usage: ritma-demo [scenario]

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEMO_DIR="${RITMA_DEMO_DIR:-/tmp/ritma-demo}"
SCENARIO="${1:-basic}"

info() { echo -e "${GREEN}[RITMA]${NC} $1"; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Setup demo environment
setup() {
    info "Setting up demo environment at $DEMO_DIR"
    mkdir -p "$DEMO_DIR"/{data,out,config}
    
    export RITMA_BASE_DIR="$DEMO_DIR/data"
    export RITMA_OUT_DIR="$DEMO_DIR/out"
    export RITMA_OUT_ENABLE=1
    export RITMA_CAS_ENABLE=1
    export RITMA_NODE_ID="demo-node"
}

# Scenario: Basic - Simple proofpack generation
demo_basic() {
    info "Running BASIC demo - Generate a proofpack"
    echo
    
    step "1. Creating demo proofpack..."
    ritma demo --namespace "ns://demo/basic" --window-secs 10
    
    step "2. Listing generated proofpacks..."
    ls -la "$DEMO_DIR/out/exports/proofpacks/" 2>/dev/null || echo "Check $DEMO_DIR/out"
    
    PACK=$(ls -t "$DEMO_DIR/out/exports/proofpacks/" 2>/dev/null | head -1)
    if [ -n "$PACK" ]; then
        step "3. Verifying proofpack..."
        ritma verify-proof --path "$DEMO_DIR/out/exports/proofpacks/$PACK"
    fi
    
    echo
    info "✅ Basic demo complete!"
    info "ProofPack at: $DEMO_DIR/out/exports/proofpacks/$PACK"
}

# Scenario: Capture - Real system event capture
demo_capture() {
    info "Running CAPTURE demo - Capture real system events"
    echo
    
    step "1. Starting sidecar for 30 seconds..."
    timeout 35 ritma-sidecar 2>&1 &
    SIDECAR_PID=$!
    
    step "2. Generating some activity..."
    for i in {1..5}; do
        curl -s https://example.com > /dev/null 2>&1 || true
        ls /tmp > /dev/null
        sleep 2
    done
    
    step "3. Waiting for capture to complete..."
    wait $SIDECAR_PID 2>/dev/null || true
    
    step "4. Checking captured events..."
    if [ -f "$DEMO_DIR/data/index_db.sqlite" ]; then
        COUNT=$(sqlite3 "$DEMO_DIR/data/index_db.sqlite" "SELECT COUNT(*) FROM trace_events;" 2>/dev/null || echo "0")
        info "Captured $COUNT real events!"
    fi
    
    echo
    info "✅ Capture demo complete!"
    info "Events stored in: $DEMO_DIR/data/index_db.sqlite"
}

# Scenario: Serve - Generate and serve proofpack via web
demo_serve() {
    info "Running SERVE demo - ProofPack with web viewer"
    echo
    
    step "1. Generating proofpack with QR code..."
    ritma demo --namespace "ns://demo/serve" --window-secs 10 --qr --serve --port 8080 &
    SERVER_PID=$!
    
    sleep 3
    
    info "🌐 Web viewer running at http://localhost:8080"
    info "Press Ctrl+C to stop"
    
    wait $SERVER_PID
}

# Scenario: Forensic - Full forensic pipeline
demo_forensic() {
    info "Running FORENSIC demo - Full evidence pipeline"
    echo
    
    step "1. Creating namespace..."
    NS="ns://demo/forensic/$(date +%s)"
    
    step "2. Generating forensic evidence..."
    ritma demo --namespace "$NS" --window-secs 15 --qr
    
    step "3. Exporting incident bundle..."
    PACK_DIR=$(ls -td "$DEMO_DIR/out/exports/proofpacks/"* 2>/dev/null | head -1)
    
    if [ -n "$PACK_DIR" ]; then
        step "4. Verifying chain of custody..."
        ritma verify-proof --path "$PACK_DIR"
        
        step "5. ProofPack contents:"
        ls -la "$PACK_DIR"
    fi
    
    echo
    info "✅ Forensic demo complete!"
    info "Court-grade evidence at: $PACK_DIR"
}

# Help
show_help() {
    echo "Ritma Demo Script"
    echo
    echo "Usage: $0 [scenario]"
    echo
    echo "Scenarios:"
    echo "  basic     - Generate a simple proofpack (default)"
    echo "  capture   - Capture real system events"
    echo "  serve     - Generate proofpack with web viewer"
    echo "  forensic  - Full forensic evidence pipeline"
    echo
    echo "Examples:"
    echo "  $0 basic"
    echo "  $0 capture"
    echo "  RITMA_DEMO_DIR=/my/path $0 forensic"
}

# Main
main() {
    case "$SCENARIO" in
        basic)
            setup
            demo_basic
            ;;
        capture)
            setup
            demo_capture
            ;;
        serve)
            setup
            demo_serve
            ;;
        forensic)
            setup
            demo_forensic
            ;;
        -h|--help|help)
            show_help
            ;;
        *)
            echo "Unknown scenario: $SCENARIO"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
