#!/bin/bash
# Test script for XDP firewall enforcement
# Requires root and a test network interface

set -e

echo "=== Ritma XDP Firewall Test ==="

# Configuration
IFACE="${1:-lo}"  # Use loopback by default for testing
BPF_OBJ="ritma_fw.o"
BPF_PROG="/sys/fs/bpf/ritma_fw"
MAP_FW="/sys/fs/bpf/ritma_fw_pairs"
MAP_IP="/sys/fs/bpf/ip_to_did"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "Error: bpftool not found. Install with: apt-get install linux-tools-generic"
    exit 1
fi

# Compile BPF program
echo "[1/7] Compiling BPF program..."
clang -O2 -target bpf -c ritma_fw.c -o "$BPF_OBJ" -I./include

# Load and pin
echo "[2/7] Loading BPF program and pinning maps..."
bpftool prog load "$BPF_OBJ" "$BPF_PROG" type xdp pinmaps /sys/fs/bpf

# Attach to interface
echo "[3/7] Attaching XDP program to $IFACE..."
bpftool net attach xdp pinned "$BPF_PROG" dev "$IFACE"

# Register test IPs → DIDs
echo "[4/7] Registering test IP→DID mappings..."
# 127.0.0.1 → did:ritma:tenant:test_a (ID: hash)
# 127.0.0.2 → did:ritma:svc:test_b (ID: hash)

# For testing, manually calculate DID IDs or use ritma-ip-registry
echo "127.0.0.1 did:ritma:tenant:test_a" | ../../../target/release/ritma_ip_registry || echo "Note: ritma_ip_registry not found, skipping IP registration"

# Add deny rule: test_a → test_b
echo "[5/7] Adding deny rule for test_a → test_b..."
../../../target/release/ritma_ebpf_helper "did:ritma:tenant:test_a" "did:ritma:svc:test_b" deny || echo "Note: ritma_ebpf_helper not found"

# Dump maps
echo "[6/7] Dumping BPF maps..."
echo "--- ritma_fw_pairs ---"
bpftool map dump pinned "$MAP_FW" || echo "Map empty or not found"

echo "--- ip_to_did ---"
bpftool map dump pinned "$MAP_IP" || echo "Map empty or not found"

echo "--- stats ---"
bpftool map dump pinned /sys/fs/bpf/stats || echo "Stats map not found"

# Test traffic (would require actual packet generation)
echo "[7/7] XDP program loaded and configured!"
echo ""
echo "To test:"
echo "  1. Generate traffic to $IFACE"
echo "  2. Check stats: bpftool map dump pinned /sys/fs/bpf/stats"
echo "  3. Verify drops: watch -n1 'bpftool map dump pinned /sys/fs/bpf/stats'"
echo ""
echo "To cleanup:"
echo "  sudo bpftool net detach xdp dev $IFACE"
echo "  sudo rm /sys/fs/bpf/ritma_fw*"
echo "  sudo rm /sys/fs/bpf/ip_to_did"
echo "  sudo rm /sys/fs/bpf/stats"
