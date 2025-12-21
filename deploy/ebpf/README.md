# Ritma eBPF Firewall

This directory contains the eBPF program and tooling for Ritma's kernel-level firewall enforcement.

## Components

### `ritma_fw.c`

XDP program that enforces firewall decisions based on DID pairs.

**Map:** `ritma_fw_pairs`
- Type: `BPF_MAP_TYPE_HASH`
- Key: `struct fw_key { u32 src_id; u32 dst_id; }`
- Value: `u8` (0=allow, 1=deny, 2=throttle, 3=isolate)
- Pinned at: `/sys/fs/bpf/ritma_fw_pairs`

**Decision Model:**
- Deny-list: presence of entry with value=1 or 3 → drop packet.
- Absence of entry or value=0 → allow packet.

### `ritma-ebpf-helper`

User-space helper binary that updates the BPF map based on policy decisions.

**Usage:**
```bash
ritma-ebpf-helper <src_did> <dst_did> <decision>
```

**Environment:**
- `RITMA_EBPF_MAP_PATH` - Path to pinned map (default: `/sys/fs/bpf/ritma_fw_pairs`)
- `RITMA_EBPF_MODE` - Mode: `log` or `bpf` (default: `log`)

**Modes:**
- `log`: Only log intended map updates (safe for testing)
- `bpf`: Actually update BPF map via `bpftool`

## Building & Loading

### Prerequisites

```bash
# Install dependencies
sudo apt-get install clang llvm libbpf-dev bpftool

# Or on RHEL/Fedora
sudo dnf install clang llvm libbpf-devel bpftool
```

### Compile BPF Program

```bash
clang -O2 -target bpf -c ritma_fw.c -o ritma_fw.o
```

### Load & Pin

```bash
# Load program and pin map
sudo bpftool prog load ritma_fw.o /sys/fs/bpf/ritma_fw \
    type xdp \
    pinmaps /sys/fs/bpf

# Attach to interface (e.g., eth0)
sudo bpftool net attach xdp pinned /sys/fs/bpf/ritma_fw dev eth0

# Verify
bpftool prog show
bpftool map show
```

### Unload

```bash
# Detach from interface
sudo bpftool net detach xdp dev eth0

# Remove pinned objects
sudo rm /sys/fs/bpf/ritma_fw
sudo rm /sys/fs/bpf/ritma_fw_pairs
```

## Integration with Ritma

### 1. Load BPF Program at Boot

Add to systemd unit or init script:

```bash
#!/bin/bash
# /usr/local/bin/ritma-ebpf-load.sh

set -e

BPF_OBJ=/usr/local/share/ritma/ritma_fw.o
BPF_PIN=/sys/fs/bpf/ritma_fw
IFACE=eth0

# Load and pin
bpftool prog load "$BPF_OBJ" "$BPF_PIN" type xdp pinmaps /sys/fs/bpf

# Attach to interface
bpftool net attach xdp pinned "$BPF_PIN" dev "$IFACE"

echo "Ritma eBPF firewall loaded on $IFACE"
```

### 2. Configure `security_host`

```bash
export SECURITY_HOST_FIREWALL_HELPER=/usr/local/bin/ritma_firewall_helper
export RITMA_FW_BACKEND=ebpf
export RITMA_FW_EBPF_HELPER=/usr/local/bin/ritma_ebpf_helper
export RITMA_EBPF_MAP_PATH=/sys/fs/bpf/ritma_fw_pairs
export RITMA_EBPF_MODE=bpf
```

### 3. Test

```bash
# Deny traffic from did:ritma:tenant:acme to did:ritma:svc:api
ritma-ebpf-helper "did:ritma:tenant:acme" "did:ritma:svc:api" deny

# Check map
sudo bpftool map dump pinned /sys/fs/bpf/ritma_fw_pairs

# Allow traffic (remove deny entry)
ritma-ebpf-helper "did:ritma:tenant:acme" "did:ritma:svc:api" allow

# Verify removal
sudo bpftool map dump pinned /sys/fs/bpf/ritma_fw_pairs
```

## DID → ID Mapping

Currently, `ritma-ebpf-helper` uses a simple hash function to map DIDs to u32 IDs:

```rust
fn did_to_id(did: &str) -> u32 {
    let mut hasher = DefaultHasher::new();
    did.hash(&mut hasher);
    (hasher.finish() & 0xFFFFFFFF) as u32
}
```

**For production:**
- Maintain a persistent DID→ID registry (e.g., in a separate BPF map or database).
- Use sequential IDs to avoid hash collisions.
- Sync registry across cluster nodes.

## IP → DID Mapping

The current XDP program is a skeleton. To make it functional:

1. **Add IP→DID map:**
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __type(key, __u32);  // IP address
       __type(value, __u32); // DID ID
   } ip_to_did SEC(".maps");
   ```

2. **Populate from userspace:**
   - When a service starts, register its IP → DID mapping.
   - Update map via `bpftool` or libbpf.

3. **Lookup in XDP:**
   ```c
   __u32 src_ip = bpf_ntohl(iph->saddr);
   __u32 dst_ip = bpf_ntohl(iph->daddr);

   __u32 *src_did_id = bpf_map_lookup_elem(&ip_to_did, &src_ip);
   __u32 *dst_did_id = bpf_map_lookup_elem(&ip_to_did, &dst_ip);

   if (!src_did_id || !dst_did_id)
       return XDP_PASS;

   struct fw_key key = { .src_id = *src_did_id, .dst_id = *dst_did_id };
   __u8 *decision = bpf_map_lookup_elem(&ritma_fw_pairs, &key);

   if (decision && (*decision == 1 || *decision == 3))
       return XDP_DROP;

   return XDP_PASS;
   ```

## Performance Considerations

- **XDP:** Runs before sk_buff allocation → very fast.
- **Map lookups:** O(1) hash lookups, ~100ns per lookup.
- **Scalability:** 10k entries → ~1MB memory, negligible overhead.

## Security Notes

- BPF programs are verified by the kernel (no crashes, no infinite loops).
- Maps are isolated per network namespace (if needed).
- Requires `CAP_BPF` + `CAP_NET_ADMIN` (or root).

## Troubleshooting

### Map not found

```bash
# Check if map is pinned
ls -la /sys/fs/bpf/

# Reload BPF program
sudo /usr/local/bin/ritma-ebpf-load.sh
```

### bpftool errors

```bash
# Check bpftool version
bpftool version

# Ensure kernel supports BPF (5.4+)
uname -r
```

### Verify map updates

```bash
# Dump map contents
sudo bpftool map dump pinned /sys/fs/bpf/ritma_fw_pairs

# Expected output:
# key: 12 34 56 78  9a bc de f0  value: 01
# (src_id=0x12345678, dst_id=0x9abcdef0, decision=deny)
```
