use core_types::{hash_bytes, Hash, UID};
use dig_mem::DigRecord;

#[derive(Clone, Debug)]
pub struct EntropyBin {
    pub bin_id: UID,
    pub frame_hashes: Vec<Hash>,
    pub local_entropy: f64,
}

#[derive(Clone, Debug)]
pub struct EntropyHeapNode {
    pub node_id: UID,
    pub children: Vec<UID>,
    pub bin_ref: Option<UID>,
    pub merkle_root: Hash,
}

impl EntropyBin {
    pub fn from_records(bin_id: UID, records: &[DigRecord]) -> Self {
        let mut frame_hashes = Vec::with_capacity(records.len());
        for r in records {
            frame_hashes.push(r.data_container.content_hash());
        }
        let local_entropy = compute_entropy(&frame_hashes);
        Self {
            bin_id,
            frame_hashes,
            local_entropy,
        }
    }

    pub fn bin_hash(&self) -> Hash {
        let mut buf = Vec::new();
        for h in &self.frame_hashes {
            buf.extend_from_slice(&h.0);
        }
        hash_bytes(&buf)
    }
}

fn compute_entropy(hashes: &[Hash]) -> f64 {
    if hashes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for h in hashes {
        let idx = h.0[0] as usize;
        counts[idx] += 1;
    }

    let total = hashes.len() as f64;
    let mut entropy = 0.0;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

impl EntropyHeapNode {
    pub fn from_bins(node_id: UID, children: Vec<UID>, bins: &[EntropyBin]) -> Self {
        let mut buf = Vec::new();
        for bin in bins {
            let h = bin.bin_hash();
            buf.extend_from_slice(&h.0);
        }
        let merkle_root = hash_bytes(&buf);
        Self {
            node_id,
            children,
            bin_ref: None,
            merkle_root,
        }
    }
}
