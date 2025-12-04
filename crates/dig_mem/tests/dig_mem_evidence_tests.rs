use std::collections::BTreeMap;

use clock::TimeTick;
use core_types::{BoundaryTag, Hash, LogicRef, ParamBag, UID};
use dig_mem::{DigFile, DigRecord};
use tata::TataFrame;

fn make_params(pairs: &[(&str, &str)]) -> ParamBag {
    let mut map = BTreeMap::new();
    for (k, v) in pairs {
        map.insert((*k).to_string(), (*v).to_string());
    }
    ParamBag(map)
}

fn make_record(params: ParamBag) -> DigRecord {
    let tick = TimeTick {
        raw_time: 1,
        mock_time: 1.0,
    };

    let addr_heap_hash = Hash([1u8; 32]);
    let hook_hash = Hash([2u8; 32]);
    let hash_root = Hash([3u8; 32]);
    let logic_ref = LogicRef("logic".to_string());
    let wall = BoundaryTag("wall".to_string());

    let frame = TataFrame::new(
        b"payload".to_vec(),
        tick,
        hash_root,
        params.clone(),
        logic_ref,
        wall,
    );

    DigRecord {
        addr_heap_hash,
        p_container: params,
        timeclock: tick,
        data_container: frame,
        hook_hash,
    }
}

#[test]
fn dig_file_merkle_root_empty_uses_empty_hash() {
    let file_id = UID(42);
    let time_range = (0u64, 0u64);
    let dig = DigFile::from_records(file_id, time_range, Vec::new());

    // Empty dig file should have a deterministic, non-zero hash (hash of empty buffer).
    // We just assert it is stable across multiple constructions.
    let dig2 = DigFile::from_records(file_id, time_range, Vec::new());
    assert_eq!(dig.merkle_root, dig2.merkle_root);
}

#[test]
fn dig_file_merkle_root_changes_when_records_change() {
    let file_id = UID(7);
    let time_range = (10u64, 20u64);

    let params1 = make_params(&[("tenant_id", "t1"), ("event_kind", "e1")]);
    let params2 = make_params(&[("tenant_id", "t1"), ("event_kind", "e2")]);

    let rec1 = make_record(params1.clone());
    let rec2 = make_record(params1);

    let dig1 = DigFile::from_records(file_id, time_range, vec![rec1.clone(), rec2]);

    // Change one record parameter to ensure merkle root changes.
    let rec1_modified = make_record(params2);
    let dig2 = DigFile::from_records(file_id, time_range, vec![rec1_modified, rec1]);

    assert_ne!(dig1.merkle_root, dig2.merkle_root);
}
