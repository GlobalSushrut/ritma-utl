use clock::TimeTick;
use core_types::{hash_bytes, BoundaryTag, Hash, LogicRef, ParamBag};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TataFrame<D> {
    pub data: D,
    pub timeclock: TimeTick,
    pub hash_root: Hash,
    pub params: ParamBag,
    pub logic_ref: LogicRef,
    pub wall: BoundaryTag,
}

impl<D> TataFrame<D> {
    pub fn new(
        data: D,
        timeclock: TimeTick,
        hash_root: Hash,
        params: ParamBag,
        logic_ref: LogicRef,
        wall: BoundaryTag,
    ) -> Self {
        Self {
            data,
            timeclock,
            hash_root,
            params,
            logic_ref,
            wall,
        }
    }
}

impl<D: AsRef<[u8]>> TataFrame<D> {
    pub fn content_hash(&self) -> Hash {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(self.data.as_ref());
        buffer.extend_from_slice(&self.timeclock.raw_time.to_le_bytes());
        buffer.extend_from_slice(&self.timeclock.mock_time.to_le_bytes());
        hash_bytes(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_differs_for_different_data() {
        let tick = TimeTick {
            raw_time: 1,
            mock_time: 1.0,
        };

        let params = ParamBag::default();
        let logic_ref = LogicRef("logic".to_string());
        let wall = BoundaryTag("wall".to_string());
        let hash_root = Hash([0u8; 32]);

        let f1 = TataFrame::new(
            b"a".to_vec(),
            tick,
            hash_root.clone(),
            params.clone(),
            logic_ref.clone(),
            wall.clone(),
        );

        let f2 = TataFrame::new(b"b".to_vec(), tick, hash_root, params, logic_ref, wall);
        let h1 = f1.content_hash();
        let h2 = f2.content_hash();
        println!("tata content_hash: h1={:?} h2={:?}", h1, h2);
        assert_ne!(h1, h2);
    }
}
