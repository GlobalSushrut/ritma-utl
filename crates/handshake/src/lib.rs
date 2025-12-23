use clock::TimeTick;
use core_types::{Sig, UID};
use sot_root::StateOfTruthRoot;

#[derive(Clone, Debug)]
pub struct TransitionHandshake {
    pub entity_id: UID,
    pub sot_root: StateOfTruthRoot,
    pub clock_tick: TimeTick,
    pub signature: Sig,
}
