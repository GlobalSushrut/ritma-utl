use core_types::{Hash, ParamBag, ZkArcCommitment, UID};
use serde::{Deserialize, Serialize};

pub type RootParams = ParamBag;
pub type TransitionHookId = UID;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateOfTruthRoot {
    pub root_id: UID,
    pub root_hash: Hash,
    pub root_params: RootParams,
    pub tx_hook: TransitionHookId,
    pub zk_arc_commit: ZkArcCommitment,
}

impl StateOfTruthRoot {
    pub fn new(
        root_id: UID,
        root_hash: Hash,
        root_params: RootParams,
        tx_hook: TransitionHookId,
        zk_arc_commit: ZkArcCommitment,
    ) -> Self {
        Self {
            root_id,
            root_hash,
            root_params,
            tx_hook,
            zk_arc_commit,
        }
    }
}
