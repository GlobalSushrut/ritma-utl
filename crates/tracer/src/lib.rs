use core_types::{LogicDescriptor, UID};
use tata::TataFrame;

#[derive(Clone, Debug)]
pub struct BridgeInfo {
    pub trusted: bool,
    pub location: String,
}

#[derive(Clone, Debug)]
pub struct UnknownLogicCapsule {
    pub capsule_id: UID,
    pub input_snapshot: TataFrame<Vec<u8>>,
    pub logic_descriptor: LogicDescriptor,
    pub bridge: BridgeInfo,
    pub output_snapshot: TataFrame<Vec<u8>>,
    pub output_address: String,
}

impl UnknownLogicCapsule {
    pub fn new(
        capsule_id: UID,
        input_snapshot: TataFrame<Vec<u8>>,
        logic_descriptor: LogicDescriptor,
        bridge: BridgeInfo,
        output_snapshot: TataFrame<Vec<u8>>,
        output_address: String,
    ) -> Self {
        Self {
            capsule_id,
            input_snapshot,
            logic_descriptor,
            bridge,
            output_snapshot,
            output_address,
        }
    }
}
