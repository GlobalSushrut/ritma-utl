use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, Proof};
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer,
        ConstraintSystemRef,
        SynthesisError,
        Variable,
    },
};
use ark_crypto_primitives::snark::SNARK;
use core_types::UID;
use rand::thread_rng;

pub type Engine = Bn254;
pub type Fr = <Engine as Pairing>::ScalarField;

pub struct SnarkKeys {
    pub circuit_id: UID,
    pub proving_key: ProvingKey<Engine>,
    pub verifying_key: PreparedVerifyingKey<Engine>,
}

pub struct SnarkProof {
    pub circuit_id: UID,
    pub proof: Proof<Engine>,
}

#[derive(Clone)]
pub struct EqualityCircuit {
    pub a: Option<Fr>,
    pub b: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_val = self.a.ok_or(SynthesisError::AssignmentMissing)?;
        let b_val = self.b.ok_or(SynthesisError::AssignmentMissing)?;

        let a = cs.new_witness_variable(|| Ok(a_val))?;
        let b = cs.new_witness_variable(|| Ok(b_val))?;

        // Enforce a == b
        cs.enforce_constraint(lc!() + a, lc!() + Variable::One, lc!() + b)?;

        Ok(())
    }
}

pub fn setup_equality(circuit_id: UID) -> Result<SnarkKeys, SynthesisError> {
    let mut rng = thread_rng();
    // Any satisfying assignment works for setup; 3 == 3 is fine.
    let circuit = EqualityCircuit {
        a: Some(Fr::from(3u32)),
        b: Some(Fr::from(3u32)),
    };

    let (pk, vk) = Groth16::<Engine>::circuit_specific_setup(circuit, &mut rng)?;
    let pvk = Groth16::<Engine>::process_vk(&vk)?;

    Ok(SnarkKeys {
        circuit_id,
        proving_key: pk,
        verifying_key: pvk,
    })
}

pub fn prove_equality(keys: &SnarkKeys, a: Fr, b: Fr) -> Result<SnarkProof, SynthesisError> {
    let mut rng = thread_rng();
    let circuit = EqualityCircuit {
        a: Some(a),
        b: Some(b),
    };

    let proof = Groth16::<Engine>::prove(&keys.proving_key, circuit, &mut rng)?;

    Ok(SnarkProof {
        circuit_id: keys.circuit_id,
        proof,
    })
}

pub fn verify_equality(keys: &SnarkKeys, snark: &SnarkProof) -> Result<bool, SynthesisError> {
    if snark.circuit_id != keys.circuit_id {
        return Ok(false);
    }

    // Equality circuit has no public inputs.
    let public_inputs: [Fr; 0] = [];
    Groth16::<Engine>::verify_with_processed_vk(&keys.verifying_key, &public_inputs, &snark.proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_snark_roundtrip() {
        let circuit_id = UID::new();
        let keys = setup_equality(circuit_id).expect("setup failed");

        let a = Fr::from(42u32);
        let b = Fr::from(42u32);
        let proof = prove_equality(&keys, a, b).expect("prove failed");
        let ok = verify_equality(&keys, &proof).expect("verify failed");
        println!(
            "equality_snark_roundtrip: circuit_id={} a={:?} b={:?} verify_ok={}",
            circuit_id.0,
            a,
            b,
            ok
        );
        assert!(ok);
    }
}
