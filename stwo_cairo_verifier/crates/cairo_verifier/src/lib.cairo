use stwo_cairo_air::{CairoProof, VerificationOutput, get_verification_output, verify_cairo};

#[derive(Drop, Serde)]
struct CairoProofPair {
    left: CairoProof,
    right: CairoProof,
}

#[executable]
fn main(pair: CairoProofPair) -> VerificationOutput {
    let CairoProofPair { left: left_proof, right: right_proof } = pair;
    // Compute output from the left shard (matches previous behavior).
    let verification_output = get_verification_output(proof: @left_proof);

    // Capture boundary states before consuming the proofs.
    let left_final_pc: u32 = left_proof.claim.public_data.final_state.pc.into();
    let left_final_ap: u32 = left_proof.claim.public_data.final_state.ap.into();
    let left_final_fp: u32 = left_proof.claim.public_data.final_state.fp.into();

    let right_initial_pc: u32 = right_proof.claim.public_data.initial_state.pc.into();
    let right_initial_ap: u32 = right_proof.claim.public_data.initial_state.ap.into();
    let right_initial_fp: u32 = right_proof.claim.public_data.initial_state.fp.into();

    // Verify both shards.
    verify_cairo(left_proof);
    verify_cairo(right_proof);

    // State continuity: final_state(left) == initial_state(right).
    assert!(left_final_pc == right_initial_pc);
    assert!(left_final_ap == right_initial_ap);
    assert!(left_final_fp == right_initial_fp);

    verification_output
}
