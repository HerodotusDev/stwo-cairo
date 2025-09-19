use stwo_cairo_air::{CairoProof, VerificationOutput, get_verification_output, verify_cairo};

// Verifies two Cairo proofs in a single execution and returns both outputs.
// The arguments file should contain the serialized felts for the first proof
// followed by the serialized felts for the second proof.
// For example:
// * First: jq -s '.[0] + .[1]' ../stwo_cairo_prover/test_data/test_prove_verify_fibonacci_5/proof_shard_1.json ../stwo_cairo_prover/test_data/test_prove_verify_fibonacci_5/proof_shard_2.json > /tmp/two_proofs.json
// * Then: asdf exec scarb execute --package stwo_cairo_verifier --features qm31_opcode --arguments-file /tmp/two_proofs.json --output none --print-program-output
#[executable]
fn main(proof_0: CairoProof, proof_1: CairoProof) -> Array<VerificationOutput> {
    let mut outputs: Array<VerificationOutput> = array![];

    // First proof
    let output_0 = get_verification_output(proof: @proof_0);
    verify_cairo(proof_0);
    outputs.append(output_0);

    // Second proof
    let output_1 = get_verification_output(proof: @proof_1);
    verify_cairo(proof_1);
    outputs.append(output_1);

    outputs
}
