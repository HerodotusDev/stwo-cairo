use stwo_cairo_air::{
    CairoProof, VerificationOutput, get_verification_output, verify_cairo,
    PublicData, PublicSegmentRanges,
};
use core::dict::{Felt252Dict, Felt252DictTrait};

// Verifies two Cairo proofs in a single execution and returns both outputs.
// The arguments file should contain the serialized felts for the first proof
// followed by the serialized felts for the second proof.
// For example:
// * First: jq -s '.[0] + .[1]' ../stwo_cairo_prover/test_data/test_prove_verify_fibonacci_5/proof_shard_1.json ../stwo_cairo_prover/test_data/test_prove_verify_fibonacci_5/proof_shard_2.json > /tmp/two_proofs.json
// * Then: asdf exec scarb execute --package stwo_cairo_verifier --features qm31_opcode --arguments-file /tmp/two_proofs.json --output none --print-program-output
#[executable]
fn main(proof_0: CairoProof, proof_1: CairoProof) -> Array<VerificationOutput> {
    let mut outputs: Array<VerificationOutput> = array![];

    // Gather outputs first so we can use them for consistency checks.
    let out0 = get_verification_output(proof: @proof_0);
    let out1 = get_verification_output(proof: @proof_1);

    // Consistency checks across the two proofs (before consuming proofs).
    assert_state_continuity(@proof_0.claim.public_data, @proof_1.claim.public_data);
    assert_public_memory_consistency(@out0, @out1, @proof_0.claim.public_data, @proof_1.claim.public_data);
    assert_memory_relations_consistency(@proof_0.claim.public_data, @proof_1.claim.public_data);

    // Verify both proofs individually.
    verify_cairo(proof_0);
    verify_cairo(proof_1);

    // Return both outputs.
    outputs.append(out0);
    outputs.append(out1);
    outputs
}

// Ensures state continuity between shards: final state of first equals initial state of second.
fn assert_state_continuity(pd0: @PublicData, pd1: @PublicData) {
    let fin0 = pd0.final_state;
    let init1 = pd1.initial_state;
    assert!(fin0.pc == init1.pc, "state continuity violation: pc");
    assert!(fin0.ap == init1.ap, "state continuity violation: ap");
    assert!(fin0.fp == init1.fp, "state continuity violation: fp");
}

// Ensures that public memory of all shards matches the first shard.
// We compare:
// - Program hash (from outputs[0/1].program_hash)
// - Output values (constructed felts)
// - Safe call ids
// - Public segment ranges (start/stop ids and values)
fn assert_public_memory_consistency(
    out0: @VerificationOutput,
    out1: @VerificationOutput,
    pd0: @PublicData,
    pd1: @PublicData,
) {
    // Program hash equality (covers program memory section equality succinctly).
    assert!(out0.program_hash == out1.program_hash, "program hash mismatch across shards");

    // Output memory section equality.
    assert!(out0.output == out1.output, "output memory mismatch across shards");

    // Safe call ids equality.
    let [sc0_0, sc0_1] = pd0.public_memory.safe_call_ids;
    let [sc1_0, sc1_1] = pd1.public_memory.safe_call_ids;
    assert!(*sc0_0 == *sc1_0, "safe_call_ids[0] mismatch");
    assert!(*sc0_1 == *sc1_1, "safe_call_ids[1] mismatch");

    // Public segments equality.
    assert_segment_ranges_equal(pd0.public_memory.public_segments, pd1.public_memory.public_segments);
}

fn assert_segment_ranges_equal(sr0: @PublicSegmentRanges, sr1: @PublicSegmentRanges) {
    assert!(eq_segment(sr0.output, sr1.output), "segment mismatch: output");
    assert!(eq_segment(sr0.pedersen, sr1.pedersen), "segment mismatch: pedersen");
    assert!(eq_segment(sr0.range_check_128, sr1.range_check_128), "segment mismatch: rc128");
    assert!(eq_segment(sr0.ecdsa, sr1.ecdsa), "segment mismatch: ecdsa");
    assert!(eq_segment(sr0.bitwise, sr1.bitwise), "segment mismatch: bitwise");
    assert!(eq_segment(sr0.ec_op, sr1.ec_op), "segment mismatch: ec_op");
    assert!(eq_segment(sr0.keccak, sr1.keccak), "segment mismatch: keccak");
    assert!(eq_segment(sr0.poseidon, sr1.poseidon), "segment mismatch: poseidon");
    assert!(eq_segment(sr0.range_check_96, sr1.range_check_96), "segment mismatch: rc96");
    assert!(eq_segment(sr0.add_mod, sr1.add_mod), "segment mismatch: add_mod");
    assert!(eq_segment(sr0.mul_mod, sr1.mul_mod), "segment mismatch: mul_mod");
}

fn eq_segment(sr0: @stwo_cairo_air::SegmentRange, sr1: @stwo_cairo_air::SegmentRange) -> bool {
    sr0.start_ptr.id == sr1.start_ptr.id
        && sr0.start_ptr.value == sr1.start_ptr.value
        && sr0.stop_ptr.id == sr1.stop_ptr.id
        && sr0.stop_ptr.value == sr1.stop_ptr.value
}

// Checks memory relation consistency across both proofs:
// - No address changes of id (across public memory entries and private address->id relation)
// - No id changes of value (across private id->value relation)
fn assert_memory_relations_consistency(pd0: @PublicData, pd1: @PublicData) {
    let mut addr_to_id_contains: Felt252Dict<bool> = Default::default();
    let mut addr_to_id_values: Felt252Dict<u32> = Default::default();

    // Enforce consistency from the private address->id relation of both shards.
    for (address, id, _mult) in pd0.private_memory.address_to_id.span() {
        check_addr_id(ref addr_to_id_contains, ref addr_to_id_values, *address, *id);
    }
    for (address, id, _mult) in pd1.private_memory.address_to_id.span() {
        check_addr_id(ref addr_to_id_contains, ref addr_to_id_values, *address, *id);
    }

    // Check id->value consistency using the private id_to_value relation of both shards.
    let mut id_value_limb_present: Felt252Dict<bool> = Default::default();
    let mut id_value_limb_value: Felt252Dict<u32> = Default::default();


    for (id, value, _mult) in pd0.private_memory.id_to_value.span() {
        check_id_value(ref id_value_limb_present, ref id_value_limb_value, *id, *value);
    }
    for (id, value, _mult) in pd1.private_memory.id_to_value.span() {
        check_id_value(ref id_value_limb_present, ref id_value_limb_value, *id, *value);
    }
}

// Helper to insert/check address->id pairs.
fn check_addr_id(
    ref contains: Felt252Dict<bool>, ref values: Felt252Dict<u32>, address: u32, id: u32,
) {
    let key: felt252 = address.into();
    if contains.get(key) {
        let prev = values.get(key);
        assert!(prev == id, "address->id conflict");
    } else {
        values.insert(key, id);
        contains.insert(key, true);
    }
}

fn check_id_value(
    ref present: Felt252Dict<bool>,
    ref values: Felt252Dict<u32>,
    id: u32,
    value: [u32; 28],
) {
    let mut idx: u32 = 0;
    for limb in value.span() {
        let key: felt252 = id.into() * 256 + idx.into();
        if present.get(key) {
            let prev = values.get(key);
            assert!(prev == *limb, "id->value conflict");
        } else {
            values.insert(key, *limb);
            present.insert(key, true);
        }
        idx = idx + 1;
    }
}

// Compute the overall initial_pc, initial_ap, final_ap used for public memory entries.
fn overall_bounds(pd: @PublicData) -> (u32, u32, u32) {
    let overall_initial_pc: u32 = match pd.overall_initial_state {
        Option::Some(state) => (*state.pc).into(),
        Option::None => (*pd.initial_state.pc).into(),
    };
    let overall_initial_ap: u32 = match pd.overall_initial_state {
        Option::Some(state) => (*state.ap).into(),
        Option::None => (*pd.initial_state.ap).into(),
    };
    let overall_final_ap: u32 = match pd.overall_final_state {
        Option::Some(state) => (*state.ap).into(),
        Option::None => (*pd.final_state.ap).into(),
    };
    (overall_initial_pc, overall_initial_ap, overall_final_ap)
}
