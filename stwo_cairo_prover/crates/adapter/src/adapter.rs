use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use tracing::{info, span, Level};

use super::memory::{MemoryBuilder, MemoryConfig};
use super::ProverInput;
use crate::builtins::BuiltinSegments;
use crate::relocator::Relocator;
use crate::{PublicSegmentContext, StateTransitions};

pub fn adapter(runner: &CairoRunner) -> ProverInput {
    let _span = span!(Level::INFO, "adapter").entered();

    // Extract the relevant information from the Runner.
    let relocatable_trace = runner
        .get_relocatable_trace()
        .expect("Trace was not enabled in the run");

    info!("Num steps: {:?}", relocatable_trace.len());

    let mut relocatable_memory = runner.get_relocatable_memory();

    let public_memory_offsets = &runner.vm.segments.public_memory_offsets;
    let builtin_segments = runner.get_builtin_segments();
    BuiltinSegments::pad_relocatble_builtin_segments(&mut relocatable_memory, &builtin_segments);

    // Relocation part.
    let relocator = Relocator::new(&relocatable_memory);
    let relocated_memory = relocator.relocate_memory(&relocatable_memory);

    #[cfg(feature = "extract-mem-trace")]
    let relocated_memory_clone = relocated_memory.clone();

    let relocated_trace = relocator.relocate_trace(relocatable_trace);
    let builtin_segments = relocator.relocate_builtin_segments(&builtin_segments);
    info!("Builtin segments: {:?}", builtin_segments);
    let public_memory_addresses = relocator.relocate_public_addresses(public_memory_offsets);

    let memory = MemoryBuilder::from_iter(MemoryConfig::default(), relocated_memory);
    let state_transitions = StateTransitions::from_slice_parallel(&relocated_trace, &memory);
    info!(
        "Opcode counts: {:?}",
        state_transitions.casm_states_by_opcode.counts()
    );

    // TODO(spapini): Add output builtin to public memory.
    let (memory, inst_cache) = memory.build();

    // TODO(Ohad): take this from the input.
    let public_segment_context = PublicSegmentContext::bootloader_context();
    ProverInput {
        state_transitions,
        memory,
        inst_cache,
        public_memory_addresses,
        builtin_segments,
        public_segment_context,
        #[cfg(feature = "extract-mem-trace")]
        relocated_mem: relocated_memory_clone,
        #[cfg(feature = "extract-mem-trace")]
        relocated_trace: relocated_trace.clone(),
    }
}

/// Like `adapter`, but splits the relocated trace into shards of `size_of_shard` transitions
/// and returns a prover input per shard. The final state of shard n matches the initial state
/// of shard n+1 by overlapping the boundary trace entry.
pub fn adapter_shards(runner: &CairoRunner, size_of_shard: usize) -> Vec<ProverInput> {
    let _span = span!(Level::INFO, "adapter_shards").entered();

    assert!(size_of_shard > 0, "size_of_shard must be > 0");

    // Extract the relevant information from the Runner.
    let relocatable_trace = runner
        .get_relocatable_trace()
        .expect("Trace was not enabled in the run");

    info!("Num steps: {:?}", relocatable_trace.len());

    let mut relocatable_memory = runner.get_relocatable_memory();

    let public_memory_offsets = &runner.vm.segments.public_memory_offsets;
    let builtin_segments = runner.get_builtin_segments();
    BuiltinSegments::pad_relocatble_builtin_segments(&mut relocatable_memory, &builtin_segments);

    // Relocation part.
    let relocator = Relocator::new(&relocatable_memory);
    let relocated_memory = relocator.relocate_memory(&relocatable_memory);

    let relocated_trace = relocator.relocate_trace(relocatable_trace);
    let overall_initial_state = relocated_trace.first().copied().unwrap().into();
    let overall_final_state = relocated_trace.last().copied().unwrap().into();
    let builtin_segments = relocator.relocate_builtin_segments(&builtin_segments);
    info!("Builtin segments: {:?}", builtin_segments);
    let public_memory_addresses = relocator.relocate_public_addresses(public_memory_offsets);

    // Split the relocated trace into shards with overlapping boundaries so that
    // final state of shard n equals initial state of shard n+1.
    let mut res = Vec::new();
    let n = relocated_trace.len();
    if n == 0 {
        return res;
    }

    // Each shard covers up to `size_of_shard` transitions, which requires `size_of_shard + 1`
    // trace entries. The first entry of shard k is the last entry of shard k-1.
    let mut start = 0usize;
    while start + 1 < n {
        let last_idx = core::cmp::min(start + size_of_shard, n - 1);
        let shard_trace = &relocated_trace[start..last_idx + 1];

        let memory = MemoryBuilder::from_iter(MemoryConfig::default(), relocated_memory.clone());
        let mut state_transitions = StateTransitions::from_slice_parallel(shard_trace, &memory);
        // Set overall boundaries for shards to the overall program boundaries.
        state_transitions.overall_initial_state = Some(overall_initial_state);
        state_transitions.overall_final_state = Some(overall_final_state);
        info!(
            "Opcode counts (shard starting at {start}): {:?}",
            state_transitions.casm_states_by_opcode.counts()
        );

        // Build memory and instruction cache for the shard.
        let (memory, inst_cache) = memory.build();

        let public_segment_context = PublicSegmentContext::bootloader_context();

        res.push(ProverInput {
            state_transitions,
            memory,
            inst_cache,
            public_memory_addresses: public_memory_addresses.clone(),
            builtin_segments: builtin_segments.clone(),
            public_segment_context,
            #[cfg(feature = "extract-mem-trace")]
            relocated_mem: relocated_memory.clone(),
            #[cfg(feature = "extract-mem-trace")]
            relocated_trace: shard_trace.to_vec(),
        });
        start = last_idx;
    }

    res
}

#[cfg(test)]
#[cfg(feature = "slow-tests")]
mod tests {
    use std::collections::HashMap;

    use dev_utils::utils::{
        get_compiled_cairo_program_path, run_program_and_adapter, run_program_and_adapter_shards,
        ProgramType,
    };
    use serde_json::to_value;

    use crate::test_utils::{get_prover_input_path, read_json, write_json};
    use crate::ProverInput;

    fn test_compare_prover_input_to_expected_file(test_name: &str) {
        let is_fix_mode = std::env::var("FIX") == Ok("1".to_string());

        let compiled_program = get_compiled_cairo_program_path(test_name);
        let mut prover_input = run_program_and_adapter(&compiled_program, ProgramType::Json, None);
        // Instruction cache and public memory addresses are not deterministic, sort them.
        prover_input.inst_cache.sort_by_key(|(addr, _)| *addr);
        prover_input.public_memory_addresses.sort();

        let prover_input_value =
            to_value(&prover_input).expect("Unable to convert prover input to value");

        let expected_prover_input_path = get_prover_input_path(test_name);
        if is_fix_mode {
            write_json(&expected_prover_input_path, &prover_input_value);
        }
        let expected_prover_input = read_json(&expected_prover_input_path);

        assert_eq!(
            prover_input_value,
            expected_prover_input,
            "Prover input from compiled cairo program: {test_name} doesn't match the expected prover input. To update prover input file, run the test with FIX=1."
        );
    }

    #[test]
    fn test_compare_prover_input_to_expected_file_all_opcodes() {
        test_compare_prover_input_to_expected_file("test_prove_verify_all_opcode_components");
    }

    #[test]
    fn test_compare_prover_input_to_expected_file_all_builtins() {
        test_compare_prover_input_to_expected_file("test_prove_verify_all_builtins");
    }

    #[test]
    fn test_shards_continuity() {
        let compiled_program =
            get_compiled_cairo_program_path("test_prove_verify_all_opcode_components");
        let shards = run_program_and_adapter_shards(&compiled_program, ProgramType::Json, None, 10);

        assert!(shards.len() > 1, "Expected multiple shards");

        // 1) Continuity: final state of shard n == initial state of shard n+1.
        for i in 0..(shards.len() - 1) {
            let a = &shards[i].state_transitions.final_state;
            let b = &shards[i + 1].state_transitions.initial_state;
            assert_eq!(a, b, "State continuity failed at shard boundary {i}");
        }

        // 2) Overall bounds match the expected single-run prover_input.json
        let expected_prover_input_path =
            get_prover_input_path("test_prove_verify_all_opcode_components");
        let expected: ProverInput =
            serde_json::from_value(read_json(&expected_prover_input_path)).unwrap();

        // Initial and final state equality with the expected single-run input.
        assert_eq!(
            shards[0].state_transitions.initial_state, expected.state_transitions.initial_state,
            "Initial state of first shard differs from expected"
        );
        assert_eq!(
            shards.last().unwrap().state_transitions.final_state,
            expected.state_transitions.final_state,
            "Final state of last shard differs from expected"
        );

        // Aggregate opcode counts across shards (sum per opcode name).
        let mut agg_opcode_counts: HashMap<String, usize> = HashMap::new();
        for shard in &shards {
            let shard_counts = shard
                .state_transitions
                .casm_states_by_opcode
                .counts()
                .into_iter()
                .collect::<Vec<_>>();
            for (name, cnt) in shard_counts {
                *agg_opcode_counts.entry(name).or_default() += cnt;
            }
        }
        let expected_opcode_counts: HashMap<String, usize> = expected
            .state_transitions
            .casm_states_by_opcode
            .counts()
            .into_iter()
            .collect();
        assert_eq!(
            agg_opcode_counts, expected_opcode_counts,
            "Aggregated opcode counts differ from expected"
        );

        // Builtin instance counts and memory tables sizes should match per shard (they are common).
        let shard0_builtin_counts = shards[0].builtin_segments.get_counts();
        let expected_builtin_counts = expected.builtin_segments.get_counts();
        assert_eq!(
            shard0_builtin_counts, expected_builtin_counts,
            "Builtin instance counts differ from expected"
        );
        assert_eq!(
            shards[0].memory.address_to_id.len(),
            expected.memory.address_to_id.len(),
            "address_to_id size differs from expected"
        );
        assert_eq!(
            shards[0].memory.f252_values.len(),
            expected.memory.f252_values.len(),
            "id_to_big size differs from expected"
        );
        assert_eq!(
            shards[0].memory.small_values.len(),
            expected.memory.small_values.len(),
            "id_to_small size differs from expected"
        );
    }
}
