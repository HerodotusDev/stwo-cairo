use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use cairo_air::air::{CairoClaim, CairoComponents, CairoInteractionElements};
use cairo_air::preprocessed::PreProcessedTrace;
use cairo_air::verifier::{verify_cairo, verify_cairo_with_queries};
use cairo_air::{CairoProof, PreProcessedTraceVariant};
use cairo_lang_runner::Arg;
use cairo_prove::args::{Cli, Commands, ProgramArguments};
use cairo_prove::execute::execute;
use cairo_prove::prove::{prove, prover_input_from_runner};
use clap::Parser;
use log::{error, info};
use serde_json::json;
use stwo_cairo_prover::stwo_prover::constraint_framework::PREPROCESSED_TRACE_IDX;
use stwo_cairo_prover::stwo_prover::core::air::Components as AirComponents;
use stwo_cairo_prover::stwo_prover::core::circle::CirclePoint;
use stwo_cairo_prover::stwo_prover::core::fields::qm31::SecureField;
use stwo_cairo_prover::stwo_prover::core::fields::secure_column::SECURE_EXTENSION_DEGREE;
use stwo_cairo_prover::stwo_prover::core::fri::FriConfig;
use stwo_cairo_prover::stwo_prover::core::pcs::PcsConfig;
use stwo_cairo_prover::stwo_prover::core::queries::{Queries, QueriesWithBranching};
use stwo_cairo_prover::stwo_prover::core::vcs::blake2_merkle::{
    Blake2sMerkleChannel, Blake2sMerkleHasher,
};

fn execute_and_prove(
    target_path: &str,
    args: Vec<Arg>,
    pcs_config: PcsConfig,
) -> CairoProof<Blake2sMerkleHasher> {
    // Execute.
    let executable = serde_json::from_reader(std::fs::File::open(target_path).unwrap())
        .expect("Failed to read executable");
    let runner = execute(executable, args);

    // Prove.
    let prover_input = prover_input_from_runner(&runner);
    prove(prover_input, pcs_config)
}

const COMPONENT_CONFIG_LEN: usize = 61;

fn pcs_config_with_queries(n_queries: usize) -> PcsConfig {
    PcsConfig {
        pow_bits: 26,
        fri_config: FriConfig {
            log_last_layer_degree_bound: 0,
            log_blowup_factor: 1,
            n_queries,
        },
    }
}

fn secure_pcs_config() -> PcsConfig {
    pcs_config_with_queries(70)
}

fn build_component_config(claim: &CairoClaim) -> [bool; COMPONENT_CONFIG_LEN] {
    let mut config = [false; COMPONENT_CONFIG_LEN];
    config[20] = true;
    for idx in 40..COMPONENT_CONFIG_LEN {
        config[idx] = true;
    }

    macro_rules! mark_if_non_empty {
        ($index:expr, $collection:expr) => {
            if !$collection.is_empty() {
                config[$index] = true;
            }
        };
    }

    let opcodes = &claim.opcodes;
    mark_if_non_empty!(0, opcodes.add);
    mark_if_non_empty!(1, opcodes.add_small);
    mark_if_non_empty!(2, opcodes.add_ap);
    mark_if_non_empty!(3, opcodes.assert_eq);
    mark_if_non_empty!(4, opcodes.assert_eq_imm);
    mark_if_non_empty!(5, opcodes.assert_eq_double_deref);
    mark_if_non_empty!(6, opcodes.blake);
    mark_if_non_empty!(7, opcodes.call);
    mark_if_non_empty!(8, opcodes.call_rel_imm);
    mark_if_non_empty!(9, opcodes.generic);
    mark_if_non_empty!(10, opcodes.jnz);
    mark_if_non_empty!(11, opcodes.jnz_taken);
    mark_if_non_empty!(12, opcodes.jump);
    mark_if_non_empty!(13, opcodes.jump_double_deref);
    mark_if_non_empty!(14, opcodes.jump_rel);
    mark_if_non_empty!(15, opcodes.jump_rel_imm);
    mark_if_non_empty!(16, opcodes.mul);
    mark_if_non_empty!(17, opcodes.mul_small);
    mark_if_non_empty!(18, opcodes.qm31);
    mark_if_non_empty!(19, opcodes.ret);

    if claim.blake_context.claim.is_some() {
        config[21] = true;
        config[22] = true;
        config[23] = true;
        config[24] = true;
        config[25] = true;
    }

    let builtins = &claim.builtins;
    if builtins.add_mod_builtin.is_some() {
        config[26] = true;
    }
    if builtins.bitwise_builtin.is_some() {
        config[27] = true;
    }
    if builtins.mul_mod_builtin.is_some() {
        config[28] = true;
    }
    if builtins.pedersen_builtin.is_some() {
        config[29] = true;
    }
    if builtins.poseidon_builtin.is_some() {
        config[30] = true;
    }
    if builtins.range_check_96_builtin.is_some() {
        config[31] = true;
    }
    if builtins.range_check_128_builtin.is_some() {
        config[32] = true;
    }

    if claim.pedersen_context.claim.is_some() {
        config[33] = true;
        config[34] = true;
    }

    if claim.poseidon_context.claim.is_some() {
        config[35] = true;
        config[36] = true;
        config[37] = true;
        config[38] = true;
        config[39] = true;
    }

    config
}

fn build_preprocessed_config(components: &AirComponents) -> Vec<bool> {
    let mask_points = components.mask_points(CirclePoint::<SecureField>::zero());
    mask_points[PREPROCESSED_TRACE_IDX]
        .iter()
        .map(|points| !points.is_empty())
        .collect()
}

fn build_column_log_sizes(
    claim: &CairoClaim,
    preprocessed_log_sizes: &[u32],
    components: &AirComponents,
) -> Vec<Vec<u64>> {
    let mut log_sizes = claim.log_sizes();
    log_sizes[PREPROCESSED_TRACE_IDX] = preprocessed_log_sizes.to_vec();
    let mut as_vec = log_sizes
        .0
        .into_iter()
        .map(|tree| tree.into_iter().map(|log_size| log_size as u64).collect())
        .collect::<Vec<_>>();
    let composition_log_degree_bound = components.composition_log_degree_bound() as u64;
    as_vec.push(vec![composition_log_degree_bound; SECURE_EXTENSION_DEGREE]);
    as_vec
}

fn compute_shape_data(
    proof: &CairoProof<Blake2sMerkleHasher>,
    preprocessed_trace: &PreProcessedTrace,
) -> (Vec<Vec<u64>>, Vec<bool>, [bool; COMPONENT_CONFIG_LEN]) {
    let preprocessed_log_sizes = preprocessed_trace.log_sizes();
    let preprocessed_column_ids = preprocessed_trace.ids();
    let interaction_elements = CairoInteractionElements::dummy();
    let cairo_components = CairoComponents::new(
        &proof.claim,
        &interaction_elements,
        &proof.interaction_claim,
        &preprocessed_column_ids,
    );
    let component_refs = cairo_components.components();
    let air_components = AirComponents {
        components: component_refs.clone(),
        n_preprocessed_columns: preprocessed_log_sizes.len(),
    };
    let column_log_sizes =
        build_column_log_sizes(&proof.claim, &preprocessed_log_sizes, &air_components);
    let preprocessed_config = build_preprocessed_config(&air_components);
    let component_config = build_component_config(&proof.claim);
    (column_log_sizes, preprocessed_config, component_config)
}

fn build_deduped_queries_shape(mut queries: Queries) -> Vec<u64> {
    let mut shape = vec![0u64; 32];
    loop {
        let log_size = queries.log_domain_size as usize;
        if log_size < shape.len() {
            shape[log_size] = queries.positions.len() as u64;
        }
        if log_size == 0 {
            break;
        }
        queries = queries.fold(1);
    }
    shape
}

fn build_queries_by_log_size(mut queries: Queries) -> Vec<Vec<usize>> {
    let mut per_log = vec![Vec::new(); queries.log_domain_size as usize + 1];
    loop {
        let log_size = queries.log_domain_size as usize;
        per_log[log_size] = queries.positions.clone();
        if log_size == 0 {
            break;
        }
        queries = queries.fold(1);
    }
    per_log
}

fn build_column_bounds(column_log_sizes: &[Vec<u64>]) -> Vec<usize> {
    let mut set = BTreeSet::new();
    for tree in column_log_sizes {
        for &log_size in tree {
            set.insert((log_size + 1) as usize);
        }
    }
    let mut bounds: Vec<usize> = set.into_iter().collect();
    bounds.sort_by(|a, b| b.cmp(a));
    bounds
}

fn build_positions_with_pairs(
    base_positions: &[Vec<usize>],
    paired_layers: &BTreeSet<usize>,
) -> Vec<Vec<usize>> {
    let mut positions = vec![Vec::new(); base_positions.len()];
    for log_size in 0..base_positions.len() {
        if paired_layers.contains(&log_size) {
            if log_size == 0 {
                positions[log_size] = base_positions[log_size].clone();
            } else {
                let parents = &base_positions[log_size - 1];
                let mut paired = Vec::with_capacity(parents.len() * 2);
                for &parent in parents {
                    paired.push(parent * 2);
                    paired.push(parent * 2 + 1);
                }
                positions[log_size] = paired;
            }
        } else {
            positions[log_size] = base_positions[log_size].clone();
        }
    }
    positions
}

fn build_branching(positions_by_log_size: &[Vec<usize>]) -> Vec<Vec<u8>> {
    if positions_by_log_size.is_empty() {
        return Vec::new();
    }
    let mut branching = vec![Vec::new(); positions_by_log_size.len()];
    for log_size in 0..positions_by_log_size.len() - 1 {
        let children = &positions_by_log_size[log_size + 1];
        for &parent in &positions_by_log_size[log_size] {
            let left = parent * 2;
            let right = left + 1;
            let left_present = children.binary_search(&left).is_ok();
            let right_present = children.binary_search(&right).is_ok();
            let code = (left_present as u8) | ((right_present as u8) << 1);
            branching[log_size].push(code);
        }
    }
    branching
}

fn build_fri_inner_layer_branching(
    base_positions: &[Vec<usize>],
    column_bounds: &[usize],
    n_inner_layers: usize,
) -> Vec<Vec<Vec<u8>>> {
    if column_bounds.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(n_inner_layers);
    let mut log_size = column_bounds[0].saturating_sub(2);
    for _ in 0..n_inner_layers {
        let paired_layer = log_size + 1;
        let mut paired_layers = BTreeSet::new();
        paired_layers.insert(paired_layer);
        let positions = build_positions_with_pairs(base_positions, &paired_layers);
        result.push(build_branching(&positions));
        if log_size == 0 {
            break;
        }
        log_size -= 1;
    }
    result
}

fn handle_prove(target: &Path, proof: &Path, args: ProgramArguments) {
    info!("Generating proof for target: {:?}", target);
    let start = Instant::now();
    let cairo_proof = execute_and_prove(
        target.to_str().unwrap(),
        args.read_arguments(),
        secure_pcs_config(),
    );
    let elapsed = start.elapsed();

    // Serialize proof to file.
    let proof_json = serde_json::to_string(&cairo_proof).unwrap();
    std::fs::write(proof.to_str().unwrap(), proof_json).unwrap();
    info!("Proof saved to: {:?}", proof);
    info!("Proof generation completed in {:.2?}", elapsed);
}

fn handle_verify(proof: &Path, with_pedersen: bool) {
    info!("Verifying proof from: {:?}", proof);
    let cairo_proof =
        serde_json::from_reader(std::fs::File::open(proof.to_str().unwrap()).unwrap()).unwrap();
    let preprocessed_trace = match with_pedersen {
        true => PreProcessedTraceVariant::Canonical,
        false => PreProcessedTraceVariant::CanonicalWithoutPedersen,
    };
    let result =
        verify_cairo::<Blake2sMerkleChannel>(cairo_proof, secure_pcs_config(), preprocessed_trace);
    match result {
        Ok(_) => info!("Verification successful"),
        Err(e) => error!("Verification failed: {:?}", e),
    }
}

fn handle_generate_circuit_data(proof_path: &Path, n_queries: usize) {
    assert!(n_queries > 0, "number of queries must be positive");
    info!(
        "Verifying proof and generating circuit data from: {:?}",
        proof_path
    );
    let file = std::fs::File::open(proof_path.to_str().unwrap()).unwrap();
    let cairo_proof: CairoProof<Blake2sMerkleHasher> =
        serde_json::from_reader(file).expect("Failed to deserialize proof");
    let preprocessed_trace_variant = PreProcessedTraceVariant::Canonical;
    let preprocessed_trace = preprocessed_trace_variant.to_preprocessed_trace();
    let (column_log_sizes, preprocessed_config, component_config) =
        compute_shape_data(&cairo_proof, &preprocessed_trace);
    let inner_layers_len = cairo_proof.stark_proof.fri_proof.inner_layers.len();

    let pcs_config = pcs_config_with_queries(n_queries);
    let queries_with_branching = match verify_cairo_with_queries::<Blake2sMerkleChannel>(
        cairo_proof,
        pcs_config,
        preprocessed_trace_variant,
    ) {
        Ok(queries) => queries,
        Err(err) => {
            error!("Verification failed: {:?}", err);
            return;
        }
    };
    let QueriesWithBranching { queries, branching } = queries_with_branching;
    let mut queries_branching = branching;
    let deduped_shape = build_deduped_queries_shape(queries.clone());
    let base_queries = build_queries_by_log_size(queries);
    let column_bounds = build_column_bounds(&column_log_sizes);
    let paired_layers: BTreeSet<usize> = column_bounds.iter().copied().collect();
    let first_layer_positions = build_positions_with_pairs(&base_queries, &paired_layers);
    let fri_first_layer_branching = build_branching(&first_layer_positions);
    let fri_inner_layer_branching =
        build_fri_inner_layer_branching(&base_queries, &column_bounds, inner_layers_len);
    if queries_branching.len() < deduped_shape.len() {
        queries_branching.resize(deduped_shape.len(), Vec::new());
    }

    let shape_file_name = proof_path
        .file_stem()
        .map(|stem| {
            let mut name = stem.to_os_string();
            name.push("_shape.json");
            name
        })
        .expect("proof path must have a valid file name");
    let shape_path = proof_path.with_file_name(shape_file_name);
    let payload = json!({
        "columnLogSizes": column_log_sizes,
        "dedupedQueriesShape": deduped_shape,
        "queriesBranching": queries_branching,
        "friFirstLayerBranching": fri_first_layer_branching,
        "friInnerLayerBranching": fri_inner_layer_branching,
        "componentConfig": component_config.to_vec(),
        "preprocessedConfig": preprocessed_config,
    });
    std::fs::write(&shape_path, serde_json::to_string_pretty(&payload).unwrap()).unwrap();
    info!("Circuit data saved to {:?}", shape_path);
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Prove {
            target,
            proof,
            program_arguments,
        } => {
            handle_prove(&target, &proof, program_arguments);
        }
        Commands::Verify {
            proof,
            with_pedersen,
        } => {
            handle_verify(&proof, with_pedersen);
        }
        Commands::CircuitData { path, queries } => {
            handle_generate_circuit_data(&path, queries);
        }
    }
}

#[cfg(test)]
mod tests {
    use cairo_vm::Felt252;
    use num_bigint::BigInt;

    use super::*;

    #[test]
    fn test_e2e() {
        let target_path = "./example/target/release/example.executable.json";
        let args = vec![Arg::Value(Felt252::from(BigInt::from(100)))];
        let proof = execute_and_prove(target_path, args, PcsConfig::default());
        let pcs_config = PcsConfig::default();
        let preprocessed_trace = PreProcessedTraceVariant::CanonicalWithoutPedersen;
        let result = verify_cairo::<Blake2sMerkleChannel>(proof, pcs_config, preprocessed_trace);
        assert!(result.is_ok());
    }
}
