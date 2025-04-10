use std::process::ExitCode;

use cairo_air::verifier::{verify_cairo, CairoVerificationError};
use stwo_cairo_adapter::builtins::BuiltinSegments;
use stwo_cairo_adapter::memory::{EncodedMemoryValueId, Memory, MemoryConfig};
use stwo_cairo_adapter::opcodes::{CasmStatesByOpcode, StateTransitions};
use stwo_cairo_adapter::vm_import::VmImportError;
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_prover::prover::{default_prod_prover_parameters, prove_cairo, ProverParameters};
use stwo_cairo_prover::witness::prelude::{CasmState, M31};
use stwo_cairo_utils::binary_utils::run_binary;
use stwo_cairo_utils::file_utils::IoErrorWithPath;
use stwo_prover::core::prover::ProvingError;
use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("Invalid arguments: {0}")]
    Cli(#[from] clap::Error),
    #[error("IO failed: {0}")]
    IO(#[from] std::io::Error),
    #[error("Proving failed: {0}")]
    Proving(#[from] ProvingError),
    #[error("Serialization failed: {0}")]
    Serde(#[from] serde_json::error::Error),
    #[error("Verification failed: {0}")]
    Verification(#[from] CairoVerificationError),
    #[error("VM import failed: {0}")]
    VmImport(#[from] VmImportError),
    #[error("File IO failed: {0}")]
    File(#[from] IoErrorWithPath),
}

fn main() -> ExitCode {
    run_binary(run, "adapted_stwo")
}

fn run(_args: impl Iterator<Item = String>) -> Result<(), Error> {
    let prover_input = ProverInput {
        state_transitions: StateTransitions {
            initial_state: CasmState {
                pc: M31(9),
                ap: M31(18),
                fp: M31(13),
            },
            final_state: CasmState {
                pc: M31(10),
                ap: M31(19),
                fp: M31(13),
            },
            casm_states_by_opcode: CasmStatesByOpcode {
                mul_opcode_small: vec![CasmState {
                    pc: M31(9),
                    ap: M31(18),
                    fp: M31(13),
                }],
                ..Default::default()
            },
        },
        instruction_by_pc: [(M31(9), 5210805504208502784)].into_iter().collect(),
        memory: Memory {
            config: MemoryConfig {
                small_max: 4722366482869645213695,
            },
            address_to_id: [
                (0, EncodedMemoryValueId(1073741823)),
                (1, EncodedMemoryValueId(0)),
                (2, EncodedMemoryValueId(0)),
                (3, EncodedMemoryValueId(0)),
                (4, EncodedMemoryValueId(0)),
                (5, EncodedMemoryValueId(0)),
                (6, EncodedMemoryValueId(0)),
                (7, EncodedMemoryValueId(0)),
                (8, EncodedMemoryValueId(0)),
                (9, EncodedMemoryValueId(6)),
                (10, EncodedMemoryValueId(7)),
                (11, EncodedMemoryValueId(0)),
                (12, EncodedMemoryValueId(0)),
                (13, EncodedMemoryValueId(0)),
                (14, EncodedMemoryValueId(0)),
                (15, EncodedMemoryValueId(0)),
                (16, EncodedMemoryValueId(0)),
                (17, EncodedMemoryValueId(10)),
                (18, EncodedMemoryValueId(11)),
            ]
            .into_iter()
            .collect(),
            inst_cache: [(9, 5210805504208502784)].into_iter().collect(),
            f252_values: vec![],
            small_values: vec![
                0,
                0,
                0,
                0,
                0,
                0,
                5210805504208502784,
                2345108766317314046,
                0,
                0,
                7,
                49,
            ],
        },
        public_memory_addresses: vec![],
        builtins_segments: BuiltinSegments {
            add_mod: None,
            bitwise: None,
            ec_op: None,
            ecdsa: None,
            keccak: None,
            mul_mod: None,
            pedersen: None,
            poseidon: None,
            range_check_bits_96: None,
            range_check_bits_128: None,
        },
    };

    let ProverParameters {
        pcs_config,
        preprocessed_trace,
        ..
    } = default_prod_prover_parameters();

    let proof = prove_cairo::<Blake2sMerkleChannel>(prover_input, pcs_config, preprocessed_trace)?;
    log::info!("Proof proven successfully");

    verify_cairo::<Blake2sMerkleChannel>(proof, pcs_config, preprocessed_trace)?;
    log::info!("Proof verified successfully");

    Ok(())
}
