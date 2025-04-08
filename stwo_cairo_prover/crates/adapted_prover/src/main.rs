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
    let prover_input: ProverInput = ProverInput {
        state_transitions: StateTransitions {
            initial_state: CasmState {
                pc: M31(1),
                ap: M31(12),
                fp: M31(12),
            },
            final_state: CasmState {
                pc: M31(9),
                ap: M31(17),
                fp: M31(12),
            },
            casm_states_by_opcode: CasmStatesByOpcode {
                add_opcode_small: vec![CasmState {
                    pc: M31(8),
                    ap: M31(16),
                    fp: M31(12),
                }],
                assert_eq_opcode_imm: vec![
                    CasmState {
                        pc: M31(1),
                        ap: M31(12),
                        fp: M31(12),
                    },
                    CasmState {
                        pc: M31(3),
                        ap: M31(13),
                        fp: M31(12),
                    },
                    CasmState {
                        pc: M31(5),
                        ap: M31(14),
                        fp: M31(12),
                    },
                ],
                mul_opcode_small: vec![CasmState {
                    pc: M31(7),
                    ap: M31(15),
                    fp: M31(12),
                }],
                ..Default::default()
            },
        },
        instruction_by_pc: [
            (M31(5), 5189976364521848832),
            (M31(8), 5201798304953565184),
            (M31(7), 5210805504208437248),
            (M31(1), 5189976364521848832),
            (M31(3), 5189976364521848832),
        ]
        .into_iter()
        .collect(),
        memory: Memory {
            config: MemoryConfig {
                small_max: 4722366482869645213695,
            },
            address_to_id: vec![
                EncodedMemoryValueId(1073741823),
                EncodedMemoryValueId(0),
                EncodedMemoryValueId(1),
                EncodedMemoryValueId(0),
                EncodedMemoryValueId(2),
                EncodedMemoryValueId(0),
                EncodedMemoryValueId(3),
                EncodedMemoryValueId(4),
                EncodedMemoryValueId(5),
                EncodedMemoryValueId(6),
                EncodedMemoryValueId(7),
                EncodedMemoryValueId(7),
                EncodedMemoryValueId(1),
                EncodedMemoryValueId(2),
                EncodedMemoryValueId(3),
                EncodedMemoryValueId(8),
                EncodedMemoryValueId(9),
            ],
            inst_cache: [
                (1, 5189976364521848832),
                (5, 5189976364521848832),
                (7, 5210805504208437248),
                (3, 5189976364521848832),
                (8, 5201798304953565184),
            ]
            .into_iter()
            .collect(),
            f252_values: vec![],
            small_values: vec![
                5189976364521848832,
                1,
                2,
                3,
                5210805504208437248,
                5201798304953565184,
                2345108766317314046,
                17,
                6,
                7,
            ],
        },
        public_memory_addresses: vec![],
        builtins_segments: BuiltinSegments::default(),
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
