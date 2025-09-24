use itertools::Itertools;
use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::air::Components as CoreComponents;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::verifier::{VerificationError, PREPROCESSED_TRACE_IDX};
use stwo::prover::backend::cpu::CpuCirclePoly;

use crate::air::{lookup_sum, CairoComponents, CairoInteractionElements, CairoProof};
use crate::verifier::{verify_claim, CairoVerificationError, INTERACTION_POW_BITS};
use crate::PreProcessedTraceVariant;

/// Samples the public Address->Id polynomials at the component mask points.
/// Returns (base_samples, interaction_samples), each as Vec<column> where
/// each inner Vec is the evaluations at mask points for that polynomial.
fn sample_address_to_id_public_polys(
    claim: &crate::air::CairoClaim,
    components: &CairoComponents,
    oods_point: CirclePoint<SecureField>,
) -> (Vec<Vec<SecureField>>, Vec<Vec<SecureField>>) {
    // Collect per-component mask points for Address->Id.
    let mask = components
        .memory_address_to_id
        .mask_points(oods_point)
        .to_vec();

    // Build polynomials directly from public_data coefficients (no interpolation).
    let base_poly_coeffs = &claim
        .public_data
        .memory_poly_coeffs
        .memory_address_to_id_base_poly_coeffs;
    let interaction_poly_coeffs = &claim
        .public_data
        .memory_poly_coeffs
        .memory_address_to_id_interaction_poly_coeffs;

    let base_polys: Vec<CpuCirclePoly> = base_poly_coeffs
        .iter()
        .cloned()
        .map(CpuCirclePoly::new)
        .collect();
    let interaction_polys: Vec<CpuCirclePoly> = interaction_poly_coeffs
        .iter()
        .cloned()
        .map(CpuCirclePoly::new)
        .collect();

    // Sample them at the component mask points (tree 1 is base, tree 2 is interaction).
    let base_samples = base_polys
        .iter()
        .zip(mask[1].clone())
        .map(|(poly, points)| {
            points
                .iter()
                .map(|&point| poly.eval_at_point(point))
                .collect_vec()
        })
        .collect_vec();
    let interaction_samples = interaction_polys
        .iter()
        .zip(mask[2].clone())
        .map(|(poly, points)| {
            points
                .iter()
                .map(|&point| poly.eval_at_point(point))
                .collect_vec()
        })
        .collect_vec();

    (base_samples, interaction_samples)
}

/// Verifies a Cairo proof by reproducing the full verification protocol without
/// calling the stwo `verify` helper (unfolded for aggregation/experimentation).
pub fn aggregate_cairo<MC: MerkleChannel>(
    CairoProof {
        claim,
        interaction_pow,
        interaction_claim,
        stark_proof,
    }: CairoProof<MC::H>,
    preprocessed_trace: PreProcessedTraceVariant,
) -> Result<(), CairoVerificationError> {
    // Auxiliary verifications (same as verify_cairo).
    verify_claim(&claim);

    let channel = &mut MC::C::default();
    let pcs_config = stark_proof.config;
    pcs_config.mix_into(channel);
    let commitment_scheme_verifier = &mut CommitmentSchemeVerifier::<MC>::new(pcs_config);

    // Trace structure (trees and column log-sizes).
    let mut log_sizes = claim.log_sizes();
    log_sizes[PREPROCESSED_TRACE_IDX] = preprocessed_trace.to_preprocessed_trace().log_sizes();

    // Commit preprocessed and base traces.
    commitment_scheme_verifier.commit(stark_proof.commitments[0], &log_sizes[0], channel);
    claim.mix_into(channel);
    commitment_scheme_verifier.commit(stark_proof.commitments[1], &log_sizes[1], channel);

    // PoW for interaction.
    channel.mix_u64(interaction_pow);
    if channel.trailing_zeros() < INTERACTION_POW_BITS {
        return Err(CairoVerificationError::ProofOfWork);
    }

    // Interaction elements and logup sum check.
    let interaction_elements = CairoInteractionElements::draw(channel);
    if lookup_sum(&claim, &interaction_elements, &interaction_claim) != SecureField::zero() {
        return Err(CairoVerificationError::InvalidLogupSum);
    }
    interaction_claim.mix_into(channel);
    commitment_scheme_verifier.commit(stark_proof.commitments[2], &log_sizes[2], channel);

    // Build components for composition polynomial masking/evaluation.
    let component_generator = CairoComponents::new(
        &claim,
        &interaction_elements,
        &interaction_claim,
        &preprocessed_trace.to_preprocessed_trace().ids(),
    );
    let components_vec = component_generator.components();

    // Construct stwo core Components with the number of preprocessed columns.
    let n_preprocessed_columns = log_sizes[PREPROCESSED_TRACE_IDX].len();
    let core_components = CoreComponents {
        components: components_vec,
        n_preprocessed_columns,
    };

    // Unfolded verifier steps (equivalent to stwo::core::verifier::verify).
    let random_coeff = channel.draw_secure_felt();

    // Read composition polynomial commitment (last commitment).
    commitment_scheme_verifier.commit(
        *stark_proof.commitments.last().unwrap(),
        &[core_components.composition_log_degree_bound(); SECURE_EXTENSION_DEGREE],
        channel,
    );

    // Draw OODS point and compute mask points.
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    let mut sample_points = core_components.mask_points(oods_point);
    // Add composition polynomial mask points (one per coordinate).
    sample_points.push(vec![vec![oods_point]; SECURE_EXTENSION_DEGREE]);

    // Address-to-ID: sample public polynomials on the component mask points (base + interaction).
    let (_base_samples, _interaction_samples) =
        sample_address_to_id_public_polys(&claim, &component_generator, oods_point);

    // Verify DEEP-ALI: composition OODS value must match components' computed value.
    // Extract composition OODS evaluation from the sampled_values structure.
    let composition_mask =
        stark_proof
            .sampled_values
            .last()
            .ok_or(CairoVerificationError::Stark(
                VerificationError::InvalidStructure(
                    "Missing composition mask in sampled_values".into(),
                ),
            ))?;
    let coordinate_evals = composition_mask
        .iter()
        .map(|columns| {
            if columns.len() == 1 {
                Some(columns[0])
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(CairoVerificationError::Stark(
            VerificationError::InvalidStructure("Unexpected composition mask structure".into()),
        ))?;
    let coordinate_evals: [SecureField; SECURE_EXTENSION_DEGREE] =
        coordinate_evals.try_into().map_err(|_| {
            CairoVerificationError::Stark(VerificationError::InvalidStructure(
                "Unexpected number of composition coordinates".into(),
            ))
        })?;
    let composition_oods_eval = SecureField::from_partial_evals(coordinate_evals);
    if composition_oods_eval
        != core_components.eval_composition_polynomial_at_point(
            oods_point,
            &stark_proof.sampled_values,
            random_coeff,
        )
    {
        return Err(CairoVerificationError::Stark(
            VerificationError::OodsNotMatching,
        ));
    }

    // Verify commitment scheme values, FRI, and Merkle decommitments.
    commitment_scheme_verifier
        .verify_values(sample_points, stark_proof.0, channel)
        .map_err(CairoVerificationError::Stark)
}

#[cfg(test)]
mod aggregate_tests {
    use super::*;
    use crate::utils::{deserialize_proof_from_file, ProofFormat};
    use std::path::PathBuf;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;

    #[test]
    #[ignore]
    fn test_aggregate_cairo_on_fixture() {
        let mut proof_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // Move from crates/cairo-air one level up to stwo_cairo_prover then into test_data
        proof_path.push("../../test_data/test_prove_verify_all_opcode_components/proof.json");
        let cairo_proof =
            deserialize_proof_from_file::<<Blake2sMerkleChannel as MerkleChannel>::H>(
                &proof_path,
                ProofFormat::CairoSerde,
            )
            .expect("failed to load proof.json");

        let preprocessed_trace = PreProcessedTraceVariant::CanonicalWithoutPedersen;
        aggregate_cairo::<Blake2sMerkleChannel>(cairo_proof, preprocessed_trace)
            .expect("aggregate_cairo verification failed");
    }
}
