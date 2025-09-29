use components::memory_address_to_id::InteractionClaimImpl as MemoryAddressToIdInteractionClaimImpl;
use components::memory_id_to_big::{
    InteractionClaimImpl as MemoryIdToBigInteractionClaimImpl, LARGE_MEMORY_VALUE_ID_BASE,
};
use components::triple_xor_32::InteractionClaimImpl as TripleXor32InteractionClaimImpl;
use components::verify_bitwise_xor_12::InteractionClaimImpl as VerifyBitwiseXor12InteractionClaimImpl;
use components::verify_bitwise_xor_4::InteractionClaimImpl as VerifyBitwiseXor4InteractionClaimImpl;
use components::verify_bitwise_xor_7::InteractionClaimImpl as VerifyBitwiseXor7InteractionClaimImpl;
use components::verify_bitwise_xor_8::InteractionClaimImpl as VerifyBitwiseXor8InteractionClaimImpl;
use components::verify_bitwise_xor_9::InteractionClaimImpl as VerifyBitwiseXor9InteractionClaimImpl;
use components::verify_instruction::InteractionClaimImpl as VerifyInstructionInteractionClaimImpl;
use core::box::BoxImpl;
use core::num::traits::Zero;
use stwo_cairo_air::blake::*;
use stwo_cairo_air::builtins::*;
use stwo_cairo_air::cairo_component::CairoComponent;
use stwo_cairo_air::claim::ClaimTrait;
use stwo_cairo_air::opcodes::*;
use crate::P_U32;

#[cfg(not(feature: "poseidon252_verifier"))]
pub mod poseidon252_verifier_imports {
    pub use stwo_cairo_air::pedersen::{PedersenContextComponents, PedersenContextComponentsImpl};
    pub use stwo_cairo_air::poseidon::{PoseidonContextComponents, PoseidonContextComponentsImpl};
}
#[cfg(not(feature: "poseidon252_verifier"))]
use poseidon252_verifier_imports::*;
use stwo_cairo_air::blake::{
    BlakeContextClaim, BlakeContextComponents, BlakeContextComponentsImpl,
    BlakeContextInteractionClaim, BlakeContextInteractionClaimImpl,
};
use stwo_cairo_air::builtins::{
    BuiltinsClaim, BuiltinsInteractionClaim, BuiltinsInteractionClaimImpl,
};
use stwo_cairo_air::pedersen::{
    PedersenContextClaim, PedersenContextInteractionClaim, PedersenContextInteractionClaimImpl,
};
use stwo_cairo_air::poseidon::{
    PoseidonContextClaim, PoseidonContextInteractionClaim, PoseidonContextInteractionClaimImpl,
};
use stwo_cairo_air::preprocessed_columns::PREPROCESSED_COLUMNS;
use stwo_cairo_air::range_checks::{
    RangeChecksClaim, RangeChecksComponents, RangeChecksComponentsImpl, RangeChecksInteractionClaim,
    RangeChecksInteractionClaimImpl, RangeChecksInteractionElements,
    RangeChecksInteractionElementsImpl,
};
use stwo_cairo_air::{PublicData, PublicDataImpl, RelationUsesDict, components, utils};
use stwo_constraint_framework::{
    LookupElements, LookupElementsImpl, PreprocessedColumnImpl, PreprocessedColumnKey,
    PreprocessedColumnSet, PreprocessedMaskValuesImpl,
};
use stwo_verifier_core::channel::Channel;
use stwo_verifier_core::circle::CirclePoint;
use stwo_verifier_core::fields::qm31::QM31;
use stwo_verifier_core::fields::m31::M31;
use stwo_verifier_core::pcs::verifier::CommitmentSchemeVerifierImpl;
use stwo_verifier_core::utils::{ArrayImpl, OptionImpl, pow2};
use stwo_verifier_core::verifier::Air;
use stwo_verifier_core::{ColumnArray, ColumnSpan, TreeArray, TreeSpan};
use stwo_verifier_core::circle::CirclePointTrait;
use stwo_cairo_air::MemoryPolyCoeffs;

// Local circle polynomial evaluation over the circle basis, used to sample
// public Address->Id polynomials at mask points.
fn fold_mixed(
    values: @Array<M31>, folding_factors: @Array<QM31>, index: usize, level: usize, n: usize,
) -> QM31 {
    if n == 1 {
        return (*values[index]).into();
    }
    let lhs_val = fold_mixed(values, folding_factors, index, level + 1, n / 2);
    let rhs_val = fold_mixed(values, folding_factors, index + n / 2, level + 1, n / 2);
    lhs_val + rhs_val * *folding_factors[level]
}

fn circle_eval_at_point(coeffs: @Array<M31>, log_size: u32, point: CirclePoint<QM31>) -> QM31 {
    if log_size == 0_u32 {
        return (*coeffs[0]).into();
    }
    let mut factors: Array<QM31> = array![];
    factors.append(point.y);
    let mut x = point.x;
    let mut i: u32 = 1_u32;
    while i < log_size {
        factors.append(x);
        x = CirclePointTrait::double_x(x);
        i += 1_u32;
    }
    // reverse
    let mut rev_factors: Array<QM31> = array![];
    let mut span = factors.span();
    while let Some(v) = span.pop_back() {
        rev_factors.append(*v);
    }
    fold_mixed(coeffs, @rev_factors, 0, 0, coeffs.len())
}


pub type Cube252Elements = LookupElements<20>;

pub type MemoryAddressToIdElements = LookupElements<2>;

pub type AddressElements = LookupElements<1>;

pub type IdElements = LookupElements<1>;

pub type MemoryIdToBigElements = LookupElements<29>;

pub type OpcodesElements = LookupElements<3>;

pub type PartialEcMulElements = LookupElements<73>;

pub type PedersenPointsTableElements = LookupElements<57>;

pub type PoseidonFullRoundChainElements = LookupElements<32>;

pub type Poseidon3PartialRoundsChainElements = LookupElements<42>;

pub type PoseidonRoundKeysElements = LookupElements<31>;

pub type BlakeGElements = LookupElements<20>;

pub type BlakeRoundElements = LookupElements<35>;

pub type BlakeRoundSigmaElements = LookupElements<17>;

pub type TripleXor32Elements = LookupElements<8>;

pub type RangeCheckFelt252Width27Elements = LookupElements<10>;

pub type VerifyInstructionElements = LookupElements<7>;

pub type VerifyBitwiseXor_4Elements = LookupElements<3>;

pub type VerifyBitwiseXor_7Elements = LookupElements<3>;

pub type VerifyBitwiseXor_8Elements = LookupElements<3>;

pub type VerifyBitwiseXor_9Elements = LookupElements<3>;

pub type VerifyBitwiseXor_12Elements = LookupElements<3>;


#[derive(Drop, Serde)]
pub struct CairoClaim {
    pub public_data: PublicData,
    pub opcodes: OpcodeClaim,
    pub verify_instruction: components::verify_instruction::Claim,
    pub blake_context: BlakeContextClaim,
    pub builtins: BuiltinsClaim,
    pub pedersen_context: PedersenContextClaim,
    pub poseidon_context: PoseidonContextClaim,
    pub memory_address_to_id: components::memory_address_to_id::Claim,
    pub memory_id_to_value: components::memory_id_to_big::Claim,
    pub range_checks: RangeChecksClaim,
    pub verify_bitwise_xor_4: components::verify_bitwise_xor_4::Claim,
    pub verify_bitwise_xor_7: components::verify_bitwise_xor_7::Claim,
    pub verify_bitwise_xor_8: components::verify_bitwise_xor_8::Claim,
    pub verify_bitwise_xor_9: components::verify_bitwise_xor_9::Claim,
    // ...
}

pub impl CairoClaimImpl of ClaimTrait<CairoClaim> {
    fn log_sizes(self: @CairoClaim) -> TreeArray<Span<u32>> {
        let mut aggregated_log_sizes = utils::tree_array_concat_cols(
            array![
                self.opcodes.log_sizes(), self.verify_instruction.log_sizes(),
                self.blake_context.log_sizes(), self.builtins.log_sizes(),
                self.pedersen_context.log_sizes(), self.poseidon_context.log_sizes(),
                self.memory_address_to_id.log_sizes(), self.memory_id_to_value.log_sizes(),
                self.range_checks.log_sizes(), self.verify_bitwise_xor_4.log_sizes(),
                self.verify_bitwise_xor_7.log_sizes(), self.verify_bitwise_xor_8.log_sizes(),
                self.verify_bitwise_xor_9.log_sizes(),
            ],
        );

        // Overwrite the preprocessed trace log sizes.
        let _invalid_preprocessed_trace_log_sizes = aggregated_log_sizes.pop_front();

        let mut preprocessed_trace_log_sizes = array![];

        for preprocessed_column in PREPROCESSED_COLUMNS.span() {
            preprocessed_trace_log_sizes.append(preprocessed_column.log_size());
        }

        let trace_log_sizes = aggregated_log_sizes.pop_front().unwrap();
        let interaction_log_sizes = aggregated_log_sizes.pop_front().unwrap();
        assert!(aggregated_log_sizes.is_empty());

        array![preprocessed_trace_log_sizes.span(), trace_log_sizes, interaction_log_sizes]
    }

    fn mix_into(self: @CairoClaim, ref channel: Channel) {
        let CairoClaim {
            public_data,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            pedersen_context,
            poseidon_context,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        public_data.mix_into(ref channel);
        opcodes.mix_into(ref channel);
        verify_instruction.mix_into(ref channel);
        blake_context.mix_into(ref channel);
        builtins.mix_into(ref channel);
        pedersen_context.mix_into(ref channel);
        poseidon_context.mix_into(ref channel);
        memory_address_to_id.mix_into(ref channel);
        memory_id_to_value.mix_into(ref channel);
        range_checks.mix_into(ref channel);
        verify_bitwise_xor_4.mix_into(ref channel);
        verify_bitwise_xor_7.mix_into(ref channel);
        verify_bitwise_xor_8.mix_into(ref channel);
        verify_bitwise_xor_9.mix_into(ref channel);
    }

    fn accumulate_relation_uses(self: @CairoClaim, ref relation_uses: RelationUsesDict) {
        let CairoClaim {
            public_data: _,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            pedersen_context,
            poseidon_context,
            memory_address_to_id: _,
            memory_id_to_value,
            range_checks: _,
            verify_bitwise_xor_4: _,
            verify_bitwise_xor_7: _,
            verify_bitwise_xor_8: _,
            verify_bitwise_xor_9: _,
        } = self;
        // NOTE: The following components do not USE relations:
        // - range_checks
        // - verify_bitwise_xor_*
        // - memory_address_to_id

        opcodes.accumulate_relation_uses(ref relation_uses);
        blake_context.accumulate_relation_uses(ref relation_uses);
        builtins.accumulate_relation_uses(ref relation_uses);
        pedersen_context.accumulate_relation_uses(ref relation_uses);
        poseidon_context.accumulate_relation_uses(ref relation_uses);
        verify_instruction.accumulate_relation_uses(ref relation_uses);
        memory_id_to_value.accumulate_relation_uses(ref relation_uses);
    }
}


#[derive(Drop, Serde)]
pub struct CairoInteractionClaim {
    pub opcodes: OpcodeInteractionClaim,
    pub verify_instruction: components::verify_instruction::InteractionClaim,
    pub blake_context: BlakeContextInteractionClaim,
    pub builtins: BuiltinsInteractionClaim,
    pub pedersen_context: PedersenContextInteractionClaim,
    pub poseidon_context: PoseidonContextInteractionClaim,
    pub memory_address_to_id: components::memory_address_to_id::InteractionClaim,
    pub memory_id_to_value: components::memory_id_to_big::InteractionClaim,
    pub range_checks: RangeChecksInteractionClaim,
    pub verify_bitwise_xor_4: components::verify_bitwise_xor_4::InteractionClaim,
    pub verify_bitwise_xor_7: components::verify_bitwise_xor_7::InteractionClaim,
    pub verify_bitwise_xor_8: components::verify_bitwise_xor_8::InteractionClaim,
    pub verify_bitwise_xor_9: components::verify_bitwise_xor_9::InteractionClaim,
}

#[generate_trait]
pub impl CairoInteractionClaimImpl of CairoInteractionClaimTrace {
    fn mix_into(self: @CairoInteractionClaim, ref channel: Channel) {
        let CairoInteractionClaim {
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            pedersen_context,
            poseidon_context,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        opcodes.mix_into(ref channel);
        verify_instruction.mix_into(ref channel);
        blake_context.mix_into(ref channel);
        builtins.mix_into(ref channel);
        pedersen_context.mix_into(ref channel);
        poseidon_context.mix_into(ref channel);
        memory_address_to_id.mix_into(ref channel);
        memory_id_to_value.mix_into(ref channel);
        range_checks.mix_into(ref channel);
        verify_bitwise_xor_4.mix_into(ref channel);
        verify_bitwise_xor_7.mix_into(ref channel);
        verify_bitwise_xor_8.mix_into(ref channel);
        verify_bitwise_xor_9.mix_into(ref channel);
    }
}

#[derive(Drop)]
pub struct CairoInteractionElements {
    pub opcodes: OpcodesElements,
    pub verify_instruction: VerifyInstructionElements,
    pub blake_round: BlakeRoundElements,
    pub blake_g: BlakeGElements,
    pub blake_round_sigma: BlakeRoundSigmaElements,
    pub triple_xor_32: TripleXor32Elements,
    pub partial_ec_mul: PartialEcMulElements,
    pub pedersen_points_table: PedersenPointsTableElements,
    pub poseidon_full_round_chain: PoseidonFullRoundChainElements,
    pub poseidon_3_partial_rounds_chain: Poseidon3PartialRoundsChainElements,
    pub cube_252: Cube252Elements,
    pub poseidon_round_keys: PoseidonRoundKeysElements,
    pub range_check_felt_252_width_27: RangeCheckFelt252Width27Elements,
    pub memory_address_to_id: MemoryAddressToIdElements,
    pub address: AddressElements,
    pub id: IdElements,
    pub memory_id_to_value: MemoryIdToBigElements,
    pub range_checks: RangeChecksInteractionElements,
    pub verify_bitwise_xor_4: VerifyBitwiseXor_4Elements,
    pub verify_bitwise_xor_7: VerifyBitwiseXor_7Elements,
    pub verify_bitwise_xor_8: VerifyBitwiseXor_8Elements,
    pub verify_bitwise_xor_9: VerifyBitwiseXor_9Elements,
    pub verify_bitwise_xor_12: VerifyBitwiseXor_12Elements,
}

#[generate_trait]
pub impl CairoInteractionElementsImpl of CairoInteractionElementsTrait {
    fn draw(ref channel: Channel) -> CairoInteractionElements {
        CairoInteractionElements {
            opcodes: LookupElementsImpl::draw(ref channel),
            verify_instruction: LookupElementsImpl::draw(ref channel),
            blake_round: LookupElementsImpl::draw(ref channel),
            blake_g: LookupElementsImpl::draw(ref channel),
            blake_round_sigma: LookupElementsImpl::draw(ref channel),
            triple_xor_32: LookupElementsImpl::draw(ref channel),
            poseidon_3_partial_rounds_chain: LookupElementsImpl::draw(ref channel),
            poseidon_full_round_chain: LookupElementsImpl::draw(ref channel),
            cube_252: LookupElementsImpl::draw(ref channel),
            poseidon_round_keys: LookupElementsImpl::draw(ref channel),
            range_check_felt_252_width_27: LookupElementsImpl::draw(ref channel),
            partial_ec_mul: LookupElementsImpl::draw(ref channel),
            pedersen_points_table: LookupElementsImpl::draw(ref channel),
            address: LookupElementsImpl::draw(ref channel),
            id: LookupElementsImpl::draw(ref channel),
            memory_address_to_id: LookupElementsImpl::draw(ref channel),
            memory_id_to_value: LookupElementsImpl::draw(ref channel),
            range_checks: RangeChecksInteractionElementsImpl::draw(ref channel),
            verify_bitwise_xor_4: LookupElementsImpl::draw(ref channel),
            verify_bitwise_xor_7: LookupElementsImpl::draw(ref channel),
            verify_bitwise_xor_8: LookupElementsImpl::draw(ref channel),
            verify_bitwise_xor_9: LookupElementsImpl::draw(ref channel),
            verify_bitwise_xor_12: LookupElementsImpl::draw(ref channel),
        }
    }
}


#[derive(Drop)]
#[cfg(not(feature: "poseidon252_verifier"))]
pub struct CairoAir {
    // Public polynomial coefficients used to recompute mask values for public tables.
    memory_poly_coeffs: @MemoryPolyCoeffs,
    opcodes: OpcodeComponents,
    verify_instruction: components::verify_instruction::Component,
    blake_context: BlakeContextComponents,
    builtins: BuiltinComponents,
    pedersen_context: PedersenContextComponents,
    poseidon_context: PoseidonContextComponents,
    memory_address_to_id: components::memory_address_to_id::Component,
    memory_id_to_value: (
        Array<components::memory_id_to_big::BigComponent>,
        components::memory_id_to_big::SmallComponent,
    ),
    range_checks: RangeChecksComponents,
    verify_bitwise_xor_4: components::verify_bitwise_xor_4::Component,
    verify_bitwise_xor_7: components::verify_bitwise_xor_7::Component,
    verify_bitwise_xor_8: components::verify_bitwise_xor_8::Component,
    verify_bitwise_xor_9: components::verify_bitwise_xor_9::Component,
}

#[generate_trait]
#[cfg(not(feature: "poseidon252_verifier"))]
pub impl CairoAirNewImpl of CairoAirNewTrait {
    fn new(
        cairo_claim: @CairoClaim,
        interaction_elements: @CairoInteractionElements,
        interaction_claim: @CairoInteractionClaim,
    ) -> CairoAir {
        let opcode_components = OpcodeComponentsImpl::new(
            cairo_claim.opcodes, interaction_elements, interaction_claim.opcodes,
        );

        let blake_context_component = BlakeContextComponentsImpl::new(
            cairo_claim.blake_context, interaction_elements, interaction_claim.blake_context,
        );

        let builtins_components = BuiltinComponentsImpl::new(
            cairo_claim.builtins, interaction_elements, interaction_claim.builtins,
        );

        let pedersen_context_components = PedersenContextComponentsImpl::new(
            cairo_claim.pedersen_context, interaction_elements, interaction_claim.pedersen_context,
        );

        let poseidon_context_components = PoseidonContextComponentsImpl::new(
            cairo_claim.poseidon_context, interaction_elements, interaction_claim.poseidon_context,
        );

        let verifyinstruction_component = components::verify_instruction::NewComponentImpl::new(
            cairo_claim.verify_instruction,
            interaction_claim.verify_instruction,
            interaction_elements,
        );

        let memory_address_to_id_component =
            components::memory_address_to_id::NewComponentImpl::new(
            cairo_claim.memory_address_to_id,
            interaction_claim.memory_address_to_id,
            interaction_elements,
        );

        assert!(
            cairo_claim
                .memory_id_to_value
                .big_log_sizes
                .len() == interaction_claim
                .memory_id_to_value
                .big_claimed_sums
                .len(),
        );
        let mut memory_id_to_value_components = array![];
        let mut offset: u32 = LARGE_MEMORY_VALUE_ID_BASE;
        for i in 0..cairo_claim.memory_id_to_value.big_log_sizes.len() {
            let log_size = *cairo_claim.memory_id_to_value.big_log_sizes[i];
            let claimed_sum = *interaction_claim.memory_id_to_value.big_claimed_sums[i];
            memory_id_to_value_components
                .append(
                    components::memory_id_to_big::NewBigComponentImpl::new(
                        log_size, offset, claimed_sum, interaction_elements,
                    ),
                );
            offset = offset + pow2(log_size);
        }
        // Check that IDs in (ID -> Value) do not overflow P.
        assert!(offset <= P_U32);

        let small_memory_id_to_value_component =
            components::memory_id_to_big::NewSmallComponentImpl::new(
            *cairo_claim.memory_id_to_value.small_log_size,
            *interaction_claim.memory_id_to_value.small_claimed_sum,
            interaction_elements,
        );

        let range_checks_components = RangeChecksComponentsImpl::new(
            cairo_claim.range_checks, interaction_elements, interaction_claim.range_checks,
        );

        let verify_bitwise_xor_4_component =
            components::verify_bitwise_xor_4::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_4,
            interaction_claim.verify_bitwise_xor_4,
            interaction_elements,
        );

        let verify_bitwise_xor_7_component =
            components::verify_bitwise_xor_7::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_7,
            interaction_claim.verify_bitwise_xor_7,
            interaction_elements,
        );

        let verify_bitwise_xor_8_component =
            components::verify_bitwise_xor_8::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_8,
            interaction_claim.verify_bitwise_xor_8,
            interaction_elements,
        );

        let verify_bitwise_xor_9_component =
            components::verify_bitwise_xor_9::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_9,
            interaction_claim.verify_bitwise_xor_9,
            interaction_elements,
        );

        CairoAir {
            memory_poly_coeffs: cairo_claim.public_data.memory_poly_coeffs,
            opcodes: opcode_components,
            verify_instruction: verifyinstruction_component,
            blake_context: blake_context_component,
            builtins: builtins_components,
            pedersen_context: pedersen_context_components,
            poseidon_context: poseidon_context_components,
            memory_address_to_id: memory_address_to_id_component,
            memory_id_to_value: (memory_id_to_value_components, small_memory_id_to_value_component),
            range_checks: range_checks_components,
            verify_bitwise_xor_4: verify_bitwise_xor_4_component,
            verify_bitwise_xor_7: verify_bitwise_xor_7_component,
            verify_bitwise_xor_8: verify_bitwise_xor_8_component,
            verify_bitwise_xor_9: verify_bitwise_xor_9_component,
        }
    }
}

#[cfg(not(feature: "poseidon252_verifier"))]
pub impl CairoAirImpl of Air<CairoAir> {
    fn composition_log_degree_bound(self: @CairoAir) -> u32 {
        let CairoAir {
            memory_poly_coeffs: _,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            pedersen_context,
            poseidon_context,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        let mut max_degree = opcodes.max_constraint_log_degree_bound();
        max_degree =
            core::cmp::max(max_degree, verify_instruction.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, blake_context.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, builtins.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, pedersen_context.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, poseidon_context.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, memory_address_to_id.max_constraint_log_degree_bound());
        let (memory_id_to_value_big, memory_id_to_value_small) = memory_id_to_value;
        for memory_id_to_value_big_component in memory_id_to_value_big.span() {
            max_degree =
                core::cmp::max(
                    max_degree, memory_id_to_value_big_component.max_constraint_log_degree_bound(),
                );
        }
        max_degree =
            core::cmp::max(max_degree, memory_id_to_value_small.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, range_checks.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_4.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_7.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_8.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_9.max_constraint_log_degree_bound());
        max_degree
    }

    fn mask_points(
        self: @CairoAir, point: CirclePoint<QM31>,
    ) -> TreeArray<ColumnArray<Array<CirclePoint<QM31>>>> {
        let mut preprocessed_column_set: PreprocessedColumnSet = Default::default();
        let mut trace_mask_points = array![];
        let mut interaction_trace_mask_points = array![];
        let CairoAir {
            memory_poly_coeffs: _,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            pedersen_context,
            poseidon_context,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        opcodes
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_instruction
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        blake_context
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        builtins
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        pedersen_context
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        poseidon_context
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        memory_address_to_id
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );

        let (memory_id_to_value_big, memory_id_to_value_small) = memory_id_to_value;
        for memory_id_to_value_big_component in memory_id_to_value_big.span() {
            memory_id_to_value_big_component
                .mask_points(
                    ref preprocessed_column_set,
                    ref trace_mask_points,
                    ref interaction_trace_mask_points,
                    point,
                );
        }
        memory_id_to_value_small
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        range_checks
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_4
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_7
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_8
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_9
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );

        let preprocessed_trace_mask_points = preprocessed_trace_mask_points(
            preprocessed_column_set, point,
        );

        array![preprocessed_trace_mask_points, trace_mask_points, interaction_trace_mask_points]
    }

    fn eval_composition_polynomial_at_point(
        self: @CairoAir,
        point: CirclePoint<QM31>,
        mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
        random_coeff: QM31,
    ) -> QM31 {
        let mut sum = Zero::zero();

        let [
            preprocessed_mask_values,
            mut trace_mask_values,
            mut interaction_trace_mask_values,
            _composition_trace_mask_values,
        ]: [ColumnSpan<Span<QM31>>; 4] =
            (*mask_values
            .try_into()
            .unwrap())
            .unbox();

        let mut preprocessed_mask_values = PreprocessedMaskValuesImpl::new(
            preprocessed_mask_values, PREPROCESSED_COLUMNS.span(),
        );
        let CairoAir {
            memory_poly_coeffs: _,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            pedersen_context,
            poseidon_context,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        opcodes
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_instruction
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        blake_context
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        builtins
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        pedersen_context
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        poseidon_context
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        memory_address_to_id
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        let (memory_id_to_value_big, memory_id_to_value_small) = memory_id_to_value;
        for memory_id_to_value_big_component in memory_id_to_value_big.span() {
            memory_id_to_value_big_component
                .evaluate_constraints_at_point(
                    ref sum,
                    ref preprocessed_mask_values,
                    ref trace_mask_values,
                    ref interaction_trace_mask_values,
                    random_coeff,
                    point,
                );
        }
        memory_id_to_value_small
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );

        range_checks
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_4
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_7
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_8
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_9
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        sum
    }


    // Asserts that the reconstructed OODS from public Id->Big polynomials equals the
    // prover-supplied OODS for all Id->Big components (big + small).
    fn assert_id_to_big_preimage_oods(
        self: @CairoAir,
        point: CirclePoint<QM31>,
        mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
        random_coeff: QM31,
    ) {
        // 1) Build public samples for big + small components.
        let (
            big_base_samples_all,
            big_inter_samples_all,
            small_base_samples,
            small_inter_samples,
        ) = sample_id_to_big_public_polys(self, point);

        // Empty preprocessed mask values (not used by this component).
        let mut empty_pre_cols_arrays: Array<Array<QM31>> = array![];
        for _ in PREPROCESSED_COLUMNS.span() { empty_pre_cols_arrays.append(array![]); }
        let mut empty_pre_cols: Array<Span<QM31>> = array![];
        for arr in empty_pre_cols_arrays.span() { empty_pre_cols.append(arr.span()); }
        let mut preprocessed_mask_values_dummy =
            PreprocessedMaskValuesImpl::new(empty_pre_cols.span(), PREPROCESSED_COLUMNS.span());

        // 2) Extract the proof-provided spans only for Id->Big components from mask_values.
        let [
            _pre_mask,
            mut trace_mask_values,
            mut interaction_mask_values,
            _composition_mask,
        ]: [ColumnSpan<Span<QM31>>; 4] = (*mask_values.try_into().unwrap()).unbox();

        // Skip preceding components by mirroring mask_points ordering up to memory_address_to_id.
        let mut set: PreprocessedColumnSet = Default::default();
        let mut t_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut i_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut skip_t: usize = 0;
        let mut skip_i: usize = 0;

        // opcodes
        skip_t = t_points.len(); skip_i = i_points.len();
        self.opcodes.mask_points(ref set, ref t_points, ref i_points, point);
        let mut d_t = t_points.len() - skip_t; let mut d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // verify_instruction
        skip_t = t_points.len(); skip_i = i_points.len();
        self.verify_instruction.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // blake_context
        skip_t = t_points.len(); skip_i = i_points.len();
        self.blake_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // builtins
        skip_t = t_points.len(); skip_i = i_points.len();
        self.builtins.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // pedersen_context
        skip_t = t_points.len(); skip_i = i_points.len();
        self.pedersen_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // poseidon_context
        skip_t = t_points.len(); skip_i = i_points.len();
        self.poseidon_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // memory_address_to_id
        skip_t = t_points.len(); skip_i = i_points.len();
        self.memory_address_to_id.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // Now process big components sequentially.
        let (big_components, small_component) = self.memory_id_to_value;
        let mut idx: usize = 0;
        for big_comp in big_components.span() {
            // Prepare public samples for this component.
            let mut base_spans: Array<Span<QM31>> = array![];
            let mut inter_spans: Array<Span<QM31>> = array![];
            let base_cols = big_base_samples_all[idx];
            for vals in base_cols.span() { base_spans.append(vals.span()); }
            let inter_cols = big_inter_samples_all[idx];
            for vals in inter_cols.span() { inter_spans.append(vals.span()); }

            // Evaluate OODS using public samples for this component.
            let mut preimage_sum: QM31 = Zero::zero();
            let mut base_spans_span = base_spans.span();
            let mut inter_spans_span = inter_spans.span();
            big_comp.evaluate_constraints_at_point(
                ref preimage_sum,
                ref preprocessed_mask_values_dummy,
                ref base_spans_span,
                ref inter_spans_span,
                random_coeff,
                point,
            );

            // Extract proof-provided values for this big component and evaluate.
            skip_t = t_points.len(); skip_i = i_points.len();
            big_comp.mask_points(ref set, ref t_points, ref i_points, point);
            d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
            let mut trace_comp_vals: Array<Span<QM31>> = array![];
            let mut inter_comp_vals: Array<Span<QM31>> = array![];
            for _ in 0..d_t { trace_comp_vals.append(*trace_mask_values.pop_front().unwrap()); }
            for _ in 0..d_i { inter_comp_vals.append(*interaction_mask_values.pop_front().unwrap()); }

            let mut proof_sum: QM31 = Zero::zero();
            let mut trace_comp_vals_span = trace_comp_vals.span();
            let mut inter_comp_vals_span = inter_comp_vals.span();
            big_comp.evaluate_constraints_at_point(
                ref proof_sum,
                ref preprocessed_mask_values_dummy,
                ref trace_comp_vals_span,
                ref inter_comp_vals_span,
                random_coeff,
                point,
            );

            assert!(
                preimage_sum == proof_sum,
                "{}",
                stwo_verifier_core::verifier::VerificationError::OodsNotMatching,
            );

            idx += 1_usize;
        }

        // Small component.
        let mut base_spans: Array<Span<QM31>> = array![];
        let mut inter_spans: Array<Span<QM31>> = array![];
        for vals in small_base_samples.span() { base_spans.append(vals.span()); }
        for vals in small_inter_samples.span() { inter_spans.append(vals.span()); }

        let mut preimage_sum: QM31 = Zero::zero();
        let mut base_spans_span = base_spans.span();
        let mut inter_spans_span = inter_spans.span();
        small_component.evaluate_constraints_at_point(
            ref preimage_sum,
            ref preprocessed_mask_values_dummy,
            ref base_spans_span,
            ref inter_spans_span,
            random_coeff,
            point,
        );

        // Extract proof-provided values for small component.
        skip_t = t_points.len(); skip_i = i_points.len();
        small_component.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        let mut trace_comp_vals: Array<Span<QM31>> = array![];
        let mut inter_comp_vals: Array<Span<QM31>> = array![];
        for _ in 0..d_t { trace_comp_vals.append(*trace_mask_values.pop_front().unwrap()); }
        for _ in 0..d_i { inter_comp_vals.append(*interaction_mask_values.pop_front().unwrap()); }

        let mut proof_sum: QM31 = Zero::zero();
        let mut trace_comp_vals_span = trace_comp_vals.span();
        let mut inter_comp_vals_span = inter_comp_vals.span();
        small_component.evaluate_constraints_at_point(
            ref proof_sum,
            ref preprocessed_mask_values_dummy,
            ref trace_comp_vals_span,
            ref inter_comp_vals_span,
            random_coeff,
            point,
        );

        assert!(
            preimage_sum == proof_sum,
            "{}",
            stwo_verifier_core::verifier::VerificationError::OodsNotMatching,
        );
    }

    fn assert_address_to_id_preimage_oods(
        self: @CairoAir,
        point: CirclePoint<QM31>,
        mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
        random_coeff: QM31,
    ) {
        // 1) Build public samples.
        let (base_samples, inter_samples) = sample_address_to_id_public_polys(self, point);

        // Convert public samples to spans-of-spans.
        let mut base_spans: Array<Span<QM31>> = array![];
        for vals in base_samples.span() {
            base_spans.append(vals.span());
        }
        let mut inter_spans: Array<Span<QM31>> = array![];
        for vals in inter_samples.span() {
            inter_spans.append(vals.span());
        }

        // Empty preprocessed mask values (not used by this component).
        let mut empty_pre_cols_arrays: Array<Array<QM31>> = array![];
        for _ in PREPROCESSED_COLUMNS.span() {
            empty_pre_cols_arrays.append(array![]);
        }
        let mut empty_pre_cols: Array<Span<QM31>> = array![];
        for arr in empty_pre_cols_arrays.span() {
            empty_pre_cols.append(arr.span());
        }
        let mut preprocessed_mask_values_dummy =
            PreprocessedMaskValuesImpl::new(empty_pre_cols.span(), PREPROCESSED_COLUMNS.span());

        // 2) Evaluate OODS using public samples.
        let mut preimage_sum: QM31 = Zero::zero();
        let mut base_spans_span = base_spans.span();
        let mut inter_spans_span = inter_spans.span();
        self.memory_address_to_id.evaluate_constraints_at_point(
            ref preimage_sum,
            ref preprocessed_mask_values_dummy,
            ref base_spans_span,
            ref inter_spans_span,
            random_coeff,
            point,
        );

        // 3) Extract the proof-provided spans only for this component from mask_values and evaluate.
        let [
            _pre_mask,
            mut trace_mask_values,
            mut interaction_mask_values,
            _composition_mask,
        ]: [ColumnSpan<Span<QM31>>; 4] =
            (*mask_values
            .try_into()
            .unwrap())
            .unbox();

        // Skip preceding components by mirroring mask_points ordering.
        let mut set: PreprocessedColumnSet = Default::default();
        let mut t_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut i_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut skip_t: usize = 0;
        let mut skip_i: usize = 0;

        // opcodes
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.opcodes.mask_points(ref set, ref t_points, ref i_points, point);
        let mut d_t = t_points.len() - skip_t;
        let mut d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // verify_instruction
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.verify_instruction.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // blake_context
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.blake_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // builtins
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.builtins.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // pedersen_context
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.pedersen_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // poseidon_context
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.poseidon_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // memory_address_to_id: capture spans for this component.
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.memory_address_to_id.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        let mut trace_comp_vals: Array<Span<QM31>> = array![];
        let mut inter_comp_vals: Array<Span<QM31>> = array![];
        for _ in 0..d_t { trace_comp_vals.append(*trace_mask_values.pop_front().unwrap()); }
        for _ in 0..d_i { inter_comp_vals.append(*interaction_mask_values.pop_front().unwrap()); }

        // Evaluate proof OODS for this component using proof-provided values.
        let mut proof_sum: QM31 = Zero::zero();
        let mut trace_comp_vals_span = trace_comp_vals.span();
        let mut inter_comp_vals_span = inter_comp_vals.span();
        self.memory_address_to_id.evaluate_constraints_at_point(
            ref proof_sum,
            ref preprocessed_mask_values_dummy,
            ref trace_comp_vals_span,
            ref inter_comp_vals_span,
            random_coeff,
            point,
        );

        assert!(
            preimage_sum == proof_sum,
            "{}",
            stwo_verifier_core::verifier::VerificationError::OodsNotMatching,
        );
    }
}

#[derive(Drop)]
#[cfg(feature: "poseidon252_verifier")]
pub struct CairoAir {
    // Public polynomial coefficients used to recompute mask values for public tables.
    memory_poly_coeffs: @MemoryPolyCoeffs,
    opcodes: OpcodeComponents,
    verify_instruction: components::verify_instruction::Component,
    blake_context: BlakeContextComponents,
    builtins: BuiltinComponents,
    memory_address_to_id: components::memory_address_to_id::Component,
    memory_id_to_value: (
        Array<components::memory_id_to_big::BigComponent>,
        components::memory_id_to_big::SmallComponent,
    ),
    range_checks: RangeChecksComponents,
    verify_bitwise_xor_4: components::verify_bitwise_xor_4::Component,
    verify_bitwise_xor_7: components::verify_bitwise_xor_7::Component,
    verify_bitwise_xor_8: components::verify_bitwise_xor_8::Component,
    verify_bitwise_xor_9: components::verify_bitwise_xor_9::Component,
}

#[generate_trait]
#[cfg(feature: "poseidon252_verifier")]
pub impl CairoAirNewImpl of CairoAirNewTrait {
    fn new(
        cairo_claim: @CairoClaim,
        interaction_elements: @CairoInteractionElements,
        interaction_claim: @CairoInteractionClaim,
    ) -> CairoAir {
        let opcode_components = OpcodeComponentsImpl::new(
            cairo_claim.opcodes, interaction_elements, interaction_claim.opcodes,
        );

        let blake_context_component = BlakeContextComponentsImpl::new(
            cairo_claim.blake_context, interaction_elements, interaction_claim.blake_context,
        );

        let builtins_components = BuiltinComponentsImpl::new(
            cairo_claim.builtins, interaction_elements, interaction_claim.builtins,
        );

        let verifyinstruction_component = components::verify_instruction::NewComponentImpl::new(
            cairo_claim.verify_instruction,
            interaction_claim.verify_instruction,
            interaction_elements,
        );

        let memory_address_to_id_component =
            components::memory_address_to_id::NewComponentImpl::new(
            cairo_claim.memory_address_to_id,
            interaction_claim.memory_address_to_id,
            interaction_elements,
        );

        assert!(
            cairo_claim
                .memory_id_to_value
                .big_log_sizes
                .len() == interaction_claim
                .memory_id_to_value
                .big_claimed_sums
                .len(),
        );
        let mut memory_id_to_value_components = array![];
        let mut offset: u32 = LARGE_MEMORY_VALUE_ID_BASE;
        for i in 0..cairo_claim.memory_id_to_value.big_log_sizes.len() {
            let log_size = *cairo_claim.memory_id_to_value.big_log_sizes[i];
            let claimed_sum = *interaction_claim.memory_id_to_value.big_claimed_sums[i];
            memory_id_to_value_components
                .append(
                    components::memory_id_to_big::NewBigComponentImpl::new(
                        log_size, offset, claimed_sum, interaction_elements,
                    ),
                );
            offset = offset + pow2(log_size);
        }
        // Check that IDs in (ID -> Value) do not overflow P.
        assert!(offset <= P_U32);

        let small_memory_id_to_value_component =
            components::memory_id_to_big::NewSmallComponentImpl::new(
            *cairo_claim.memory_id_to_value.small_log_size,
            *interaction_claim.memory_id_to_value.small_claimed_sum,
            interaction_elements,
        );

        let range_checks_components = RangeChecksComponentsImpl::new(
            cairo_claim.range_checks, interaction_elements, interaction_claim.range_checks,
        );

        let verify_bitwise_xor_4_component =
            components::verify_bitwise_xor_4::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_4,
            interaction_claim.verify_bitwise_xor_4,
            interaction_elements,
        );

        let verify_bitwise_xor_7_component =
            components::verify_bitwise_xor_7::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_7,
            interaction_claim.verify_bitwise_xor_7,
            interaction_elements,
        );

        let verify_bitwise_xor_8_component =
            components::verify_bitwise_xor_8::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_8,
            interaction_claim.verify_bitwise_xor_8,
            interaction_elements,
        );

        let verify_bitwise_xor_9_component =
            components::verify_bitwise_xor_9::NewComponentImpl::new(
            cairo_claim.verify_bitwise_xor_9,
            interaction_claim.verify_bitwise_xor_9,
            interaction_elements,
        );

        CairoAir {
            memory_poly_coeffs: cairo_claim.public_data.memory_poly_coeffs,
            opcodes: opcode_components,
            verify_instruction: verifyinstruction_component,
            blake_context: blake_context_component,
            builtins: builtins_components,
            memory_address_to_id: memory_address_to_id_component,
            memory_id_to_value: (memory_id_to_value_components, small_memory_id_to_value_component),
            range_checks: range_checks_components,
            verify_bitwise_xor_4: verify_bitwise_xor_4_component,
            verify_bitwise_xor_7: verify_bitwise_xor_7_component,
            verify_bitwise_xor_8: verify_bitwise_xor_8_component,
            verify_bitwise_xor_9: verify_bitwise_xor_9_component,
        }
    }
}

#[cfg(feature: "poseidon252_verifier")]
pub impl CairoAirImpl of Air<CairoAir> {
    fn composition_log_degree_bound(self: @CairoAir) -> u32 {
        let CairoAir {
            memory_poly_coeffs: _,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        let mut max_degree = opcodes.max_constraint_log_degree_bound();
        max_degree =
            core::cmp::max(max_degree, verify_instruction.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, blake_context.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, builtins.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, memory_address_to_id.max_constraint_log_degree_bound());
        let (memory_id_to_value_big, memory_id_to_value_small) = memory_id_to_value;
        for memory_id_to_value_big_component in memory_id_to_value_big.span() {
            max_degree =
                core::cmp::max(
                    max_degree, memory_id_to_value_big_component.max_constraint_log_degree_bound(),
                );
        }
        max_degree =
            core::cmp::max(max_degree, memory_id_to_value_small.max_constraint_log_degree_bound());
        max_degree = core::cmp::max(max_degree, range_checks.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_4.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_7.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_8.max_constraint_log_degree_bound());
        max_degree =
            core::cmp::max(max_degree, verify_bitwise_xor_9.max_constraint_log_degree_bound());
        max_degree
    }

    fn mask_points(
        self: @CairoAir, point: CirclePoint<QM31>,
    ) -> TreeArray<ColumnArray<Array<CirclePoint<QM31>>>> {
        let mut preprocessed_column_set: PreprocessedColumnSet = Default::default();
        let mut trace_mask_points = array![];
        let mut interaction_trace_mask_points = array![];
        let CairoAir {
            memory_poly_coeffs: _,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        opcodes
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_instruction
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        blake_context
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        builtins
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        memory_address_to_id
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );

        let (memory_id_to_value_big, memory_id_to_value_small) = memory_id_to_value;
        for memory_id_to_value_big_component in memory_id_to_value_big.span() {
            memory_id_to_value_big_component
                .mask_points(
                    ref preprocessed_column_set,
                    ref trace_mask_points,
                    ref interaction_trace_mask_points,
                    point,
                );
        }
        memory_id_to_value_small
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        range_checks
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_4
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_7
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_8
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );
        verify_bitwise_xor_9
            .mask_points(
                ref preprocessed_column_set,
                ref trace_mask_points,
                ref interaction_trace_mask_points,
                point,
            );

        let preprocessed_trace_mask_points = preprocessed_trace_mask_points(
            preprocessed_column_set, point,
        );

        array![preprocessed_trace_mask_points, trace_mask_points, interaction_trace_mask_points]
    }

    fn eval_composition_polynomial_at_point(
        self: @CairoAir,
        point: CirclePoint<QM31>,
        mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
        random_coeff: QM31,
    ) -> QM31 {
        let mut sum = Zero::zero();

        let [
            preprocessed_mask_values,
            mut trace_mask_values,
            mut interaction_trace_mask_values,
            _composition_trace_mask_values,
        ]: [ColumnSpan<Span<QM31>>; 4] =
            (*mask_values
            .try_into()
            .unwrap())
            .unbox();

        let mut preprocessed_mask_values = PreprocessedMaskValuesImpl::new(
            preprocessed_mask_values, PREPROCESSED_COLUMNS.span(),
        );

        let CairoAir {
            memory_poly_coeffs: _,
            opcodes,
            verify_instruction,
            blake_context,
            builtins,
            memory_address_to_id,
            memory_id_to_value,
            range_checks,
            verify_bitwise_xor_4,
            verify_bitwise_xor_7,
            verify_bitwise_xor_8,
            verify_bitwise_xor_9,
        } = self;

        opcodes
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_instruction
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        blake_context
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        builtins
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        memory_address_to_id
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        let (memory_id_to_value_big, memory_id_to_value_small) = memory_id_to_value;
        for memory_id_to_value_big_component in memory_id_to_value_big.span() {
            memory_id_to_value_big_component
                .evaluate_constraints_at_point(
                    ref sum,
                    ref preprocessed_mask_values,
                    ref trace_mask_values,
                    ref interaction_trace_mask_values,
                    random_coeff,
                    point,
                );
        }
        memory_id_to_value_small
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        range_checks
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_4
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_7
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_8
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        verify_bitwise_xor_9
            .evaluate_constraints_at_point(
                ref sum,
                ref preprocessed_mask_values,
                ref trace_mask_values,
                ref interaction_trace_mask_values,
                random_coeff,
                point,
            );
        sum
    }


    // Asserts that the reconstructed OODS from public Id->Big polynomials equals the
    // prover-supplied OODS for all Id->Big components (big + small).
    fn assert_id_to_big_preimage_oods(
        self: @CairoAir,
        point: CirclePoint<QM31>,
        mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
        random_coeff: QM31,
    ) {
        // 1) Build public samples for big + small components.
        let (
            big_base_samples_all,
            big_inter_samples_all,
            small_base_samples,
            small_inter_samples,
        ) = sample_id_to_big_public_polys(self, point);

        // Empty preprocessed mask values.
        let mut empty_pre_cols_arrays: Array<Array<QM31>> = array![];
        for _ in PREPROCESSED_COLUMNS.span() { empty_pre_cols_arrays.append(array![]); }
        let mut empty_pre_cols: Array<Span<QM31>> = array![];
        for arr in empty_pre_cols_arrays.span() { empty_pre_cols.append(arr.span()); }
        let mut preprocessed_mask_values_dummy =
            PreprocessedMaskValuesImpl::new(empty_pre_cols.span(), PREPROCESSED_COLUMNS.span());

        // 2) Extract proof-provided spans for Id->Big components from mask_values.
        let [
            _pre_mask,
            mut trace_mask_values,
            mut interaction_mask_values,
            _composition_mask,
        ]: [ColumnSpan<Span<QM31>>; 4] = (*mask_values.try_into().unwrap()).unbox();

        // Skip preceding components up to memory_address_to_id.
        let mut set: PreprocessedColumnSet = Default::default();
        let mut t_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut i_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut skip_t: usize = 0;
        let mut skip_i: usize = 0;

        // opcodes
        skip_t = t_points.len(); skip_i = i_points.len();
        self.opcodes.mask_points(ref set, ref t_points, ref i_points, point);
        let mut d_t = t_points.len() - skip_t; let mut d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // verify_instruction
        skip_t = t_points.len(); skip_i = i_points.len();
        self.verify_instruction.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // blake_context
        skip_t = t_points.len(); skip_i = i_points.len();
        self.blake_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // builtins
        skip_t = t_points.len(); skip_i = i_points.len();
        self.builtins.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // memory_address_to_id
        skip_t = t_points.len(); skip_i = i_points.len();
        self.memory_address_to_id.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // Process big components.
        let (big_components, small_component) = self.memory_id_to_value;
        let mut idx: usize = 0;
        for big_comp in big_components.span() {
            // Public samples for this component.
            let mut base_spans: Array<Span<QM31>> = array![];
            let mut inter_spans: Array<Span<QM31>> = array![];
            let base_cols = big_base_samples_all[idx];
            for vals in base_cols.span() { base_spans.append(vals.span()); }
            let inter_cols = big_inter_samples_all[idx];
            for vals in inter_cols.span() { inter_spans.append(vals.span()); }

            let mut preimage_sum: QM31 = Zero::zero();
            let mut base_spans_span = base_spans.span();
            let mut inter_spans_span = inter_spans.span();
            big_comp.evaluate_constraints_at_point(
                ref preimage_sum,
                ref preprocessed_mask_values_dummy,
                ref base_spans_span,
                ref inter_spans_span,
                random_coeff,
                point,
            );

            // Proof-provided values for this big component.
            skip_t = t_points.len(); skip_i = i_points.len();
            big_comp.mask_points(ref set, ref t_points, ref i_points, point);
            d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
            let mut trace_comp_vals: Array<Span<QM31>> = array![];
            let mut inter_comp_vals: Array<Span<QM31>> = array![];
            for _ in 0..d_t { trace_comp_vals.append(*trace_mask_values.pop_front().unwrap()); }
            for _ in 0..d_i { inter_comp_vals.append(*interaction_mask_values.pop_front().unwrap()); }

            let mut proof_sum: QM31 = Zero::zero();
            let mut trace_comp_vals_span = trace_comp_vals.span();
            let mut inter_comp_vals_span = inter_comp_vals.span();
            big_comp.evaluate_constraints_at_point(
                ref proof_sum,
                ref preprocessed_mask_values_dummy,
                ref trace_comp_vals_span,
                ref inter_comp_vals_span,
                random_coeff,
                point,
            );

            assert!(
                preimage_sum == proof_sum,
                "{}",
                stwo_verifier_core::verifier::VerificationError::OodsNotMatching,
            );

            idx += 1_usize;
        }

        // Small component.
        let mut base_spans: Array<Span<QM31>> = array![];
        let mut inter_spans: Array<Span<QM31>> = array![];
        for vals in small_base_samples.span() { base_spans.append(vals.span()); }
        for vals in small_inter_samples.span() { inter_spans.append(vals.span()); }

        let mut preimage_sum: QM31 = Zero::zero();
        let mut base_spans_span = base_spans.span();
        let mut inter_spans_span = inter_spans.span();
        small_component.evaluate_constraints_at_point(
            ref preimage_sum,
            ref preprocessed_mask_values_dummy,
            ref base_spans_span,
            ref inter_spans_span,
            random_coeff,
            point,
        );

        // Extract proof-provided values for small component.
        skip_t = t_points.len(); skip_i = i_points.len();
        small_component.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t; d_i = i_points.len() - skip_i;
        let mut trace_comp_vals: Array<Span<QM31>> = array![];
        let mut inter_comp_vals: Array<Span<QM31>> = array![];
        for _ in 0..d_t { trace_comp_vals.append(*trace_mask_values.pop_front().unwrap()); }
        for _ in 0..d_i { inter_comp_vals.append(*interaction_mask_values.pop_front().unwrap()); }

        let mut proof_sum: QM31 = Zero::zero();
        let mut trace_comp_vals_span = trace_comp_vals.span();
        let mut inter_comp_vals_span = inter_comp_vals.span();
        small_component.evaluate_constraints_at_point(
            ref proof_sum,
            ref preprocessed_mask_values_dummy,
            ref trace_comp_vals_span,
            ref inter_comp_vals_span,
            random_coeff,
            point,
        );

        assert!(
            preimage_sum == proof_sum,
            "{}",
            stwo_verifier_core::verifier::VerificationError::OodsNotMatching,
        );
    }

    fn assert_address_to_id_preimage_oods(
        self: @CairoAir,
        point: CirclePoint<QM31>,
        mask_values: TreeSpan<ColumnSpan<Span<QM31>>>,
        random_coeff: QM31,
    ) {
        // 1) Build public samples.
        let (base_samples, inter_samples) = sample_address_to_id_public_polys(self, point);

        // Convert public samples to spans-of-spans.
        let mut base_spans: Array<Span<QM31>> = array![];
        for vals in base_samples.span() { base_spans.append(vals.span()); }
        let mut inter_spans: Array<Span<QM31>> = array![];
        for vals in inter_samples.span() { inter_spans.append(vals.span()); }

        // Empty preprocessed mask values.
        let mut empty_pre_cols_arrays: Array<Array<QM31>> = array![];
        for _ in PREPROCESSED_COLUMNS.span() { empty_pre_cols_arrays.append(array![]); }
        let mut empty_pre_cols: Array<Span<QM31>> = array![];
        for arr in empty_pre_cols_arrays.span() { empty_pre_cols.append(arr.span()); }
        let mut preprocessed_mask_values_dummy =
            PreprocessedMaskValuesImpl::new(empty_pre_cols.span(), PREPROCESSED_COLUMNS.span());

        // 2) Evaluate OODS using public samples.
        let mut preimage_sum: QM31 = Zero::zero();
        let mut base_spans_span = base_spans.span();
        let mut inter_spans_span = inter_spans.span();
        self.memory_address_to_id.evaluate_constraints_at_point(
            ref preimage_sum,
            ref preprocessed_mask_values_dummy,
            ref base_spans_span,
            ref inter_spans_span,
            random_coeff,
            point,
        );

        // 3) Slice proof values to this component using mask_points order up to this component.
        let [
            _pre_mask,
            mut trace_mask_values,
            mut interaction_mask_values,
            _composition_mask,
        ]: [ColumnSpan<Span<QM31>>; 4] = (*mask_values.try_into().unwrap()).unbox();

        let mut set: PreprocessedColumnSet = Default::default();
        let mut t_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut i_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut skip_t: usize = 0;
        let mut skip_i: usize = 0;

        // opcodes
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.opcodes.mask_points(ref set, ref t_points, ref i_points, point);
        let mut d_t = t_points.len() - skip_t;
        let mut d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // verify_instruction
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.verify_instruction.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // blake_context
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.blake_context.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        for _ in 0..d_t { let _ = trace_mask_values.pop_front().unwrap(); }
        for _ in 0..d_i { let _ = interaction_mask_values.pop_front().unwrap(); }

        // memory_address_to_id
        skip_t = t_points.len();
        skip_i = i_points.len();
        self.memory_address_to_id.mask_points(ref set, ref t_points, ref i_points, point);
        d_t = t_points.len() - skip_t;
        d_i = i_points.len() - skip_i;
        let mut trace_comp_vals: Array<Span<QM31>> = array![];
        let mut inter_comp_vals: Array<Span<QM31>> = array![];
        for _ in 0..d_t { trace_comp_vals.append(*trace_mask_values.pop_front().unwrap()); }
        for _ in 0..d_i { inter_comp_vals.append(*interaction_mask_values.pop_front().unwrap()); }

        // Evaluate proof OODS for this component using proof-provided values.
        let mut proof_sum: QM31 = Zero::zero();
        let mut trace_comp_vals_span = trace_comp_vals.span();
        let mut inter_comp_vals_span = inter_comp_vals.span();
        self.memory_address_to_id.evaluate_constraints_at_point(
            ref proof_sum,
            ref preprocessed_mask_values_dummy,
            ref trace_comp_vals_span,
            ref inter_comp_vals_span,
            random_coeff,
            point,
        );

        assert!(
            preimage_sum == proof_sum,
            "{}",
            stwo_verifier_core::verifier::VerificationError::OodsNotMatching,
        );
    }
}


fn preprocessed_trace_mask_points(
    preprocessed_column_set: PreprocessedColumnSet, point: CirclePoint<QM31>,
) -> ColumnArray<Array<CirclePoint<QM31>>> {
    let mut mask_points = array![];

    let PreprocessedColumnSet { values: original_values, mut contains } = preprocessed_column_set;

    for preprocessed_column in PREPROCESSED_COLUMNS.span() {
        let preprocessed_column_key = PreprocessedColumnKey::encode(preprocessed_column);

        if contains.get(preprocessed_column_key) {
            mask_points.append(array![point]);
            // Remove the item from the set.
            contains.insert(preprocessed_column_key, false);
        } else {
            mask_points.append(array![]);
        }
    }

    // Sanity check all the original values have been handled.
    for value in original_values {
        let column_key = PreprocessedColumnKey::encode(@value);
        assert!(!contains.get(column_key));
    }

    mask_points
}

// Public-polys sampling helpers (not part of the Air trait)
fn sample_address_to_id_public_polys(
    air: @CairoAir, point: CirclePoint<QM31>,
) -> (ColumnArray<Array<QM31>>, ColumnArray<Array<QM31>>) {
    let mut preprocessed_column_set: PreprocessedColumnSet = Default::default();
    let mut trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
    let mut interaction_trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
    air.memory_address_to_id
        .mask_points(
            ref preprocessed_column_set,
            ref trace_mask_points,
            ref interaction_trace_mask_points,
            point,
        );

    let log_size = *air.memory_address_to_id.claim.log_size;

    // Base (trace) columns.
    let mut base_samples: ColumnArray<Array<QM31>> = array![];
    let base_len = air.memory_poly_coeffs.memory_address_to_id_base_poly_coeffs.len();
    assert!(base_len == trace_mask_points.len());
    for i in 0..base_len {
        let coeffs = air.memory_poly_coeffs.memory_address_to_id_base_poly_coeffs[i];
        let points = trace_mask_points[i];
        let mut values: Array<QM31> = array![];
        let n_pts = points.len();
        for j in 0..n_pts {
            let p = *points[j];
            values.append(circle_eval_at_point(coeffs, log_size, p));
        }
        base_samples.append(values);
    }

    // Interaction columns.
    let mut inter_samples: ColumnArray<Array<QM31>> = array![];
    let inter_len = air
        .memory_poly_coeffs
        .memory_address_to_id_interaction_poly_coeffs
        .len();
    assert!(inter_len == interaction_trace_mask_points.len());
    for i in 0..inter_len {
        let coeffs = air.memory_poly_coeffs.memory_address_to_id_interaction_poly_coeffs[i];
        let points = interaction_trace_mask_points[i];
        let mut values: Array<QM31> = array![];
        let n_pts = points.len();
        for j in 0..n_pts {
            let p = *points[j];
            values.append(circle_eval_at_point(coeffs, log_size, p));
        }
        inter_samples.append(values);
    }

    (base_samples, inter_samples)
}

fn sample_id_to_big_public_polys(
    air: @CairoAir, point: CirclePoint<QM31>,
) -> (
    Array<ColumnArray<Array<QM31>>>,
    Array<ColumnArray<Array<QM31>>>,
    ColumnArray<Array<QM31>>,
    ColumnArray<Array<QM31>>,
) {
    let (big_components, small_component) = air.memory_id_to_value;

    let mut big_base_samples_all: Array<ColumnArray<Array<QM31>>> = array![];
    let mut big_inter_samples_all: Array<ColumnArray<Array<QM31>>> = array![];

    let big_base_coeffs_all = air
        .memory_poly_coeffs
        .memory_id_to_big_base_poly_coeffs_big
        .span();
    let big_inter_coeffs_all = air
        .memory_poly_coeffs
        .memory_id_to_big_interaction_poly_coeffs_big
        .span();

    assert!(big_base_coeffs_all.len() == big_components.len());
    assert!(big_inter_coeffs_all.len() == big_components.len());

    let mut i: usize = 0;
    for big_comp in big_components.span() {
        let mut preprocessed_column_set: PreprocessedColumnSet = Default::default();
        let mut trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        let mut interaction_trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
        big_comp.mask_points(
            ref preprocessed_column_set,
            ref trace_mask_points,
            ref interaction_trace_mask_points,
            point,
        );

        let log_size = *big_comp.log_n_rows;

        // Base columns for this big component.
        let mut base_samples: ColumnArray<Array<QM31>> = array![];
        let base_coeffs = big_base_coeffs_all[i];
        assert!(base_coeffs.len() == trace_mask_points.len());
        for j in 0..base_coeffs.len() {
            let coeffs = base_coeffs[j];
            let points = trace_mask_points[j];
            let mut values: Array<QM31> = array![];
            let n_pts = points.len();
            for k in 0..n_pts {
                let p = *points[k];
                values.append(circle_eval_at_point(coeffs, log_size, p));
            }
            base_samples.append(values);
        }

        // Interaction columns for this big component.
        let mut inter_samples: ColumnArray<Array<QM31>> = array![];
        let inter_coeffs = big_inter_coeffs_all[i];
        assert!(inter_coeffs.len() == interaction_trace_mask_points.len());
        for j in 0..inter_coeffs.len() {
            let coeffs = inter_coeffs[j];
            let points = interaction_trace_mask_points[j];
            let mut values: Array<QM31> = array![];
            let n_pts = points.len();
            for k in 0..n_pts {
                let p = *points[k];
                values.append(circle_eval_at_point(coeffs, log_size, p));
            }
            inter_samples.append(values);
        }

        big_base_samples_all.append(base_samples);
        big_inter_samples_all.append(inter_samples);
        i += 1_usize;
    }

    // Small component: single set of base and interaction columns.
    let mut preprocessed_column_set: PreprocessedColumnSet = Default::default();
    let mut trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
    let mut interaction_trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>> = array![];
    small_component.mask_points(
        ref preprocessed_column_set,
        ref trace_mask_points,
        ref interaction_trace_mask_points,
        point,
    );

    let small_log_size = *small_component.log_n_rows;

    // Base columns for small component.
    let mut small_base_samples: ColumnArray<Array<QM31>> = array![];
    let small_base_coeffs = air
        .memory_poly_coeffs
        .memory_id_to_big_base_poly_coeffs_small
        .span();
    assert!(small_base_coeffs.len() == trace_mask_points.len());
    for j in 0..small_base_coeffs.len() {
        let coeffs = small_base_coeffs[j];
        let points = trace_mask_points[j];
        let mut values: Array<QM31> = array![];
        let n_pts = points.len();
        for k in 0..n_pts {
            let p = *points[k];
            values.append(circle_eval_at_point(coeffs, small_log_size, p));
        }
        small_base_samples.append(values);
    }

    // Interaction columns for small component.
    let mut small_inter_samples: ColumnArray<Array<QM31>> = array![];
    let small_inter_coeffs = air
        .memory_poly_coeffs
        .memory_id_to_big_interaction_poly_coeffs_small
        .span();
    assert!(small_inter_coeffs.len() == interaction_trace_mask_points.len());
    for j in 0..small_inter_coeffs.len() {
        let coeffs = small_inter_coeffs[j];
        let points = interaction_trace_mask_points[j];
        let mut values: Array<QM31> = array![];
        let n_pts = points.len();
        for k in 0..n_pts {
            let p = *points[k];
            values.append(circle_eval_at_point(coeffs, small_log_size, p));
        }
        small_inter_samples.append(values);
    }

    (big_base_samples_all, big_inter_samples_all, small_base_samples, small_inter_samples)
}
