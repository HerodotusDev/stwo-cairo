use crate::prelude::*;
use super::{MEMORY_ADDRESS_TO_ID_SPLIT, N_INTERACTION_TRACE_QM31_COLUMNS};

pub fn mask_points(
    ref preprocessed_column_set: PreprocessedColumnSet,
    ref trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>>,
    ref interaction_trace_mask_points: ColumnArray<Array<CirclePoint<QM31>>>,
    point: CirclePoint<QM31>,
    trace_gen: CirclePointIndex,
    log_size: u32,
) {
    let point_offset_neg_1 = point.add_circle_point_m31(-trace_gen.mul(1).to_point());

    // For each split: enabler, prev_address, curr_address, id, multiplicity.
    for _ in 0..MEMORY_ADDRESS_TO_ID_SPLIT {
        trace_mask_points.append(array![point]);
        trace_mask_points.append(array![point]);
        trace_mask_points.append(array![point]);
        trace_mask_points.append(array![point]);
        trace_mask_points.append(array![point]);
    }

    for _ in 0..N_INTERACTION_TRACE_QM31_COLUMNS - 1 {
        // Each QM31 column is implemented as 4 M31 columns.
        interaction_trace_mask_points.append(array![point]);
        interaction_trace_mask_points.append(array![point]);
        interaction_trace_mask_points.append(array![point]);
        interaction_trace_mask_points.append(array![point]);
    }

    // Final cumulative logup column with neighbor (-1, 0).
    interaction_trace_mask_points.append(array![point_offset_neg_1, point]);
    interaction_trace_mask_points.append(array![point_offset_neg_1, point]);
    interaction_trace_mask_points.append(array![point_offset_neg_1, point]);
    interaction_trace_mask_points.append(array![point_offset_neg_1, point]);
}

#[derive(Drop)]
pub struct ConstraintParams {
    pub lookup_elements: @crate::MemoryAddressToIdElements,
    pub claimed_sum: QM31,
    pub column_size: M31,
    pub address_lookup_elements: @crate::AddressElements,
    pub range_check_19_lookup_elements: @crate::RangeCheck_19Elements,
}

/// Interpret the mask values as a single `QM31` value.
pub fn as_qm31(mask_values: @Box<[Span<QM31>; 4]>) -> QM31 {
    let [column_0, column_1, column_2, column_3]: [Span<QM31>; 4] = mask_values.unbox();

    let [coeff_0]: [QM31; 1] = (*column_0.try_into().unwrap()).unbox();
    let [coeff_1]: [QM31; 1] = (*column_1.try_into().unwrap()).unbox();
    let [coeff_2]: [QM31; 1] = (*column_2.try_into().unwrap()).unbox();
    let [coeff_3]: [QM31; 1] = (*column_3.try_into().unwrap()).unbox();

    QM31Trait::from_partial_evals([coeff_0, coeff_1, coeff_2, coeff_3])
}

/// Interpret the mask values as two neighboring `QM31` values.
pub fn as_neighboring_qm31s(mask_values: @Box<[Span<QM31>; 4]>) -> [QM31; 2] {
    let [column_0, column_1, column_2, column_3]: [Span<QM31>; 4] = mask_values.unbox();

    let [coeff_0_first, coeff_0_second]: [QM31; 2] = (*column_0.try_into().unwrap()).unbox();
    let [coeff_1_first, coeff_1_second]: [QM31; 2] = (*column_1.try_into().unwrap()).unbox();
    let [coeff_2_first, coeff_2_second]: [QM31; 2] = (*column_2.try_into().unwrap()).unbox();
    let [coeff_3_first, coeff_3_second]: [QM31; 2] = (*column_3.try_into().unwrap()).unbox();

    [
        QM31Trait::from_partial_evals([coeff_0_first, coeff_1_first, coeff_2_first, coeff_3_first]),
        QM31Trait::from_partial_evals(
            [coeff_0_second, coeff_1_second, coeff_2_second, coeff_3_second],
        ),
    ]
}

pub fn evaluate_constraints_at_point(
    ref sum: QM31,
    ref trace_mask_values: ColumnSpan<Span<QM31>>,
    ref interaction_mask_values: ColumnSpan<Span<QM31>>,
    params: ConstraintParams,
    random_coeff: QM31,
    domain_vanish_at_point_inv: QM31,
) {
    let ConstraintParams { lookup_elements, claimed_sum, column_size, address_lookup_elements, range_check_19_lookup_elements } = params;
    let column_size: QM31 = column_size.into();

    let mut prev_cum_sum: QM31 = Zero::zero();

    // This loop executes `MEMORY_ADDRESS_TO_ID_SPLIT - 1` iterations, each enforcing the
    // 4 lookup sum constraints.
    for _ in 0..MEMORY_ADDRESS_TO_ID_SPLIT - 1 {
        // Get (enabler, prev_address, curr_address, id, multiplicity) from the trace.
        let [enabler, prev_address, curr_address, id, multiplicity]: [Span<QM31>; 5] = (*trace_mask_values
                .multi_pop_front()
                .unwrap())
                .unbox();
        let [enabler]: [QM31; 1] = (*enabler.try_into().unwrap()).unbox();
        let [prev_address]: [QM31; 1] = (*prev_address.try_into().unwrap()).unbox();
        let [curr_address]: [QM31; 1] = (*curr_address.try_into().unwrap()).unbox();
        let [id]: [QM31; 1] = (*id.try_into().unwrap()).unbox();
        let [multiplicity]: [QM31; 1] = (*multiplicity.try_into().unwrap()).unbox();

        let combination_memory = lookup_elements.combine_qm31([curr_address, id]);
        let combination_prev_address = address_lookup_elements.combine_qm31([prev_address]);
        let combination_curr_address = address_lookup_elements.combine_qm31([curr_address]);
        let combination_range_check = range_check_19_lookup_elements.combine_qm31([curr_address - prev_address - enabler]);

        // Get the corresponding cumulative logup sum from interaction trace. And check that:
        // (current - prev) = (-multiplicity0 / intermediate0) + (-multiplicity1 / intermediate1)
        // = (-multiplicity0 * intermediate1 -multiplicity1 * intermediate0) / (intermediate0 *
        // intermediate1)
        // ==>
        // (current - prev) * (intermediate0 * intermediate1) =
        // -multiplicity0 * intermediate1 - multiplicity1 * intermediate0
        let curr_cum_sum_1 = as_qm31(interaction_mask_values.multi_pop_front::<4>().unwrap());
        let constraint_quotient_1 = ((curr_cum_sum_1 - prev_cum_sum) * combination_memory * combination_prev_address
            + multiplicity * combination_prev_address
            + enabler * combination_memory)
            * domain_vanish_at_point_inv;
        sum = sum * random_coeff + constraint_quotient_1;
        prev_cum_sum = curr_cum_sum_1;

        let curr_cum_sum_2 = as_qm31(interaction_mask_values.multi_pop_front::<4>().unwrap());
        let constraint_quotient_2 = ((curr_cum_sum_2 - prev_cum_sum) * combination_curr_address * combination_range_check
            - enabler * combination_range_check
            - combination_curr_address)
            * domain_vanish_at_point_inv;
        sum = sum * random_coeff + constraint_quotient_2;
        prev_cum_sum = curr_cum_sum_2;
    }

    let [enabler, prev_address, curr_address, id, multiplicity]: [Span<QM31>; 5] = (*trace_mask_values
            .multi_pop_front()
            .unwrap())
            .unbox();
    let [enabler]: [QM31; 1] = (*enabler.try_into().unwrap()).unbox();
    let [prev_address]: [QM31; 1] = (*prev_address.try_into().unwrap()).unbox();
    let [curr_address]: [QM31; 1] = (*curr_address.try_into().unwrap()).unbox();
    let [id]: [QM31; 1] = (*id.try_into().unwrap()).unbox();
    let [multiplicity]: [QM31; 1] = (*multiplicity.try_into().unwrap()).unbox();

    let combination_memory = lookup_elements.combine_qm31([curr_address, id]);
    let combination_prev_address = address_lookup_elements.combine_qm31([prev_address]);
    let combination_curr_address = address_lookup_elements.combine_qm31([curr_address]);
    let combination_range_check = range_check_19_lookup_elements.combine_qm31([curr_address - prev_address - enabler]);

    let curr_cum_sum_1 = as_qm31(interaction_mask_values.multi_pop_front::<4>().unwrap());
    let constraint_quotient_1 = ((curr_cum_sum_1 - prev_cum_sum) * combination_memory * combination_prev_address
        + multiplicity * combination_prev_address
        + enabler * combination_memory)
        * domain_vanish_at_point_inv;
    sum = sum * random_coeff + constraint_quotient_1;
    prev_cum_sum = curr_cum_sum_1;

    // Get the current and previous row's logup sum.
    let [neg_1_cum_sum, curr_cum_sum_2] = as_neighboring_qm31s(
        interaction_mask_values.multi_pop_front::<4>().unwrap(),
    );

    // Final constraint, Check that:
    // (current_cum_sum - prev_cum_sum_2 - neg_1_cum_sum + claimed_sum/column_size) *
    // combination_curr_address*combination_range_check = -enabler * combination_range_check - combination_curr_address
    let constraint_quotient = ((curr_cum_sum_2
        - prev_cum_sum
        - neg_1_cum_sum
        + claimed_sum * column_size.inverse().into())
        * combination_curr_address
        * combination_range_check
        - enabler * combination_range_check
        - combination_curr_address)
        * domain_vanish_at_point_inv;
    sum = sum * random_coeff + constraint_quotient;
}
