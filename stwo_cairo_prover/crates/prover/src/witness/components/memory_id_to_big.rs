use std::simd::Simd;

use itertools::{chain, Itertools};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use stwo_cairo_adapter::memory::{
    u128_to_4_limbs, EncodedMemoryValueId, Memory, MemoryValueId, LARGE_MEMORY_VALUE_ID_BASE,
};
use stwo_cairo_common::memory::{N_M31_IN_FELT252, N_M31_IN_SMALL_FELT252};
use stwo_cairo_common::prover_types::felt::split_f252_simd;
use stwo_cairo_common::prover_types::simd::PackedFelt252;

use crate::witness::prelude::*;
use crate::witness::utils::AtomicMultiplicityColumn;

pub type InputType = M31;
pub type PackedInputType = PackedM31;

/// Generates the trace and the claim for the id -> f252 memory table.
/// Generates 2 table, one for large values and one for small values. A large value is a full 28
/// limb Felt252. The small values are currently 8 limbs, for a maximum of 72 bits.
/// The separation is done to reduce zeroed out ('unused') trace cells.
pub struct ClaimGenerator {
    big_values: Vec<[u32; 8]>,
    big_mults: AtomicMultiplicityColumn,
    small_values: Vec<u128>,
    small_mults: AtomicMultiplicityColumn,
}
impl ClaimGenerator {
    pub fn new(mem: &Memory) -> Self {
        let mut big_values = mem.f252_values.clone();
        let simd_padded_big_size = big_values.len().next_multiple_of(N_LANES);
        big_values.resize(simd_padded_big_size, [0; 8]);
        let big_mults = AtomicMultiplicityColumn::new(simd_padded_big_size);

        let mut small_values = mem.small_values.clone();
        let simd_padded_small_size = small_values.len().next_multiple_of(N_LANES);
        small_values.resize(simd_padded_small_size, 0);
        let small_mults = AtomicMultiplicityColumn::new(simd_padded_small_size);

        Self {
            small_values,
            big_values,
            small_mults,
            big_mults,
        }
    }

    pub fn deduce_output(&self, ids: PackedM31) -> PackedFelt252 {
        let values = std::array::from_fn(|j| {
            Simd::from_array(
                ids.to_array()
                    .map(|M31(i)| match EncodedMemoryValueId(i).decode() {
                        MemoryValueId::F252(id) => self.big_values[id as usize][j],
                        MemoryValueId::Small(id) => {
                            if j >= 4 {
                                0
                            } else {
                                let small = self.small_values[id as usize];
                                u128_to_4_limbs(small)[j]
                            }
                        }
                        MemoryValueId::Empty => {
                            panic!("Attempted deduce_output on empty memory cell.")
                        }
                    }),
            )
        });

        PackedFelt252 {
            value: split_f252_simd(values),
        }
    }

    pub fn add_inputs(&self, inputs: &[InputType]) {
        for input in inputs {
            self.add_input(input);
        }
    }

    pub fn add_packed_inputs(&self, inputs: &[PackedInputType]) {
        inputs.into_par_iter().for_each(|input| {
            self.add_packed_m31(input);
        });
    }

    pub fn add_packed_m31(&self, inputs: &PackedM31) {
        let memory_ids = inputs.to_array();
        for memory_id in memory_ids {
            self.add_input(&memory_id);
        }
    }

    pub fn add_input(&self, encoded_memory_id: &M31) {
        match EncodedMemoryValueId(encoded_memory_id.0).decode() {
            MemoryValueId::F252(id) => {
                self.big_mults.increase_at(id);
            }
            MemoryValueId::Small(id) => {
                self.small_mults.increase_at(id);
            }
            MemoryValueId::Empty => panic!("Attempted add_input on empty memory cell."),
        }
    }

    pub fn write_trace(self, log_max_big_size: u32) -> InteractionClaimGenerator {
        // 1) Filter out zero-multiplicity entries up front and generate IDs.
        let (big_values_filtered, big_mults_packed, big_ids_packed) =
            filter_big_inputs(self.big_values, self.big_mults.into_simd_vec());
        let (small_values_filtered, small_mults_packed, small_ids_packed) =
            filter_small_inputs(self.small_values, self.small_mults.into_simd_vec());

        // 2) Generate traces from filtered inputs.
        let big_table_traces = gen_big_memory_traces(
            big_values_filtered,
            big_mults_packed,
            big_ids_packed.clone(),
            log_max_big_size,
        );
        let small_table_trace = gen_small_memory_trace(
            small_values_filtered,
            small_mults_packed,
            small_ids_packed.clone(),
        );

        // Lookup data.
        let big_components_values: Vec<[_; N_M31_IN_FELT252]> = big_table_traces
            .iter()
            .map(|trace| std::array::from_fn(|i| trace[i].data.clone()))
            .collect_vec();
        let big_multiplicities = big_table_traces
            .iter()
            .map(|trace| trace.last().unwrap().data.clone())
            .collect_vec();
        let big_ids: Vec<Vec<PackedM31>> = big_table_traces
            .iter()
            .map(|trace| trace[N_M31_IN_FELT252].data.clone())
            .collect_vec();

        let small_values: [_; N_M31_IN_SMALL_FELT252] =
            std::array::from_fn(|i| small_table_trace[i].data.clone());
        let small_multiplicities = small_table_trace.last().unwrap().data.clone();
        let small_ids = small_table_trace[N_M31_IN_SMALL_FELT252].data.clone();

        InteractionClaimGenerator {
            big_components_values,
            big_multiplicities,
            big_ids,
            small_values,
            small_multiplicities,
            small_ids,
        }
    }
}

// Filters big memory inputs by removing lanes with zero multiplicity, padding to N_LANES, and
// returns (filtered_values, packed_multiplicities, packed_ids).
fn filter_big_inputs(
    values: Vec<[u32; 8]>,
    mults_simd: Vec<PackedM31>,
) -> (Vec<[u32; 8]>, Vec<PackedM31>, Vec<PackedM31>) {
    let mut filtered_values: Vec<[u32; 8]> = Vec::new();
    let mut mults_flat: Vec<u32> = Vec::new();
    let mut ids_flat: Vec<u32> = Vec::new();

    for (pack_idx, mult_pack) in mults_simd.iter().enumerate() {
        let mult_arr = mult_pack.to_array();
        for lane in 0..N_LANES {
            let m = mult_arr[lane].0;
            if m == 0 {
                continue;
            }
            let idx = pack_idx * N_LANES + lane;
            filtered_values.push(values[idx]);
            mults_flat.push(m);
            ids_flat.push(LARGE_MEMORY_VALUE_ID_BASE | (idx as u32));
        }
    }

    let rem = filtered_values.len() % N_LANES;
    if rem != 0 {
        let pad = N_LANES - rem;
        filtered_values.extend(std::iter::repeat([0; 8]).take(pad));
        mults_flat.extend(std::iter::repeat(0).take(pad));
        ids_flat.extend(std::iter::repeat(0).take(pad));
    }

    let pack_u32s = |flat: Vec<u32>| -> Vec<PackedM31> {
        flat.chunks_exact(N_LANES)
            .map(|chunk| {
                let arr: [M31; N_LANES] = std::array::from_fn(|i| M31(chunk[i]));
                PackedM31::from_array(arr)
            })
            .collect()
    };

    let mults_packed = pack_u32s(mults_flat);
    let ids_packed = pack_u32s(ids_flat);

    (filtered_values, mults_packed, ids_packed)
}

// Filters small memory inputs by removing lanes with zero multiplicity, padding to N_LANES, and
// returns (filtered_values, packed_multiplicities, packed_ids).
fn filter_small_inputs(
    values: Vec<u128>,
    mults_simd: Vec<PackedM31>,
) -> (Vec<u128>, Vec<PackedM31>, Vec<PackedM31>) {
    let mut filtered_values: Vec<u128> = Vec::new();
    let mut mults_flat: Vec<u32> = Vec::new();
    let mut ids_flat: Vec<u32> = Vec::new();

    for (pack_idx, mult_pack) in mults_simd.iter().enumerate() {
        let mult_arr = mult_pack.to_array();
        for lane in 0..N_LANES {
            let m = mult_arr[lane].0;
            if m == 0 {
                continue;
            }
            let idx = pack_idx * N_LANES + lane;
            filtered_values.push(values[idx]);
            mults_flat.push(m);
            ids_flat.push(idx as u32);
        }
    }

    let rem = filtered_values.len() % N_LANES;
    if rem != 0 {
        let pad = N_LANES - rem;
        filtered_values.extend(std::iter::repeat(0).take(pad));
        mults_flat.extend(std::iter::repeat(0).take(pad));
        ids_flat.extend(std::iter::repeat(0).take(pad));
    }

    let pack_u32s = |flat: Vec<u32>| -> Vec<PackedM31> {
        flat.chunks_exact(N_LANES)
            .map(|chunk| {
                let arr: [M31; N_LANES] = std::array::from_fn(|i| M31(chunk[i]));
                PackedM31::from_array(arr)
            })
            .collect()
    };

    let mults_packed = pack_u32s(mults_flat);
    let ids_packed = pack_u32s(ids_flat);

    (filtered_values, mults_packed, ids_packed)
}

/// Generates the trace for the id -> f252 `big` tables. Splits the table to multiple traces
/// according to `log_max_big_size`.
fn gen_big_memory_traces(
    values: Vec<[u32; 8]>,
    mults: Vec<PackedM31>,
    ids: Vec<PackedM31>,
    log_max_big_size: u32,
) -> Vec<Vec<BaseColumn>> {
    assert!(log_max_big_size >= LOG_N_LANES);
    let max_big_size = 1 << log_max_big_size;
    assert_eq!(values.len() / N_LANES, mults.len());
    let mut traces = vec![];

    let packs_per_chunk = max_big_size / N_LANES;
    for ((values, mults), ids) in values
        .chunks(max_big_size)
        .zip(mults.chunks(packs_per_chunk))
        .zip(ids.chunks(packs_per_chunk))
    {
        let trace = gen_single_big_memory_trace(values, mults, ids);
        traces.push(trace);
    }

    traces
}

// Generates the trace of the large value memory table.
fn gen_single_big_memory_trace(
    values: &[[u32; 8]],
    mults: &[PackedM31],
    ids: &[PackedM31],
) -> Vec<BaseColumn> {
    assert_eq!(values.len(), mults.len() * N_LANES);
    let column_length = values.len().next_power_of_two();

    let mut mults = mults.to_vec();
    mults.resize(column_length / N_LANES, PackedM31::zero());
    let multiplicities = BaseColumn::from_simd(mults);
    // IDs column
    let mut ids_vec = ids.to_vec();
    ids_vec.resize(column_length / N_LANES, PackedM31::zero());
    let ids_col = BaseColumn::from_simd(ids_vec);

    let packed_values = values
        .iter()
        .chain(std::iter::repeat(&[0; 8]))
        .take(column_length)
        .array_chunks::<N_LANES>()
        .map(|chunk| {
            std::array::from_fn(|i| Simd::from_array(std::array::from_fn(|j| chunk[j][i])))
        })
        .collect_vec();

    let mut value_trace =
        std::iter::repeat_with(|| unsafe { BaseColumn::uninitialized(column_length) })
            .take(N_M31_IN_FELT252)
            .collect_vec();
    for (i, values) in packed_values.iter().enumerate() {
        let values = split_f252_simd(*values);
        for (j, value) in values.iter().enumerate() {
            value_trace[j].data[i] = *value;
        }
    }

    chain!(value_trace, [ids_col, multiplicities]).collect_vec()
}

// Generates the trace of the small value memory table.
fn gen_small_memory_trace(
    values: Vec<u128>,
    mut mults: Vec<PackedM31>,
    mut ids: Vec<PackedM31>,
) -> Vec<BaseColumn> {
    assert_eq!(values.len(), mults.len() * N_LANES);
    let column_length = values.len().next_power_of_two();

    mults.resize(column_length / N_LANES, PackedM31::zero());
    let multiplicities = BaseColumn::from_simd(mults);
    ids.resize(column_length / N_LANES, PackedM31::zero());
    let ids_col = BaseColumn::from_simd(ids);

    let packed_values: Vec<[Simd<u32, N_LANES>; 4]> = values
        .into_iter()
        .chain(std::iter::repeat(0))
        .take(column_length)
        .map(u128_to_4_limbs)
        .array_chunks::<N_LANES>()
        .map(|chunk| {
            std::array::from_fn(|i| Simd::from_array(std::array::from_fn(|j| chunk[j][i])))
        })
        .collect_vec();

    let mut values_trace =
        std::iter::repeat_with(|| unsafe { BaseColumn::uninitialized(column_length) })
            .take(N_M31_IN_SMALL_FELT252)
            .collect_vec();
    for (i, values) in packed_values.iter().enumerate() {
        let values = split_f252_simd([
            values[0],
            values[1],
            values[2],
            values[3],
            Simd::splat(0),
            Simd::splat(0),
            Simd::splat(0),
            Simd::splat(0),
        ]);
        for (j, value) in values[..N_M31_IN_SMALL_FELT252].iter().enumerate() {
            values_trace[j].data[i] = *value;
        }
    }

    chain!(values_trace, [ids_col, multiplicities]).collect_vec()
}

#[derive(Debug)]
pub struct InteractionClaimGenerator {
    pub big_components_values: Vec<[Vec<PackedM31>; N_M31_IN_FELT252]>,
    pub big_multiplicities: Vec<Vec<PackedM31>>,
    pub big_ids: Vec<Vec<PackedM31>>,
    pub small_values: [Vec<PackedM31>; N_M31_IN_SMALL_FELT252],
    pub small_multiplicities: Vec<PackedM31>,
    pub small_ids: Vec<PackedM31>,
}
