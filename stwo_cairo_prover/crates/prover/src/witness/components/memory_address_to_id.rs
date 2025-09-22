use std::ops::Index;

use cairo_air::components::memory_address_to_id::{
    Claim, InteractionClaim, MEMORY_ADDRESS_TO_ID_SPLIT, N_ID_AND_MULT_COLUMNS_PER_CHUNK,
    N_TRACE_COLUMNS,
};
use cairo_air::relations;
use itertools::{izip, Itertools};
use num_traits::{One, Zero};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use stwo::core::fields::m31::{BaseField, M31};
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::m31::{PackedBaseField, PackedM31, LOG_N_LANES, N_LANES};
use stwo::prover::backend::simd::qm31::PackedQM31;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_cairo_adapter::memory::Memory;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::Seq;
use stwo_constraint_framework::{LogupTraceGenerator, Relation};

use crate::witness::components::range_check_19;
use crate::witness::utils::{AtomicMultiplicityColumn, Enabler, TreeBuilder};

pub type InputType = M31;
pub type PackedInputType = PackedM31;

/// A struct that represents a mapping from Address to ID. Zero address is not allowed.
pub struct AddressToId {
    /// Since zero address is reserved, the vector holding the data is offset by 1, i.e. the ID of
    /// address 1 is stored at index 0, and so on.
    data: Vec<u32>,
}
impl AddressToId {
    pub fn new(data: Vec<u32>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn resize(&mut self, new_len: usize, value: u32) {
        self.data.resize(new_len, value);
    }

    pub fn array_chunks<const N: usize>(&self) -> impl Iterator<Item = &[u32; N]> {
        self.data.array_chunks::<N>()
    }
}

impl Index<usize> for AddressToId {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index - 1]
    }
}

/// A struct to generate the memory address to ID trace.
pub struct ClaimGenerator {
    address_to_raw_id: AddressToId,
    multiplicities: AtomicMultiplicityColumn,
}
impl ClaimGenerator {
    pub fn new(memory: &Memory) -> Self {
        // Note that while `memory.address_to_id` starts from address 0, the memory component can
        // only yield addresses starting from 1.
        let address_to_raw_id = AddressToId::new(
            (1..memory.address_to_id.len())
                .map(|addr| memory.get_raw_id(addr as u32))
                .collect_vec(),
        );
        let multiplicities = AtomicMultiplicityColumn::new(address_to_raw_id.len());

        Self {
            address_to_raw_id,
            multiplicities,
        }
    }

    pub fn deduce_output(&self, input: PackedBaseField) -> PackedBaseField {
        let indices = input.to_array().map(|i| i.0);
        let memory_ids = std::array::from_fn(|j| self.get_id(M31(indices[j])));
        PackedBaseField::from_array(memory_ids)
    }

    pub fn get_id(&self, input: BaseField) -> M31 {
        M31(self.address_to_raw_id[input.0 as usize])
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

    pub fn add_packed_m31(&self, inputs: &PackedBaseField) {
        let addresses = inputs.to_array();
        for address in addresses {
            self.add_input(&address);
        }
    }

    pub fn add_input(&self, addr: &BaseField) {
        // Addresses are offset by 1.
        self.multiplicities.increase_at(addr.0 - 1);
    }

    pub fn write_trace(
        mut self,
        range_check_19_trace_generator: &range_check_19::ClaimGenerator,
        tree_builder: &mut impl TreeBuilder<SimdBackend>,
    ) -> (Claim, InteractionClaimGenerator) {
        // Convert multiplicities into packed vectors.
        let multiplicities_packed: Vec<PackedM31> = self.multiplicities.into_simd_vec();

        // Pad to a multiple of `N_LANES` to align addresses and IDs.
        let next_multiple_of_16 = self.address_to_raw_id.len().next_multiple_of(N_LANES);
        self.address_to_raw_id.resize(next_multiple_of_16, 0);

        // Repack only non-zero lanes contiguously into new packed vectors.
        let mut ids_used: Vec<PackedM31> = Vec::new();
        let mut mults_used: Vec<PackedM31> = Vec::new();
        let mut addrs_used: Vec<PackedM31> = Vec::new();

        let mut addr_buf = [M31::zero(); N_LANES];
        let mut ids_buf = [M31::zero(); N_LANES];
        let mut mult_buf = [M31::zero(); N_LANES];
        let mut buf_count = 0usize;
        let mut last_current_address = M31::zero();

        for (pack_idx, mult_pack) in multiplicities_packed.iter().enumerate() {
            let mult_arr = mult_pack.to_array();
            for lane in 0..N_LANES {
                let global_idx = pack_idx * N_LANES + lane;
                let m = mult_arr[lane].0;
                if m == 0 {
                    continue;
                }
                addr_buf[buf_count] = M31(global_idx as u32 + 1); // addresses are offset by 1.
                                                                  // AddressToId expects 1-based address in its Index impl.
                ids_buf[buf_count] = M31(self.address_to_raw_id[global_idx + 1]);
                mult_buf[buf_count] = M31(m);
                last_current_address = addr_buf[buf_count];
                buf_count += 1;

                if buf_count == N_LANES {
                    // Flush a full packed row.
                    addrs_used.push(PackedM31::from_array(addr_buf));
                    ids_used.push(PackedM31::from_array(ids_buf));
                    mults_used.push(PackedM31::from_array(mult_buf));

                    addr_buf = [M31::zero(); N_LANES];
                    ids_buf = [M31::zero(); N_LANES];
                    mult_buf = [M31::zero(); N_LANES];
                    buf_count = 0;
                }
            }
        }

        // Must add an enabler to do the range_check
        let n_rows = addrs_used.len() * N_LANES + buf_count;
        let enabler_col = Enabler::new(n_rows);

        if buf_count > 0 {
            // Flush the final partial packed row (padded with zeros).
            ids_used.push(PackedM31::from_array(ids_buf));
            mults_used.push(PackedM31::from_array(mult_buf));
            addrs_used.push(PackedM31::from_array(addr_buf));
        }

        // Compute trace size: proportional to used packed rows across splits, at least N_LANES.
        let used_packed = ids_used.len();
        let n_used = used_packed * N_LANES;
        let size = std::cmp::max(
            (n_used / MEMORY_ADDRESS_TO_ID_SPLIT).next_power_of_two(),
            N_LANES,
        );
        let n_packed_rows = size.div_ceil(N_LANES);

        let mut trace: [_; N_TRACE_COLUMNS] =
            std::array::from_fn(|_| Col::<SimdBackend, M31>::zeros(size));

        // Compute prev_address as a global shift of the addresses by 1, with the very first entry defaulting to 0.
        let mut prev_addrs_used: Vec<PackedM31> = Vec::with_capacity(addrs_used.len());
        for (i, addr_pack) in addrs_used.iter().enumerate() {
            let curr_arr = addr_pack.to_array();
            let mut prev_arr = [M31::zero(); N_LANES];
            // Shift within the pack.
            for lane in 1..N_LANES {
                prev_arr[lane] = curr_arr[lane - 1];
            }
            // The first lane depends on the previous pack's last lane, or zero if this is the very first entry.
            if i > 0 {
                prev_arr[0] = addrs_used[i - 1].to_array()[N_LANES - 1];
            } else {
                prev_arr[0] = M31::zero();
            }
            // If this is the last packed row and there is padding inside it, zero-out the
            // first padded lane's prev-address to avoid enforcing prev > 0 with curr = 0.
            let first_padding_lane = n_rows % N_LANES;
            if i == addrs_used.len() - 1 && first_padding_lane != 0 {
                prev_arr[first_padding_lane] = M31::zero();
            }
            prev_addrs_used.push(PackedM31::from_array(prev_arr));
        }

        // Commit only used memory to the trace.
        for (i, (prev_address, address, id, multiplicity)) in
            izip!(&prev_addrs_used, &addrs_used, &ids_used, &mults_used)
                .into_iter()
                .enumerate()
        {
            let chunk_idx = i / n_packed_rows;
            let row = i % n_packed_rows;
            trace[chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = enabler_col.packed_at(i);
            trace[1 + chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = prev_address.clone();
            trace[2 + chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = address.clone();
            trace[3 + chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = id.clone();
            trace[4 + chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = multiplicity.clone();
        }

        // Lookup data.
        let prev_addresses: [_; MEMORY_ADDRESS_TO_ID_SPLIT] =
            std::array::from_fn(|i| trace[1 + i * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data.clone());
        let addresses: [_; MEMORY_ADDRESS_TO_ID_SPLIT] =
            std::array::from_fn(|i| trace[2 + i * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data.clone());
        let ids: [_; MEMORY_ADDRESS_TO_ID_SPLIT] =
            std::array::from_fn(|i| trace[3 + i * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data.clone());
        let multiplicities: [_; MEMORY_ADDRESS_TO_ID_SPLIT] =
            std::array::from_fn(|i| trace[4 + i * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data.clone());

        // Add inputs to range check that the address is strictly increasing for all rows,
        // including padded rows (which contribute zeros).
        for (i, (prev_addr, addr)) in izip!(&prev_addrs_used, &addrs_used).into_iter().enumerate() {
            let enabler = enabler_col.packed_at(i);
            let diff = (*addr) - (*prev_addr) - enabler;
            range_check_19_trace_generator.add_packed_m31(&[diff]);
        }
        // Pad RC19 multiplicities with zeros for remaining packed rows across all splits.
        let total_packed_rows = MEMORY_ADDRESS_TO_ID_SPLIT * n_packed_rows;
        for _i in addrs_used.len()..total_packed_rows {
            range_check_19_trace_generator.add_packed_m31(&[PackedM31::zero()]);
        }

        // Commit on trace.
        let log_size = size.checked_ilog2().unwrap();
        let domain = CanonicCoset::new(log_size).circle_domain();
        let trace = trace
            .into_iter()
            .map(|eval| {
                CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(domain, eval)
            })
            .collect_vec();
        tree_builder.extend_evals(trace);

        (
            Claim { log_size },
            InteractionClaimGenerator {
                n_rows,
                last_current_address,
                prev_addresses,
                addresses,
                ids,
                multiplicities,
            },
        )
    }
}

pub struct InteractionClaimGenerator {
    pub n_rows: usize,
    pub last_current_address: M31,
    pub prev_addresses: [Vec<PackedM31>; MEMORY_ADDRESS_TO_ID_SPLIT],
    pub addresses: [Vec<PackedM31>; MEMORY_ADDRESS_TO_ID_SPLIT],
    pub ids: [Vec<PackedM31>; MEMORY_ADDRESS_TO_ID_SPLIT],
    pub multiplicities: [Vec<PackedM31>; MEMORY_ADDRESS_TO_ID_SPLIT],
}
impl InteractionClaimGenerator {
    pub fn write_interaction_trace(
        self,
        tree_builder: &mut impl TreeBuilder<SimdBackend>,
        lookup_elements: &relations::MemoryAddressToId,
        address_relation: &relations::Address,
        range_check_19_relation: &relations::RangeCheck_19,
    ) -> InteractionClaim {
        let packed_size = self.ids[0].len();
        let log_size = packed_size.ilog2() + LOG_N_LANES;
        let mut logup_gen = LogupTraceGenerator::new(log_size);
        let enabler_col = Enabler::new(self.n_rows);

        // MemoryAddressToId relation (address,id) with multiplicities.
        for (split_idx, (prev_addrs, curr_addrs, ids, mults)) in izip!(
            &self.prev_addresses,
            &self.addresses,
            &self.ids,
            &self.multiplicities
        )
        .enumerate()
        {
            let mut col_gen = logup_gen.new_col();
            (col_gen.par_iter_mut(), prev_addrs, curr_addrs, ids, mults)
                .into_par_iter()
                .enumerate()
                .for_each(|(i, (writer, &prev_addr, &curr_addr, &id, &mult))| {
                    let global_i = split_idx * packed_size + i;
                    let enabler = PackedQM31::from(enabler_col.packed_at(global_i));
                    let p0: PackedQM31 = lookup_elements.combine(&[curr_addr, id]);
                    let p1: PackedQM31 = address_relation.combine(&[prev_addr]);
                    writer.write_frac(p0 * (-enabler) + p1 * (-mult), p1 * p0);
                });
            col_gen.finalize_col();

            let mut col_gen = logup_gen.new_col();
            (col_gen.par_iter_mut(), prev_addrs, curr_addrs)
                .into_par_iter()
                .enumerate()
                .for_each(|(i, (writer, &prev_addr, &curr_addr))| {
                    let one = PackedQM31::one();
                    let global_i = split_idx * packed_size + i;
                    let enabler = PackedM31::from(enabler_col.packed_at(global_i));
                    let p0: PackedQM31 = address_relation.combine(&[curr_addr]);
                    let p1: PackedQM31 =
                        range_check_19_relation.combine(&[curr_addr - prev_addr - enabler]);
                    writer.write_frac(p0 * one + p1 * enabler, p0 * p1);
                });
            col_gen.finalize_col();
        }

        let (trace, claimed_sum) = logup_gen.finalize_last();
        tree_builder.extend_evals(trace);

        InteractionClaim { claimed_sum }
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use stwo::core::fields::m31::{BaseField, M31};
    use stwo_cairo_adapter::memory::{MemoryBuilder, MemoryConfig, MemoryEntry};

    use crate::witness::components::memory_address_to_id;

    #[test]
    fn test_memory_multiplicities() {
        const N_ENTRIES: u32 = 10;
        let (memory, ..) = MemoryBuilder::from_iter(
            MemoryConfig::default(),
            (0..N_ENTRIES).map(|i| MemoryEntry {
                address: i as u64,
                value: [i; 8],
            }),
        )
        .build();
        let memory_address_to_id_gen = memory_address_to_id::ClaimGenerator::new(&memory);
        let address_usages = [1, 1, 2, 2, 2, 3]
            .into_iter()
            .map(BaseField::from)
            .collect_vec();
        // Multiplicities are of addresses offsetted by 1.
        let expected_mults = [2, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].map(M31);

        address_usages.iter().for_each(|addr| {
            memory_address_to_id_gen.add_input(addr);
        });
        let actual_mults = memory_address_to_id_gen.multiplicities.into_simd_vec();

        assert_eq!(actual_mults.len(), 1);
        assert_eq!(actual_mults[0].to_array(), expected_mults);
    }
}
