use std::ops::Index;

use cairo_air::components::memory_address_to_id::{
    MEMORY_ADDRESS_TO_ID_SPLIT, N_ID_AND_MULT_COLUMNS_PER_CHUNK, N_TRACE_COLUMNS,
};
use itertools::{izip, Itertools};
use num_traits::Zero;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use stwo::core::fields::m31::{BaseField, M31};
use stwo::prover::backend::simd::m31::{PackedBaseField, PackedM31, N_LANES};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo_cairo_adapter::memory::Memory;

use crate::witness::utils::AtomicMultiplicityColumn;

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

    pub fn get_memory_address_to_id(mut self) -> InteractionClaimGenerator {
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

        // Commit only used memory to the trace.
        for (i, (address, id, multiplicity)) in izip!(addrs_used, ids_used, mults_used)
            .into_iter()
            .enumerate()
        {
            let chunk_idx = i / n_packed_rows;
            let row = i % n_packed_rows;
            trace[chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = address;
            trace[1 + chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = id;
            trace[2 + chunk_idx * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data[row] = multiplicity;
        }

        // Lookup data.
        let addresses: [_; MEMORY_ADDRESS_TO_ID_SPLIT] =
            std::array::from_fn(|i| trace[i * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data.clone());
        let ids: [_; MEMORY_ADDRESS_TO_ID_SPLIT] =
            std::array::from_fn(|i| trace[1 + i * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data.clone());
        let multiplicities: [_; MEMORY_ADDRESS_TO_ID_SPLIT] =
            std::array::from_fn(|i| trace[2 + i * N_ID_AND_MULT_COLUMNS_PER_CHUNK].data.clone());

        InteractionClaimGenerator {
            addresses,
            ids,
            multiplicities,
        }
    }
}

pub struct InteractionClaimGenerator {
    pub addresses: [Vec<PackedM31>; MEMORY_ADDRESS_TO_ID_SPLIT],
    pub ids: [Vec<PackedM31>; MEMORY_ADDRESS_TO_ID_SPLIT],
    pub multiplicities: [Vec<PackedM31>; MEMORY_ADDRESS_TO_ID_SPLIT],
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
