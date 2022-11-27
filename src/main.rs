use std::marker::PhantomData;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

mod range_check_lookup;
use range_check_lookup::table::RangeCheckTable;

fn main() {
    println!("Hello, world!");
}

///
/// This gadget range-constrains an element witnessed in the circuit to be N bits.
///
/// Internally, this gadget uses `range_check` helper, which provides a K-bit lookup table
///
/// Given an element `value`, we use a running sum to break it into K-bit chunks.
/// Assume for now that N | K, and define C = N / K
///         value = [b_0, b_1, ... b_{N -1}]    little endian
///               = c_0 + c_1 * 2^K + c_2 * 2^{2k} + ... + c_{C - 1} * 2^{(C - 1)K}
///
/// Initialize the running_sum at
///         value = z_0.
///
/// Consequent terms of the running sum are z_{i+1} = (z_i - c_i) * 2^{-K}:
///
///             z_1 = (z_0 - c_0) * 2^{-K}
///             z_2 = (z_1 - c_1) * 2^{-K}
///                 ...
///             z_{C - 1} = c_{C - 1}
///             z_C = (z_{C - 1} - c_{C - 1}) * 2^{-K}
///                 = 0
///
/// One configuration for this gadget look like:
///
///     | running_sum | q_decompose | table_value |
///     -------------------------------------------
///     |    z_0      |      1      |      0      |
///     |    z_1      |      1      |      1      |
///     |    ...      |     ...     |     ...     |
///     |   z_{C - 1} |      1      |     ...     |
///     |   z_C       |      0      |     ...     |
///
///
///  
/// Stretch task: use the tagged lookup table to constrain arbitrary bitlengths
/// (even non-multiples of K)
///

#[derive(Debug)]
pub struct DecomposeConfig<F: FieldExt, const RANGE: usize> {
    running_sum: Column<Advice>,
    q_decompose: Selector,
    table: RangeCheckTable<F, RANGE>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const RANGE: usize> DecomposeConfig<F, RANGE> {
    pub fn configure(meta: &mut ConstraintSystem<F>, running_sum: Column<Advice>) -> Self {
        let running_sum = running_sum;
        let q_decompose = meta.complex_selector();
        let table = RangeCheckTable::<F, RANGE>::configure(meta);

        // Configure the gate/constraints

        Self {
            running_sum,
            q_decompose,
            table,
            _marker: PhantomData::default(),
        }
    }

    pub fn assign(layouter: impl Layouter<F>) -> Result<(), Error> {
        todo!()
    }
}
