use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

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

#[derive(Debug, Clone)]
pub struct DecomposeConfig<F: FieldExt, const RANGE: usize> {
    running_sum: Column<Advice>,
    q_decompose: Selector,
    table: RangeCheckTable<F, RANGE>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt + PrimeFieldBits, const RANGE: usize> DecomposeConfig<F, RANGE> {
    pub fn configure(meta: &mut ConstraintSystem<F>, running_sum: Column<Advice>) -> Self {
        // Create the needed columns and internal configs
        let running_sum = running_sum;
        let q_decompose = meta.complex_selector();
        let table = RangeCheckTable::<F, RANGE>::configure(meta);

        // We need a fixed column for the `constrain_constant` step used to enforce `z_C == 0`
        // similarly, we need to enable `running_sum` to participate in the permutation argument.
        let constant = meta.fixed_column();
        meta.enable_constant(constant);

        meta.enable_equality(running_sum);

        // Range-check lookup
        // Range-constrain eatch K-bit chunk `c_i = z_i - z_{i + 1} * 2^K`, derived from running_sum
        meta.lookup(|meta| {
            let q_decompose = meta.query_selector(q_decompose);

            // Derive the chunk c_i = z_i - z_{i + 1} * 2 ^ K from the witnessed z_i, z_{i + 1}
            let z_i = meta.query_advice(running_sum, Rotation::cur());
            let z_i_next = meta.query_advice(running_sum, Rotation::next());

            // c_i = z_i - z_{i + 1} * 2 ^ K
            let lookup_num_bits = (RANGE as f64).log2().ceil() as usize;
            let chunk = z_i - z_i_next * F::from(1 << lookup_num_bits);

            // When q_decompose = 0, not q_decompose = 1.
            // In other words, the constraint SHOULD match even when
            // q_decompose selector is NOT set.
            let not_q_decompose = Expression::Constant(F::one()) - q_decompose.clone();
            let default_chunk = Expression::Constant(F::zero());
            let expr = q_decompose * chunk + not_q_decompose * default_chunk;

            vec![(expr, table.value)]
        });

        Self {
            running_sum,
            q_decompose,
            table,
            _marker: PhantomData::default(),
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: AssignedCell<Assigned<F>, F>,
        num_bits: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Decompose value",
            |mut region| {
                let lookup_num_bits = (RANGE as f64).log2().ceil() as usize;
                assert_eq!(num_bits % lookup_num_bits, 0);

                let mut offset = 0;
                // 1. Copy in the witnessed `value`
                let mut z = value.copy_advice(
                    || "Copy value to initialize running sum",
                    &mut region,
                    self.running_sum,
                    offset,
                )?;
                offset += 1;

                // 2. Compute the running_sum values {z_1, ..., z_C}
                let running_sum = value
                    .value()
                    .map(|&v| compute_running_sum(v, num_bits, lookup_num_bits))
                    .transpose_vec(num_bits / lookup_num_bits);

                // 3. Assign the running sum values
                for z_i in running_sum.into_iter() {
                    z = region.assign_advice(
                        || format!("assign z_{}", offset),
                        self.running_sum,
                        offset,
                        || z_i,
                    )?;
                    offset += 1;
                }
                // 4. Enable the selector on each row of the running sum
                for row in 0..(num_bits / lookup_num_bits) {
                    self.q_decompose.enable(&mut region, row)?;
                }
                // 5. Constrain the final running_sum `z_C` to be 0.
                region.constrain_constant(z.cell(), F::zero())
            },
        )
    }
}

// Function to compute the interstitial running sum values {z_1, z_2, ..., z_C}
fn compute_running_sum<F: FieldExt + PrimeFieldBits>(
    value: Assigned<F>,
    num_bits: usize,
    lookup_num_bits: usize,
) -> Vec<Assigned<F>> {
    let mut running_sum = vec![];
    let mut z = value;

    // Get the little-bit endian representation of `value`
    let value: Vec<_> = value
        .evaluate()
        .to_le_bits()
        .iter()
        .by_vals()
        .take(num_bits)
        .collect();

    for chunk in value.chunks(lookup_num_bits) {
        let chunk = Assigned::from(F::from(lebs2ip(chunk)));

        // z_{i + 1} = (z_i - c_i) * 2^{-K};
        z = (z - chunk) * Assigned::from(F::from(1 << lookup_num_bits)).invert();
        running_sum.push(z);
    }
    assert_eq!(running_sum.len(), num_bits / lookup_num_bits);

    running_sum
}

pub fn lebs2ip(bits: &[bool]) -> u64 {
    // assert!(L <= 64);
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{circuit::floor_planner::V1, dev::MockProver, pasta::Fp};
    use rand;

    use super::*;

    #[derive(Debug, Default)]
    struct MyCircuit<F: FieldExt, const NUM_BITS: usize, const RANGE: usize> {
        value: Value<Assigned<F>>,
        num_bits: usize, // num_bits is a multiple of NUM_BITS
    }

    impl<F: FieldExt + PrimeFieldBits, const NUM_BITS: usize, const RANGE: usize> Circuit<F>
        for MyCircuit<F, NUM_BITS, RANGE>
    {
        type Config = DecomposeConfig<F, RANGE>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            // Self::default()
            Self {
                value: Value::unknown(),
                num_bits: self.num_bits,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // // Fixed column for constants
            // let constants = meta.fixed_column();
            // meta.enable_constant(constants);

            let running_sum = meta.advice_column();
            DecomposeConfig::configure(meta, running_sum)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;

            // Witness the value somewhere
            let value = layouter.assign_region(
                || "witness value",
                |mut region| {
                    region.assign_advice(|| "Witness value", config.running_sum, 0, || self.value)
                },
            )?;
            config.assign(
                layouter.namespace(|| "Decompose value"),
                value,
                self.num_bits,
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_decompose_1() {
        let k = 9;
        const NUM_BITS: usize = 8;
        const RANGE: usize = 256; // 8-bit value

        // Random u64 vaue
        let value: u64 = rand::random();
        let value = Value::known(Assigned::from(Fp::from(value)));

        let circuit = MyCircuit::<Fp, NUM_BITS, RANGE> {
            value,
            num_bits: 64,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn print_decompose_1() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("decompose-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Decompose Range Check Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit::<Fp, 8, 256> {
            value: Value::unknown(),
            num_bits: 64,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(9, &circuit, &root)
            .unwrap();
    }
}
