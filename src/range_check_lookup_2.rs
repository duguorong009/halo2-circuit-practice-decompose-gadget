mod table;
use table::RangeCheckTable;

use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

// Helper that checks that the value witnessed in the given cell is within a given range.
// Depending on the range, it uses either range-check expression(small ranges) or a lookup(large ranges)
//
//      value   |   q_range_check   |  q_lookup  |   table_value  |
//        v     |         1         |     0      |       0        |
//        v'    |         0         |     1      |       1        |
//
//

#[derive(Debug, Clone)]
pub struct RangeCheckConfig<
    F: FieldExt,
    const RANGE: usize,
    const NUM_BITS: usize,
    const LOOKUP_RANGE: usize,
> {
    value: Column<Advice>,
    num_bits: Column<Advice>,
    q_range_check: Selector,
    q_lookup: Selector,
    table: RangeCheckTable<F, NUM_BITS, LOOKUP_RANGE>,
}

impl<F: FieldExt, const RANGE: usize, const NUM_BITS: usize, const LOOKUP_RANGE: usize>
    RangeCheckConfig<F, RANGE, NUM_BITS, LOOKUP_RANGE>
{
    fn configure(
        meta: &mut ConstraintSystem<F>,
        value: Column<Advice>,
        num_bits: Column<Advice>,
    ) -> Self {
        // Toggles the range check constraint
        let q_range_check = meta.selector();

        // Toggles the lookup argument
        let q_lookup = meta.complex_selector();

        let table = RangeCheckTable::configure(meta);

        // Range-check gate
        // For a value v and range R, check that v < R
        //    v * (1 - v) * (2 - v) * ... * (R - 1 - v) = 0
        meta.create_gate("Range check", |meta| {
            let q_range_check = meta.query_selector(q_range_check);
            let value = meta.query_advice(value, Rotation::cur());

            let range_check = |range: usize, value: Expression<F>| {
                (0..range).fold(value.clone(), |expr, i| {
                    expr * (Expression::Constant(F::from(i as u64)) - value.clone())
                })
            };

            Constraints::with_selector(q_range_check, [("range check", range_check(RANGE, value))])
        });

        // Range-check lookup
        // Check that a value v is contained within a lookup table of values 0..RANGE
        meta.lookup(|meta| {
            let q_lookup = meta.query_selector(q_lookup);

            let num_bits = meta.query_advice(num_bits, Rotation::cur());

            let value = meta.query_advice(value, Rotation::cur());

            vec![
                (q_lookup.clone() * value, table.value),
                (q_lookup * num_bits, table.num_bits),
            ]
        });

        Self {
            q_range_check,
            q_lookup,
            value,
            num_bits,
            table,
        }
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
        larger_value_num_bits: Value<usize>,
        range: usize,
    ) -> Result<(), Error> {
        assert!(range <= LOOKUP_RANGE);

        if range < RANGE {
            layouter.assign_region(
                || "assign value",
                |mut region| {
                    // Enable q_range_check
                    self.q_range_check.enable(&mut region, 0)?;

                    // Assign given value
                    region.assign_advice(|| "value", self.value, 0, || value)?;

                    Ok(())
                },
            )
        } else {
            layouter.assign_region(
                || "assign value for lookup",
                |mut region| {
                    let offset = 0;

                    // Enable q_lookup check
                    self.q_lookup.enable(&mut region, offset)?;

                    // Assign num_bits value
                    let num_bits = larger_value_num_bits.map(|v| F::from(v as u64));
                    region.assign_advice(|| "num_bits", self.num_bits, offset, || num_bits)?;

                    // Assign given value
                    region.assign_advice(|| "value", self.value, offset, || value)?;

                    Ok(())
                },
            )
        }
    }
}

#[derive(Debug, Default)]
pub struct TestCircuit<
    F: FieldExt,
    const RANGE: usize,
    const NUM_BITS: usize,
    const LOOKUP_RANGE: usize,
> {
    pub value: Value<F>,
    pub larger_value: Value<F>,
    pub larger_value_num_bits: Value<usize>,
}

impl<F: FieldExt, const RANGE: usize, const NUM_BITS: usize, const LOOKUP_RANGE: usize> Circuit<F>
    for TestCircuit<F, RANGE, NUM_BITS, LOOKUP_RANGE>
{
    type Config = RangeCheckConfig<F, RANGE, NUM_BITS, LOOKUP_RANGE>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let value = meta.advice_column();
        let num_bits = meta.advice_column();
        RangeCheckConfig::configure(meta, value, num_bits)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.table.load(&mut layouter)?;

        config.assign(
            layouter.namespace(|| "Assign value"),
            self.value,
            self.larger_value_num_bits,
            RANGE,
        )?;
        config.assign(
            layouter.namespace(|| "Assign larger value"),
            self.larger_value,
            self.larger_value_num_bits,
            LOOKUP_RANGE,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::*, pasta::Fp};

    #[test]
    fn test_range_check() {
        let k = 20;

        const RANGE: usize = 8; // 3 bit-length
        const LOOKUP_RANGE: usize = 256; // 8 bit-length
        const NUM_BITS: usize = 8; // 8 bits number

        // Successful cases
        for i in 0..RANGE {
            let circuit = TestCircuit::<Fp, RANGE, NUM_BITS, LOOKUP_RANGE> {
                value: Value::known(Fp::from(i as u64)),
                larger_value: Value::known(Fp::from(i as u64)),
                larger_value_num_bits: Value::known((i as f64).log2().floor() as usize),
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        // Failed case
        let circuit = TestCircuit::<Fp, RANGE, NUM_BITS, LOOKUP_RANGE> {
            value: Value::known(Fp::from(RANGE as u64)),
            larger_value: Value::known(Fp::from(LOOKUP_RANGE as u64)),
            larger_value_num_bits: Value::known((LOOKUP_RANGE as f64).log2().floor() as usize),
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
