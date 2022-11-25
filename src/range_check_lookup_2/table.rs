use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::Error,
    plonk::{ConstraintSystem, TableColumn},
};

// A lookup table of values of RANGE
// e.g. RANGE = 256, values = [0..256)
// This table is tagged by an index `k`, where `k` is the number of bits of the element in the `value` column.
#[derive(Debug, Clone)]
pub(super) struct RangeCheckTable<F: FieldExt, const NUM_BITS: usize, const RANGE: usize> {
    pub(super) num_bits: TableColumn,
    pub(super) value: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const NUM_BITS: usize, const RANGE: usize> RangeCheckTable<F, NUM_BITS, RANGE> {
    pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        assert_eq!(1 << NUM_BITS, RANGE);

        let num_bits = meta.lookup_table_column();
        let value = meta.lookup_table_column();
        Self {
            num_bits,
            value,
            _marker: PhantomData::default(),
        }
    }

    pub(super) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load range-check table",
            |mut table| {
                let mut offset = 0;
                for value in 0..RANGE {
                    let num_bits = (value as f64).log2().floor();
                    table.assign_cell(
                        || "assign num_bits",
                        self.num_bits,
                        offset,
                        || Value::known(F::from(num_bits as u64)),
                    )?;
                    table.assign_cell(
                        || "assign cell",
                        self.value,
                        offset,
                        || Value::known(F::from(value as u64)),
                    )?;

                    offset += 1;
                }

                Ok(())
            },
        )
    }
}
