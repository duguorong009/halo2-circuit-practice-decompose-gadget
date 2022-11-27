use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::Error,
    plonk::{ConstraintSystem, TableColumn},
};

// A lookup table of values of RANGE
// e.g. RANGE = 256, values = [0..256)

#[derive(Debug, Clone)]
pub struct RangeCheckTable<F: FieldExt, const RANGE: usize> {
    pub value: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const RANGE: usize> RangeCheckTable<F, RANGE> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let value = meta.lookup_table_column();
        Self {
            value,
            _marker: PhantomData::default(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load range-check table",
            |mut table| {
                let mut offset = 0;
                for i in 0..RANGE {
                    table.assign_cell(
                        || "assign cell",
                        self.value,
                        offset,
                        || Value::known(F::from(i as u64)),
                    )?;

                    offset += 1;
                }
                Ok(())
            },
        )
    }
}
