use itertools::Itertools;
use num_traits::{One, Zero};
use stwo_prover::core::backend::simd::m31::{PackedM31, N_LANES};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::FieldExpOps;

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Sub};

//  ┌──────────────────────────────┐
//  │     Prep. Traces Helper      │
//  └──────────────────────────────┘

pub fn pack_column<F>(n_rows: usize, mut f: F) -> Vec<PackedM31>
where
    F: FnMut(usize) -> M31 + 'static,
{
    (0..n_rows)
        .map(move |idx| f(idx))
        .chunks(N_LANES)
        .into_iter()
        .map(|chunk| {
            let arr: [M31; N_LANES] = chunk.collect_vec().try_into().unwrap();
            PackedM31::from_array(arr)
        })
        .collect_vec()
}

//  ┌──────────────────────────────┐
//  │           Enabler            │
//  └──────────────────────────────┘

#[derive(Debug, Clone)]
pub struct Enabler {
    /// Number of active (non-padded) rows in the trace
    pub padding_offset: usize,
}
impl Enabler {
    pub const fn new(padding_offset: usize) -> Self {
        Self { padding_offset }
    }

    pub fn packed_at(&self, vec_row: usize) -> PackedM31 {
        let row_offset = vec_row * N_LANES;

        if row_offset >= self.padding_offset {
            return PackedM31::zero();
        }

        if row_offset + N_LANES <= self.padding_offset {
            return PackedM31::one();
        }

        let mut res = [M31::zero(); N_LANES];
        let enabled_lanes = self.padding_offset - row_offset;
        res[..enabled_lanes].fill(M31::one());
        PackedM31::from_array(res)
    }
}

//  ┌──────────────────────────────┐
//  │            Fu64              │
//  └──────────────────────────────┘

// Concrete 64-bit split into 8 limbs of 8 bits each
#[derive(Clone, Debug)]
pub struct Fu64_8<F>
where
    F: FieldExpOps
        + Clone
        + Zero
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<M31, Output = F>,
{
    pub limbs: [F; 8],
}

impl<F> Fu64_8<F>
where
    F: FieldExpOps
        + Zero
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<M31, Output = F>,
{
    pub fn from_felts(x: &[F; 8]) -> Self {
        Self { limbs: x.clone() }
    }
    #[allow(unused)]
    pub fn into_felts(self) -> [F; 8] {
        self.limbs
    }
}

impl<F> Zero for Fu64_8<F>
where
    F: FieldExpOps
        + Zero
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<M31, Output = F>,
{
    fn zero() -> Self {
        Self {
            limbs: core::array::from_fn(|_| F::zero()),
        }
    }

    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|x| x.is_zero())
    }
}

impl<F> Add for Fu64_8<F>
where
    F: FieldExpOps
        + Zero
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<M31, Output = F>,
{
    type Output = Self;

    // Necessary for Zero implementation
    fn add(self, _other: Self) -> Self {
        unimplemented!();
    }
}
