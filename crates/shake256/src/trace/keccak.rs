#![allow(non_snake_case)]

use crate::constants::N_BYTES_IN_STATE;
use crate::constants::{N_BYTES_IN_U64, N_LANES_SHAKE256, N_ROUNDS, SQRT_N_LANES_SHAKE256};
use crate::utils::{Enabler, Fu64_8};
use itertools::{izip, Itertools};
use num_traits::Zero;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use stwo_air_utils::trace::component_trace::ComponentTrace;
use stwo_air_utils_derive::{IterMut, ParIterMut, Uninitialized};
use stwo_prover::core::backend::simd::m31::{LOG_N_LANES, N_LANES};
use stwo_prover::core::{
    backend::{
        simd::{m31::PackedM31, SimdBackend},
        BackendForChannel,
    },
    channel::Channel,
    fields::{m31::M31, qm31::SECURE_EXTENSION_DEGREE},
    pcs::TreeVec,
    vcs::blake2_merkle::Blake2sMerkleChannel,
};

const N_KECCAK_LOOKUPS: usize = 2;
pub const N_XOR_8_8_LOOKUPS1: usize = N_ROUNDS * (SQRT_N_LANES_SHAKE256 * N_BYTES_IN_U64 + N_LANES_SHAKE256 * N_BYTES_IN_U64);
pub const N_XOR_8_8_LOOKUPS2: usize = N_ROUNDS * N_BYTES_IN_U64;
const N_XOR_8_8_LOOKUPS: usize = N_XOR_8_8_LOOKUPS1 + N_XOR_8_8_LOOKUPS2;
pub const N_XOR_8_8_8_LOOKUPS: usize = N_ROUNDS * (SQRT_N_LANES_SHAKE256 * 2 * N_BYTES_IN_U64);
pub const N_CHI_8_8_8_LOOKUPS: usize = N_ROUNDS * N_LANES_SHAKE256 * N_BYTES_IN_U64;
pub const N_RC_7_7_7_LOOKUPS_1: usize = N_ROUNDS * SQRT_N_LANES_SHAKE256 * 3;
pub const N_RC_7_7_7_LOOKUPS_2: usize = N_ROUNDS * (N_LANES_SHAKE256 - 3) * 3;
const N_RC_7_7_7_LOOKUPS: usize = N_RC_7_7_7_LOOKUPS_1 + N_RC_7_7_7_LOOKUPS_2; // 3 rotations are trivial

const N_COLUMNS: usize = 1
    + N_BYTES_IN_STATE
    + N_ROUNDS
        * (2 * SQRT_N_LANES_SHAKE256 * N_BYTES_IN_U64 // C_inter and C
            + SQRT_N_LANES_SHAKE256 * N_BYTES_IN_U64 // C_rot_1
            + SQRT_N_LANES_SHAKE256 * N_BYTES_IN_U64 // D
            + N_LANES_SHAKE256 * N_BYTES_IN_U64 // THETA on S
            + (N_LANES_SHAKE256 - 3) * N_BYTES_IN_U64 // B, 3 rotations don't require hints
            + N_LANES_SHAKE256 * N_BYTES_IN_U64 // CHI on S
            + N_BYTES_IN_U64); // IOTA on S
const N_INTERACTION_COLUMNS: usize = SECURE_EXTENSION_DEGREE
    * (N_KECCAK_LOOKUPS
        + N_XOR_8_8_LOOKUPS
        + N_XOR_8_8_8_LOOKUPS
        + N_CHI_8_8_8_LOOKUPS
        + N_RC_7_7_7_LOOKUPS)
        .div_ceil(2);

// Rotation offsets for Keccak-f[1600] RHO step
const RHO_OFFSETS: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

// IOTA round constants for Keccak-f[1600]
const IOTA_RC: [u64; N_ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

#[derive(Default, Debug)]
pub struct Indexes {
    pub col_index: usize,
    pub xor_8_8_index: usize,
    pub xor_8_8_8_index: usize,
    pub chi_8_8_8_index: usize,
    pub rc_7_7_7_index: usize,
}

pub struct InteractionClaimData {
    pub lookup_data: LookupData,
    pub non_padded_length: usize,
}

#[derive(Uninitialized, IterMut, ParIterMut)]
pub struct LookupData {
    pub keccak: [Vec<[PackedM31; N_BYTES_IN_STATE]>; N_KECCAK_LOOKUPS],
    pub xor_8_8: [Vec<[PackedM31; 3]>; N_XOR_8_8_LOOKUPS],
    pub xor_8_8_8: [Vec<[PackedM31; 4]>; N_XOR_8_8_8_LOOKUPS],
    pub chi_8_8_8: [Vec<[PackedM31; 4]>; N_CHI_8_8_8_LOOKUPS],
    pub rc_7_7_7: [Vec<[PackedM31; 3]>; N_RC_7_7_7_LOOKUPS],
}

#[derive(Copy, Clone, Default, Serialize, Deserialize, Debug)]
pub struct Claim {
    pub log_size: u32,
}

impl Claim {
    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let trace = vec![self.log_size; N_COLUMNS];
        let interaction_trace = vec![self.log_size; N_INTERACTION_COLUMNS];
        TreeVec::new(vec![vec![], trace, interaction_trace])
    }

    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
    }

    pub fn generate_trace(
        mut keccak_packed_input: Vec<[PackedM31; N_BYTES_IN_STATE]>,
        keccak_invocations: usize,
    ) -> (Self, ComponentTrace<N_COLUMNS>, InteractionClaimData)
    where
        SimdBackend: BackendForChannel<Blake2sMerkleChannel>,
    {
        let log_size = std::cmp::max(
            keccak_invocations.next_power_of_two().ilog2() as u32,
            LOG_N_LANES,
        );
        keccak_packed_input.resize(
            1 << (log_size - LOG_N_LANES),
            [PackedM31::zero(); N_BYTES_IN_STATE],
        );
        let enabler_col = Enabler::new(keccak_invocations);

        // Generate lookup data and fill the trace
        let (mut trace, mut lookup_data) = unsafe {
            (
                ComponentTrace::<N_COLUMNS>::uninitialized(log_size),
                LookupData::uninitialized(log_size - LOG_N_LANES),
            )
        };

        (
            trace.par_iter_mut(),
            keccak_packed_input.into_par_iter(),
            lookup_data.par_iter_mut(),
        )
            .into_par_iter()
            .enumerate()
            .for_each(|(row_index, (mut row, input, mut lookup_data))| {
                let mut indexes = Indexes::default();
                let enabler = enabler_col.packed_at(row_index);
                *row[indexes.col_index] = enabler;
                indexes.col_index += 1;

                // ╔════════════════════════════════════╗
                // ║           Initialization           ║
                // ╚════════════════════════════════════╝
                // Initialize the state
                input.iter().for_each(|x| {
                    *row[indexes.col_index] = *x;
                    indexes.col_index += 1;
                });

                // Use the Keccak input state
                *lookup_data.keccak[0] = input;

                // Convert the state to an array of N_LANES_SHAKE256 u64
                let words_in: [Fu64_8<PackedM31>; N_LANES_SHAKE256] = input
                    .chunks(8)
                    .map(|chunk| Fu64_8::from_felts(chunk.try_into().unwrap()))
                    .collect_vec()
                    .try_into()
                    .unwrap();
                let mut S: [Fu64_8<PackedM31>; N_LANES_SHAKE256] =
                    std::array::from_fn(|_| Fu64_8::zero());
                for y in 0..SQRT_N_LANES_SHAKE256 {
                    for x in 0..SQRT_N_LANES_SHAKE256 {
                        S[5 * x + y] = words_in[x + 5 * y].clone(); // tiny-keccak order
                    }
                }

                // ╔════════════════════════════════════╗
                // ║               Rounds               ║
                // ╚════════════════════════════════════╝
                for round in 0..N_ROUNDS {
                    // ╔════════════════════════════════════╗
                    // ║               Theta                ║
                    // ╚════════════════════════════════════╝
                    // Initialize C and C_inter with zeros
                    let mut C: [Fu64_8<PackedM31>; SQRT_N_LANES_SHAKE256] =
                        std::array::from_fn(|_| Fu64_8::zero());
                    let mut C_inter: [Fu64_8<PackedM31>; SQRT_N_LANES_SHAKE256] =
                        std::array::from_fn(|_| Fu64_8::zero());

                    // C computation
                    for x in 0..SQRT_N_LANES_SHAKE256 {
                        // Hint C_inter
                        C_inter[x] = Fu64_8::from_felts(&std::array::from_fn(|i| {
                            let c_inter = xor_8_8_8(
                                S[5 * x].limbs[i],
                                S[5 * x + 1].limbs[i],
                                S[5 * x + 2].limbs[i],
                            );
                            *row[indexes.col_index] = c_inter;
                            indexes.col_index += 1;
                            c_inter
                        }));

                        // Hint C
                        C[x] = Fu64_8::from_felts(&std::array::from_fn(|i| {
                            let c = xor_8_8_8(
                                C_inter[x].limbs[i],
                                S[5 * x + 3].limbs[i],
                                S[5 * x + 4].limbs[i],
                            );
                            *row[indexes.col_index] = c;
                            indexes.col_index += 1;
                            c
                        }));

                        // Lookup data for Xor_8_8_8
                        for i in 0..N_BYTES_IN_U64 {
                            *lookup_data.xor_8_8_8[indexes.xor_8_8_8_index] = [
                                S[5 * x].limbs[i],
                                S[5 * x + 1].limbs[i],
                                S[5 * x + 2].limbs[i],
                                C_inter[x].limbs[i],
                            ];
                            indexes.xor_8_8_8_index += 1;

                            *lookup_data.xor_8_8_8[indexes.xor_8_8_8_index] = [
                                C_inter[x].limbs[i],
                                S[5 * x + 3].limbs[i],
                                S[5 * x + 4].limbs[i],
                                C[x].limbs[i],
                            ];
                            indexes.xor_8_8_8_index += 1;
                        }
                    }

                    // Rotate neighbor column: rotl(C[x+1], 1) == rotr(C[x+1], 63)
                    let C_rot_1: [Fu64_8<PackedM31>; SQRT_N_LANES_SHAKE256] =
                        std::array::from_fn(|x| {
                            let xp1 = (x + 1) % SQRT_N_LANES_SHAKE256;
                            rotr_fu64_8(
                                &C[xp1],
                                63,
                                &mut indexes,
                                &mut row,
                                &mut lookup_data,
                            )
                        });

                    // Compute and hint D
                    let D: [Fu64_8<PackedM31>; SQRT_N_LANES_SHAKE256] = std::array::from_fn(|x| {
                        Fu64_8::from_felts(&std::array::from_fn(|i| {
                            let d = xor_8_8(
                                C[(x + 4) % SQRT_N_LANES_SHAKE256].limbs[i],
                                C_rot_1[x].limbs[i],
                            );
                            *row[indexes.col_index] = d;
                            indexes.col_index += 1;
                            d
                        }))
                    });

                    // D lookups (spec: D[x] = C[x-1] ^ rotl(C[x+1], 1))
                    for x in 0..SQRT_N_LANES_SHAKE256 {
                        for i in 0..N_BYTES_IN_U64 {
                            *lookup_data.xor_8_8[indexes.xor_8_8_index] = [
                                C[(x + 4) % SQRT_N_LANES_SHAKE256].limbs[i],
                                C_rot_1[x].limbs[i],
                                D[x].limbs[i],
                            ];
                            indexes.xor_8_8_index += 1;
                        }
                    }

                    // Update S12
                    let res_S: [Fu64_8<PackedM31>; N_LANES_SHAKE256] = std::array::from_fn(|i| {
                        let x = i / SQRT_N_LANES_SHAKE256;
                        Fu64_8::from_felts(&std::array::from_fn(|k| {
                            let v = xor_8_8(S[i].limbs[k], D[x].limbs[k]);
                            *row[indexes.col_index] = v;
                            indexes.col_index += 1;
                            v
                        }))
                    });

                    // Check S update
                    for x in 0..SQRT_N_LANES_SHAKE256 {
                        for y in 0..SQRT_N_LANES_SHAKE256 {
                            for i in 0..N_BYTES_IN_U64 {
                                *lookup_data.xor_8_8[indexes.xor_8_8_index] = [
                                    S[5 * x + y].limbs[i],
                                    D[x].limbs[i],
                                    res_S[5 * x + y].limbs[i],
                                ];
                                indexes.xor_8_8_index += 1;
                            }
                        }
                    }

                    // Update S12
                    S = res_S;

                    // ╔════════════════════════════════════╗
                    // ║            RHO and PI              ║
                    // ╚════════════════════════════════════╝
                    let mut B: [Fu64_8<PackedM31>; N_LANES_SHAKE256] =
                        std::array::from_fn(|_| Fu64_8::zero());
                    for x in 0..SQRT_N_LANES_SHAKE256 {
                        for y in 0..SQRT_N_LANES_SHAKE256 {
                            let off = RHO_OFFSETS[x][y];
                            let rotr = if off == 0 { 0 } else { 64 - off }; // emulates left rotation
                            B[5 * y + ((2 * x + 3 * y) % SQRT_N_LANES_SHAKE256)] =
                                rotr_fu64_8(
                                    &S[5 * x + y],
                                    rotr,
                                    &mut indexes,
                                    &mut row,
                                    &mut lookup_data,
                                );
                        }
                    }

                    // ╔════════════════════════════════════╗
                    // ║                 CHI                ║
                    // ╚════════════════════════════════════╝

                    // Update S
                    for y in 0..SQRT_N_LANES_SHAKE256 {
                        for x in 0..SQRT_N_LANES_SHAKE256 {
                            S[5 * x + y] = Fu64_8::from_felts(&std::array::from_fn(|i| {
                                let a = B[5 * x + y].limbs[i];
                                let b = B[5 * ((x + 1) % SQRT_N_LANES_SHAKE256) + y].limbs[i];
                                let c = B[5 * ((x + 2) % SQRT_N_LANES_SHAKE256) + y].limbs[i];
                                let v = chi_8_8_8(a, b, c);

                                *lookup_data.chi_8_8_8[indexes.chi_8_8_8_index] = [a, b, c, v];
                                indexes.chi_8_8_8_index += 1;

                                v
                            }));
                        }
                    }

                    for x in 0..N_LANES_SHAKE256 {
                        for i in 0..N_BYTES_IN_U64 {
                            *row[indexes.col_index] = S[x].limbs[i];
                            indexes.col_index += 1;
                        }
                    }

                    // ╔════════════════════════════════════╗
                    // ║                IOTA                ║
                    // ╚════════════════════════════════════╝
                    let rc = IOTA_RC[round];
                    S[0] = Fu64_8::from_felts(&std::array::from_fn(|i| {
                        let rc_byte = PackedM31::from(M31::from(((rc >> (8 * i)) & 0xFF) as u32));
                        let v = xor_8_8(S[0].limbs[i], rc_byte);

                        *lookup_data.xor_8_8[indexes.xor_8_8_index] = [S[0].limbs[i], rc_byte, v];
                        indexes.xor_8_8_index += 1;

                        *row[indexes.col_index] = v;
                        indexes.col_index += 1;
                        v
                    }));

                    if round == N_ROUNDS - 1 {
                        // Emit the Keccak output state bytes in tiny-keccak's word order (w = x + 5*y).
                        let mut out: [PackedM31; N_BYTES_IN_STATE] =
                            [PackedM31::zero(); N_BYTES_IN_STATE];
                        for y in 0..SQRT_N_LANES_SHAKE256 {
                            for x in 0..SQRT_N_LANES_SHAKE256 {
                                let w_ref = x + 5 * y; // tiny-keccak order
                                let base = w_ref * N_BYTES_IN_U64;
                                let src = &S[5 * x + y];
                                for i in 0..N_BYTES_IN_U64 {
                                    out[base + i] = src.limbs[i];
                                }
                            }
                        }
                        *lookup_data.keccak[1] = out;
                    }
                }
            });

        let claim = Self { log_size };
        (
            claim,
            trace,
            InteractionClaimData {
                lookup_data,
                non_padded_length: keccak_invocations,
            },
        )
    }
}

fn xor_8_8(a: PackedM31, b: PackedM31) -> PackedM31 {
    PackedM31::from_array(
        a.to_array()
            .iter()
            .zip(b.to_array().iter())
            .map(|(a, b)| M31::from(a.0 ^ b.0))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    )
}

fn xor_8_8_8(a: PackedM31, b: PackedM31, c: PackedM31) -> PackedM31 {
    PackedM31::from_array(
        izip!(a.to_array(), b.to_array(), c.to_array())
            .map(|(a, b, c)| M31::from(a.0 ^ b.0 ^ c.0))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    )
}

fn chi_8_8_8(a: PackedM31, b: PackedM31, c: PackedM31) -> PackedM31 {
    // Equivalent to a ^ (!b & c) on 8-bit lanes
    PackedM31::from_array(
        izip!(a.to_array(), b.to_array(), c.to_array())
            .map(|(a, b, c)| M31::from(a.0 ^ ((!b.0) & c.0)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    )
}

fn rotr_fu64_8(
    A: &Fu64_8<PackedM31>,
    n: usize,
    indexes: &mut Indexes,
    row: &mut [&mut PackedM31],
    lookup_data: &mut LookupDataMutChunk<'_>,
) -> Fu64_8<PackedM31> {
    let q = n / 8;
    let r = n % 8;
    let max_ur = PackedM31::from(M31::from((1 << r) - 1));
    let two_pow_r = PackedM31::from(M31::from(1 << r));

    // Byte rotation component of a right-rotation by n bits.
    // For a 64-bit little-endian value, rotating right by 8*q bits
    // maps new_byte[i] = old_byte[(i + q) % 8].
    let A: [PackedM31; 8] = std::array::from_fn(|i| {
        let idx = (i + (q % N_BYTES_IN_U64)) % N_BYTES_IN_U64;
        A.limbs[idx]
    });

    // Fast path: no residual rotation
    if r == 0 {
        return Fu64_8::from_felts(&A);
    }

    // Residual r-bit right rotation within each 8-bit limb
    let mut res = [[0u32; N_LANES]; 8];
    let mut A_hi_limbs = [[0u32; N_LANES]; 8];

    // Decode current limbs to per-lane u12
    let A_u32: [[u32; N_LANES]; 8] = std::array::from_fn(|k| {
        let arr = A[k].to_array();
        std::array::from_fn(|lane| (arr[lane].0 as u32) & 0xFF)
    });

    let lo_mask = (1u32 << r) - 1;
    for lane in 0..N_LANES {
        let mut hi = [0u32; 8];
        let mut lo = [0u32; 8];
        for i in 0..8 {
            let v = A_u32[i][lane];
            hi[i] = v >> r;
            lo[i] = v & lo_mask;
        }

        for i in 0..8 {
            // After the byte-rotation, the carry for byte i comes from the
            // lower r bits of byte (i + 1) mod 8.
            let carry_src = lo[(i + 1) % 8];
            let v = hi[i] | (carry_src << (8 - r));
            A_hi_limbs[i][lane] = hi[i];
            res[i][lane] = v & 0xFF;
        }
    }

    // Build PackedM31 result limbs and write to row
    let res_limbs: [PackedM31; 8] = std::array::from_fn(|k| {
        PackedM31::from_array(std::array::from_fn(|lane| M31::from(res[k][lane])))
    });

    let A_hi_limbs: [PackedM31; 8] = std::array::from_fn(|k| {
        PackedM31::from_array(std::array::from_fn(|lane| M31::from(A_hi_limbs[k][lane])))
    });
    let A_lo_limbs: [PackedM31; 8] = std::array::from_fn(|i| A[i] - A_hi_limbs[i] * two_pow_r);

    *lookup_data.rc_7_7_7[indexes.rc_7_7_7_index] = [
        max_ur - A_lo_limbs[0],
        max_ur - A_lo_limbs[1],
        max_ur - A_lo_limbs[2],
    ];
    indexes.rc_7_7_7_index += 1;

    *lookup_data.rc_7_7_7[indexes.rc_7_7_7_index] = [
        max_ur - A_lo_limbs[3],
        max_ur - A_lo_limbs[4],
        max_ur - A_lo_limbs[5],
    ];
    indexes.rc_7_7_7_index += 1;

    *lookup_data.rc_7_7_7[indexes.rc_7_7_7_index] = [
        max_ur - A_lo_limbs[6],
        max_ur - A_lo_limbs[7],
        PackedM31::zero(),
    ];
    indexes.rc_7_7_7_index += 1;

    for A_hi_limb in &A_hi_limbs {
        *row[indexes.col_index] = *A_hi_limb;
        indexes.col_index += 1;
    }

    Fu64_8::from_felts(&res_limbs)
}

#[cfg(test)]
mod tests {
    use super::Claim;
    use crate::constants::N_BYTES_IN_STATE;
    use crate::trace::shake256::apply_keccakf;
    use stwo_prover::core::{
        backend::simd::m31::{PackedM31, N_LANES},
        fields::m31::M31,
    };

    #[test]
    fn keccak_compare_to_reference() {
        // Build one packed Keccak input state (200 bytes), with 16 SIMD lanes.
        let input_state: [PackedM31; N_BYTES_IN_STATE] = std::array::from_fn(|i| {
            PackedM31::from_array(std::array::from_fn(|lane| {
                let v: u32 = ((i as u32).wrapping_mul(37)).wrapping_add((lane as u32) * 13) & 0xFF;
                M31::from(v)
            }))
        });

        // Compute the expected final state with the reference Keccak-f[1600].
        let mut expected = input_state.clone();
        apply_keccakf(&mut expected);

        // Feed the same input to the Keccak trace generator.
        let keccak_invocations = N_LANES;
        let (_claim, _trace, interaction) =
            Claim::generate_trace(vec![input_state], keccak_invocations);

        // The final state is stored in lookup_data.keccak[1]
        let got = &interaction.lookup_data.keccak[1][0];

        for i in 0..N_BYTES_IN_STATE {
            assert_eq!(
                got[i].to_array(),
                expected[i].to_array(),
                "Mismatch at byte {}",
                i
            );
        }
    }
}
