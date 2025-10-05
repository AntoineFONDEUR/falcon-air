#![allow(non_snake_case)]

use itertools::Itertools;
use num_traits::{One, Zero};
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry};
use stwo_prover::core::fields::m31::M31;

use crate::constants::{
    N_BYTES_IN_STATE, N_BYTES_IN_U64, N_LANES_SHAKE256, N_ROUNDS, SQRT_N_LANES_SHAKE256,
};
use crate::trace::keccak::Claim;
use crate::utils::Fu64_8;

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

#[derive(Clone)]
pub struct Eval {
    pub claim: Claim,
    pub interaction_elements: crate::interaction::InteractionElements,
}

impl FrameworkEval for Eval {
    fn log_size(&self) -> u32 {
        self.claim.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size() + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let enabler = E::EF::from(eval.next_trace_mask());

        // ╔════════════════════════════════════╗
        // ║           Initialization           ║
        // ╚════════════════════════════════════╝
        // Initialize the state
        let S: [E::F; N_BYTES_IN_STATE] = std::array::from_fn(|_| eval.next_trace_mask());

        // Use the Keccak input state
        eval.add_to_relation(RelationEntry::new(
            &self.interaction_elements.keccak,
            -enabler.clone(),
            &S,
        ));

        // Convert the state to an array of N_LANES_SHAKE256 u64.
        let words_in: [Fu64_8<E::F>; N_LANES_SHAKE256] = S
            .chunks(8)
            .map(|chunk| Fu64_8::from_felts(chunk.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap();
        let mut S: [Fu64_8<E::F>; N_LANES_SHAKE256] = std::array::from_fn(|_| Fu64_8::zero());
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
            // Initialize C with zeros
            let mut C: [Fu64_8<E::F>; SQRT_N_LANES_SHAKE256] =
                std::array::from_fn(|_| Fu64_8::zero());

            // Check C computation
            for x in 0..SQRT_N_LANES_SHAKE256 {
                // Guess C_inter and C
                let C_inter: Fu64_8<E::F> =
                    Fu64_8::from_felts(&std::array::from_fn(|_| eval.next_trace_mask()));
                C[x] = Fu64_8::from_felts(&std::array::from_fn(|_| eval.next_trace_mask()));

                for i in 0..N_BYTES_IN_U64 {
                    // Check that C_inter[x] = S[x,0]^S[x,1]^S[x,2]
                    eval.add_to_relation(RelationEntry::new(
                        &self.interaction_elements.xor_8_8_8,
                        E::EF::one(),
                        &[
                            S[5 * x].limbs[i].clone(),
                            S[5 * x + 1].limbs[i].clone(),
                            S[5 * x + 2].limbs[i].clone(),
                            C_inter.limbs[i].clone(),
                        ],
                    ));
                    // Check that C[x] = C_inter[x]^S[x,3]^S[x,4]
                    eval.add_to_relation(RelationEntry::new(
                        &self.interaction_elements.xor_8_8_8,
                        E::EF::one(),
                        &[
                            C_inter.limbs[i].clone(),
                            S[5 * x + 3].limbs[i].clone(),
                            S[5 * x + 4].limbs[i].clone(),
                            C[x].limbs[i].clone(),
                        ],
                    ));
                }
            }

            // Rotate neighbor column: rotl(C[x+1], 1) == rotr(C[x+1], 63)
            let C_rot_1: [Fu64_8<E::F>; SQRT_N_LANES_SHAKE256] = std::array::from_fn(|x| {
                let xp1 = (x + 1) % SQRT_N_LANES_SHAKE256;
                rotr_fu64_8(&C[xp1], 63, &mut eval, &self.interaction_elements)
            });

            // Guess D
            let D: [Fu64_8<E::F>; SQRT_N_LANES_SHAKE256] = std::array::from_fn(|_| {
                Fu64_8::from_felts(&std::array::from_fn(|_| eval.next_trace_mask()))
            });

            // Check D computation
            for x in 0..SQRT_N_LANES_SHAKE256 {
                for i in 0..N_BYTES_IN_U64 {
                    // Spec: D[x] = C[x-1] ^ rotl(C[x+1], 1)
                    let xm1 = (x + SQRT_N_LANES_SHAKE256 - 1) % SQRT_N_LANES_SHAKE256;
                    eval.add_to_relation(RelationEntry::new(
                        &self.interaction_elements.xor_8_8,
                        E::EF::one(),
                        &[
                            C[xm1].limbs[i].clone(),
                            C_rot_1[x].limbs[i].clone(),
                            D[x].limbs[i].clone(),
                        ],
                    ));
                }
            }

            let res_S: [Fu64_8<E::F>; N_LANES_SHAKE256] = std::array::from_fn(|_| {
                Fu64_8::from_felts(&std::array::from_fn(|_| eval.next_trace_mask()))
            });

            // Check S12 update
            for x in 0..SQRT_N_LANES_SHAKE256 {
                for y in 0..SQRT_N_LANES_SHAKE256 {
                    for i in 0..N_BYTES_IN_U64 {
                        // Check that res_S[x] = S[x]^D[x]
                        eval.add_to_relation(RelationEntry::new(
                            &self.interaction_elements.xor_8_8,
                            E::EF::one(),
                            &[
                                S[5 * x + y].limbs[i].clone(),
                                D[x].limbs[i].clone(),
                                res_S[5 * x + y].limbs[i].clone(),
                            ],
                        ));
                    }
                }
            }

            // Update S12
            S = res_S;

            // ╔════════════════════════════════════╗
            // ║            RHO and PI              ║
            // ╚════════════════════════════════════╝
            // Apply RHO rotations and PI permutation
            let mut B: [Fu64_8<E::F>; N_LANES_SHAKE256] = std::array::from_fn(|_| Fu64_8::zero());
            for x in 0..SQRT_N_LANES_SHAKE256 {
                for y in 0..SQRT_N_LANES_SHAKE256 {
                    let off = RHO_OFFSETS[x][y];
                    let rotr = if off == 0 { 0 } else { 64 - off }; // emulates left rotation
                    B[5 * y + ((2 * x + 3 * y) % SQRT_N_LANES_SHAKE256)] = rotr_fu64_8(
                        &S[5 * x + y],
                        rotr,
                        &mut eval,
                        &self.interaction_elements,
                    );
                }
            }

            // ╔════════════════════════════════════╗
            // ║                 CHI                ║
            // ╚════════════════════════════════════╝

            // Guess S after CHI
            S = std::array::from_fn(|_| {
                Fu64_8::from_felts(&std::array::from_fn(|_| eval.next_trace_mask()))
            });

            // Check CHI computation
            for y in 0..SQRT_N_LANES_SHAKE256 {
                for x in 0..SQRT_N_LANES_SHAKE256 {
                    for i in 0..N_BYTES_IN_U64 {
                        eval.add_to_relation(RelationEntry::new(
                            &self.interaction_elements.chi_8_8_8,
                            E::EF::one(),
                            &[
                                B[x * 5 + y].limbs[i].clone(),
                                B[((x + 1) % SQRT_N_LANES_SHAKE256) * 5 + y].limbs[i].clone(),
                                B[((x + 2) % SQRT_N_LANES_SHAKE256) * 5 + y].limbs[i].clone(),
                                S[x * 5 + y].limbs[i].clone(),
                            ],
                        ));
                    }
                }
            }

            // ╔════════════════════════════════════╗
            // ║                IOTA                ║
            // ╚════════════════════════════════════╝
            // Guess res_S_xor_RC and constrain with XOR lookups
            let res_S_xor_RC: Fu64_8<E::F> =
                Fu64_8::from_felts(&std::array::from_fn(|_| eval.next_trace_mask()));
            let rc = IOTA_RC[round];
            for i in 0..N_BYTES_IN_U64 {
                let rc_byte = E::F::from(M31::from(((rc >> (8 * i)) & 0xFF) as u32));
                eval.add_to_relation(RelationEntry::new(
                    &self.interaction_elements.xor_8_8,
                    E::EF::one(),
                    &[
                        S[0].limbs[i].clone(),
                        rc_byte.clone(),
                        res_S_xor_RC.limbs[i].clone(),
                    ],
                ));
            }
            S[0] = res_S_xor_RC;

            if round == N_ROUNDS - 1 {
                // Flatten S to bytes in tiny-keccak word order (w = x + 5*y).
                let mut out: [E::F; N_BYTES_IN_STATE] = std::array::from_fn(|_| E::F::zero());
                for y in 0..SQRT_N_LANES_SHAKE256 {
                    for x in 0..SQRT_N_LANES_SHAKE256 {
                        let w_ref = x + 5 * y; // tiny-keccak order
                        let base = w_ref * N_BYTES_IN_U64;
                        let src = &S[5 * x + y];
                        for i in 0..N_BYTES_IN_U64 {
                            out[base + i] = src.limbs[i].clone();
                        }
                    }
                }

                // Emit the Keccak output state
                eval.add_to_relation(RelationEntry::new(
                    &self.interaction_elements.keccak,
                    enabler.clone(),
                    &out,
                ));
            }
        }

        eval.finalize_logup_in_pairs();
        eval
    }
}

fn rotr_fu64_8<E: EvalAtRow>(
    A: &Fu64_8<E::F>,
    n: usize,
    eval: &mut E,
    interaction_elements: &crate::interaction::InteractionElements,
) -> Fu64_8<E::F> {
    let q = n / 8;
    let r = n % 8;
    let two_pow_r: E::F = E::F::from(M31::from(1 << r));
    let max_ur: E::F = E::F::from(M31::from((1 << r) - 1));
    let two_pow_8_minus_r: E::F = E::F::from(M31::from(1 << (8 - r)));

    // Byte rotation component of a right-rotation by n: new[i] = old[(i + q) % 8].
    let A: Fu64_8<E::F> = Fu64_8::from_felts(&std::array::from_fn(|i| {
        let idx = (i + (q % N_BYTES_IN_U64)) % N_BYTES_IN_U64;
        A.limbs[idx].clone()
    }));

    if r == 0 {
        return A;
    }

    // Guess r high bits and 8-r low bits of each 8-bit limb
    let A_hi_limbs: [E::F; 8] = std::array::from_fn(|_| eval.next_trace_mask());
    let A_lo_limbs: [E::F; 8] =
        std::array::from_fn(|i| A.limbs[i].clone() - A_hi_limbs[i].clone() * two_pow_r.clone());

    // RC a_lo_limbs
    eval.add_to_relation(RelationEntry::new(
        &interaction_elements.rc_7_7_7,
        E::EF::one(),
        &[
            max_ur.clone() - A_lo_limbs[0].clone(),
            max_ur.clone() - A_lo_limbs[1].clone(),
            max_ur.clone() - A_lo_limbs[2].clone(),
        ],
    ));
    eval.add_to_relation(RelationEntry::new(
        &interaction_elements.rc_7_7_7,
        E::EF::one(),
        &[
            max_ur.clone() - A_lo_limbs[3].clone(),
            max_ur.clone() - A_lo_limbs[4].clone(),
            max_ur.clone() - A_lo_limbs[5].clone(),
        ],
    ));
    eval.add_to_relation(RelationEntry::new(
        &interaction_elements.rc_7_7_7,
        E::EF::one(),
        &[
            max_ur.clone() - A_lo_limbs[6].clone(),
            max_ur.clone() - A_lo_limbs[7].clone(),
            E::F::zero(),
        ],
    ));

    // Rotate r times to the right
    Fu64_8::from_felts(&std::array::from_fn(|i| {
        let j = (i + 1) % N_BYTES_IN_U64;
        A_hi_limbs[i].clone() + A_lo_limbs[j].clone() * two_pow_8_minus_r.clone()
    }))
}

pub type Component = FrameworkComponent<Eval>;
