use crate::{CommitPhaseMsg, DEFAULT_R_BITS, TimedCommitment};
use crate::{
    get_order,
    protocol::{BITS, DEFAULT_B, DEFAULT_K},
    totient_slow, u256_exp_mod,
};
use crypto_bigint::{Checked, NonZero, U256};
use crypto_primes::{generate_prime, is_prime};

pub struct Verifier {
    pub k: u32, // should be the same as
    pub R_bits: u32,
    n: NonZero<U256>,
    timed_commitment: Option<TimedCommitment>,
    W: Option<Vec<U256>>,
    c: Option<Vec<U256>>,
    q_prod: U256,
}

impl Verifier {
    pub fn new(n: NonZero<U256>) -> Self {
        let q_array: Vec<U256> = (1..DEFAULT_B)
            .filter_map(|x| match is_prime(&U256::from(x)) {
                true => Some(U256::from(x.pow(BITS))),
                false => None,
            })
            .collect();

        let q_prod = q_array.into_iter().fold(U256::ONE, |acc, qin| {
            (Checked::new(acc) * Checked::new(qin)).0.unwrap()
        });

        Self {
            k: DEFAULT_K,
            R_bits: DEFAULT_R_BITS,
            n,
            timed_commitment: None,
            W: None,
            c: None,
            q_prod,
        }
    }

    pub fn receive_timed_commitment(&mut self, commit_msg: CommitPhaseMsg) {
        self.timed_commitment = Some(commit_msg.commit);
        self.W = Some(commit_msg.W);
    }

    pub fn get_challenges(&mut self) -> Vec<U256> {
        assert!(self.timed_commitment.is_some());
        let c: Vec<U256> = (0..self.k).map(|_| generate_prime(self.R_bits)).collect();
        self.c = Some(c.clone());
        c
    }

    pub fn can_open(&self) -> bool {
        self.timed_commitment.is_some()
    }

    pub fn verify_commit_zkp(&self, y: Vec<U256>, zw_pairs: Vec<(U256, U256)>) -> bool {
        let g = self.timed_commitment.as_ref().unwrap().g;
        self.c
            .as_ref()
            .unwrap()
            .iter()
            .zip(y.iter().zip(zw_pairs.iter()))
            .enumerate()
            .fold(true, |acc, (idx, (ci, (yi, (zi, wi))))| {
                let b_prev = self.W.as_ref().unwrap()[idx];
                let b_cur = self.W.as_ref().unwrap()[idx + 1];

                // w check
                let b_prevy = u256_exp_mod(&b_prev, yi, &self.n);
                let inv_b_curc = u256_exp_mod(&b_cur, ci, &self.n).inv_mod(&self.n).unwrap();
                let wcheck = &b_prevy.mul_mod(&inv_b_curc, &self.n) == wi;

                // z check
                let gy = u256_exp_mod(&g, yi, &self.n);
                let inv_b_prevc = u256_exp_mod(&b_cur, &ci, &self.n).inv_mod(&self.n).unwrap();
                let zcheck = &gy.mul_mod(&inv_b_prevc, &self.n) == zi;

                acc && wcheck && zcheck
            })
    }

    pub fn open(&self, v_prime: U256) -> U256 {
        let S = &self.timed_commitment.as_ref().unwrap().S;
        let l = S.len();
        let u = self.timed_commitment.as_ref().unwrap().u;
        let mut v = u256_exp_mod(&v_prime, &self.q_prod, &self.n);
        let _ = (0..l).map(|_| {
            v = v.mul_mod(&v, &self.n);
        });

        assert!(v == u);

        let R = (0..l)
            .scan(v, |state, i| {
                // Calculate v^(2^(l-i-1))
                *state = u256_exp_mod(state, &U256::from(2u32), &self.n);
                // Get least significant bit
                Some(state.bit(0).into())
            })
            .collect::<Vec<bool>>();

        // XOR the random sequence R with commitment S to get the message M
        let m: U256 =
            R.iter()
                .zip(S.iter())
                .enumerate()
                .fold(U256::ZERO, |acc, (i, (r_bit, s_bit))| {
                    // XOR the bits and set in the result
                    if *r_bit ^ *s_bit {
                        acc | (U256::ONE << i)
                    } else {
                        acc
                    }
                });

        m
    }

    pub fn forced_open(&self) -> U256 {
        let l = self.timed_commitment.as_ref().unwrap().S.len();
        let totient = totient_slow(*self.n); // TODO: remove this if too slow, just worried about overflow
        // get
        let mut exp = (0..(self.k)).fold(U256::from(2u32), |acc, _| acc.mul_mod(&acc, &totient));

        let inv_to_start = u256_exp_mod(&U256::from(2u32), &U256::from(l as u32), &totient)
            .inv_mod(&totient)
            .unwrap();

        exp = exp.mul_mod(&inv_to_start, &totient);
        let mut counter = U256::ZERO;
        let mut v = U256::ONE;

        while exp.gt(&counter) {
            v = v.mul_mod(&v, &self.n);
            counter = counter.wrapping_add(&U256::ONE);
        }
        v
    }
}
