use std::time::Instant;

use crate::{CommitPhaseMsg, DEFAULT_R_BITS, TimedCommitment};
use crate::{protocol::DEFAULT_K, totient_slow, u256_exp_mod};
use crypto_bigint::{NonZero, U256};
use crypto_primes::generate_prime;

pub struct Verifier {
    pub k: u32, // should be the same as
    pub R_bits: u32,
    n: NonZero<U256>,
    timed_commitment: Option<TimedCommitment>,
    W: Option<Vec<U256>>,
    c: Option<Vec<U256>>,
    v_exp: Option<U256>,
}

impl Verifier {
    pub fn new(n: NonZero<U256>) -> Self {
        println!("Verifier initialized.");

        Self {
            k: DEFAULT_K,
            R_bits: DEFAULT_R_BITS,
            n,
            timed_commitment: None,
            W: None,
            c: None,
            v_exp: None,
        }
    }

    pub fn receive_timed_commitment(&mut self, commit_msg: CommitPhaseMsg) {
        self.timed_commitment = Some(commit_msg.commit);
        self.W = Some(commit_msg.W);
        self.v_exp = Some(commit_msg.exp_primes)
    }

    pub fn can_open(&self) -> bool {
        self.timed_commitment.is_some()
    }

    pub fn get_challenges(&mut self) -> Vec<U256> {
        assert!(self.timed_commitment.is_some());
        let c: Vec<U256> = (0..self.k).map(|_| generate_prime(self.R_bits)).collect();
        self.c = Some(c.clone());
        c
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
                let inv_b_prevc = u256_exp_mod(&b_cur, ci, &self.n).inv_mod(&self.n).unwrap();
                let zcheck = &gy.mul_mod(&inv_b_prevc, &self.n) == zi;

                acc && wcheck && zcheck
            })
    }

    pub fn open(&self, v_prime: U256) -> U256 {
        assert!(self.can_open());
        let S = &self.timed_commitment.as_ref().unwrap().S;
        let l = S.len();
        let u = self.timed_commitment.as_ref().unwrap().u;
        let v_exp = self.v_exp.as_ref().unwrap();

        let v = u256_exp_mod(&v_prime, v_exp, &self.n);
        assert!(v == u);
        self.msg_from_v(v)
    }

    pub fn forced_open(&self) -> U256 {
        println!("Starting force opening...");
        let S = &self.timed_commitment.as_ref().unwrap().S;
        let l = S.len();
        let g = self.timed_commitment.as_ref().unwrap().g;
        let u = self.timed_commitment.as_ref().unwrap().u;

        let totient = totient_slow(*self.n);

        let two_k = U256::from(2u32.pow(self.k));
        let exp = two_k.wrapping_sub(&U256::from(l as u32));
        let g_exp = u256_exp_mod(&U256::from(2u32), &exp, &totient);

        let v = u256_exp_mod(&g, &g_exp, &self.n);

        println!("Extracted v: {v}");
        assert!(v == u);
        self.msg_from_v(v)
    }

    fn msg_from_v(&self, mut v: U256) -> U256 {
        let S = &self.timed_commitment.as_ref().unwrap().S;
        let l = S.len();
        let R = (0..l)
            .map(|_| {
                let ri = v.bit(0).into();
                v = v.mul_mod(&v, &self.n);
                ri
            })
            .rev()
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
}

// BENCHMARKING
impl Verifier {
    pub fn benchmark_opening(&self, v_prime: U256) {
        // Warm up the cache
        let _ = self.open(v_prime);
        let _ = self.forced_open();

        // Benchmark open()
        let start = Instant::now();
        let v1 = self.open(v_prime);
        let open_duration = start.elapsed();
        println!("open() took: {:?}", open_duration);

        // Benchmark forced_open()
        println!("");
        println!("Forced opening benchmark...");
        let start = Instant::now();
        let v2 = self.forced_open();
        let forced_duration = start.elapsed();
        println!("forced_open() took: {:?}", forced_duration);

        println!("Results match: {}", v1 == v2);
    }
}
