// TODO: import module to get primes
// import module to
use crypto_bigint::{
    AddMod, Checked, ConstZero, Constants, NonZero, RandomMod, U256, rand_core::OsRng,
};
use crypto_primes::{generate_prime, is_prime};

use crate::{get_order, totient_slow, u256_exp_mod};

pub struct Committer {
    m: U256, //message to open to
    l: u32,
    p1: U256,
    p2: U256,
    pub n: NonZero<U256>,
    pub k: u32, // T = 2 ** k
    pub h: U256,
    pub g: U256,
    // binding consts
    alphas: Option<Vec<U256>>,
    q: Option<NonZero<U256>>,
}

impl Committer {
    const DEFAULT_B: u32 = 128;
    const DEFAULT_K: u32 = 30;
    const BITS: u32 = 16;

    pub fn new(m: U256) -> Self {
        let l = 256 - m.leading_zeros(); // length of msg
        let mut p1: U256;
        loop {
            p1 = generate_prime(Self::BITS);
            if p1.checked_rem(&U256::from(4u32)).unwrap() == U256::from(3u32) {
                break;
            }
        }

        let mut p2: U256;
        loop {
            p2 = generate_prime(Self::BITS);
            if p2.checked_rem(&U256::from(4u32)).unwrap() == U256::from(3u32) {
                break;
            }
        }

        let checked_n = Checked::new(p1) * Checked::new(p2);
        let n = NonZero::new((checked_n.0).unwrap()).unwrap();

        let h = U256::random_mod(&mut OsRng, &n);
        let g = Self::generate_g(&h, &n, p1, p2);

        Self {
            m,
            l,
            p1,
            p2,
            n,
            k: Self::DEFAULT_K,
            h,
            g,
            alphas: None,
            q: None,
        }
    }

    // COMMIT PHASE
    pub fn commit(&self) -> TimedCommitment {
        let u = self.generate_u(&self.g);
        let S = self.generate_S();
        let W = self.generate_W(self.g);

        TimedCommitment {
            committer: &self,
            h: self.h,
            g: self.g,
            u,
            S,
        } // send timed commitment to verifier, then rounds of interaction
    }

    fn generate_g(h: &U256, n: &NonZero<U256>, p1: U256, p2: U256) -> U256 {
        let checked_totient = (Checked::new(p1) - Checked::new(U256::ONE))
            * (Checked::new(p2) - Checked::new(U256::ONE));
        let totient = NonZero::new(checked_totient.0.unwrap()).unwrap();

        let q_array: Vec<U256> = (1..Self::DEFAULT_B)
            .filter_map(|x| match is_prime(&U256::from(x)) {
                true => Some(U256::from(x)),
                false => None,
            })
            .collect();

        let mut exponent = q_array
            .iter()
            .fold(U256::ONE, |acc, x| acc.mul_mod(x, &totient));

        let mut g = U256::ONE;
        while exponent != U256::ZERO {
            exponent = exponent.wrapping_sub(&U256::ONE);
            g = g.mul_mod(h, n);
        }
        g
    }

    fn generate_u(&self, g: &U256) -> U256 {
        // exponentiating
        let totient = self.totient_n();
        let a = (0..self.k).fold(U256::from(2u32), |acc, _| acc.mul_mod(&acc, &totient));
        u256_exp_mod(g, &a, &self.n)
    }

    fn generate_S(&self) -> Vec<bool> {
        // convert M to bits
        // generate a psuedorandom sequence with tail u
        // let s_i = m_i xor lsb(g^2^(2^k-i) mod N)

        let mut m_bits = Vec::with_capacity((self.l) as usize);
        let mut m_temp = self.m;
        for _ in 0..self.l {
            m_bits.push(Self::get_lsb(&m_temp));
            m_temp = m_temp >> 1;
        }

        // TODO: you can get a directly
        let totient = self.totient_n();
        let mut suffix =
            (0..(self.k - self.l)).fold(U256::from(2u32), |acc, _| acc.mul_mod(&acc, &totient));

        // Generate sequence with tail u
        let mut S = Vec::with_capacity(256);
        // For each bit in reverse order (as per Python implementation)
        for i in (0..(self.l as usize)).rev() {
            // Get least significant bit of current
            let lsb = Self::get_lsb(&suffix);
            // XOR with message bit
            S.push(m_bits[i] ^ lsb);
            // Square the current value for next iteration
            suffix = suffix.mul_mod(&suffix, &self.n);
        }
        S
    }

    fn generate_W(&self, g: U256) -> Vec<U256> {
        let mut W = Vec::with_capacity(self.k as usize + 1);

        // First element is g^2 mod n

        let mut prev = g.mul_mod(&g, &self.n);
        let mut power = U256::from(2u32);
        let totient = self.totient_n();
        W.push(prev); // pushing in first term

        for _ in 1..=self.k {
            // Calculate 2^i
            let mut counter = U256::ZERO;
            let mut new = U256::ONE;

            // exponentiation
            while counter.lt(&power) {
                new = new.mul_mod(&prev, &self.n);
                counter = counter.wrapping_add(&U256::ONE);
            }
            W.push(new);
            prev = new; // change the base
            power = power.mul_mod(&power, &totient);
        }
        W
    }

    /// HELPERS
    fn totient_n(&self) -> NonZero<U256> {
        let checked_mul = (Checked::new(self.p1) - Checked::new(U256::ONE))
            * (Checked::new(self.p2) - Checked::new(U256::ONE));
        NonZero::new(checked_mul.0.unwrap()).unwrap()
    }

    fn get_lsb(value: &U256) -> bool {
        value & U256::ONE == U256::ONE
    }
}

// verify commitments
impl Committer {
    pub fn binding_setup(&mut self, g: &U256, W: Vec<U256>) -> Vec<(U256, U256)> {
        // generate q, alphas
        let q0 = get_order(&self.g, self.p1, self.p2);
        let q = NonZero::new(q0).unwrap();

        let mut alphas: Vec<U256> = Vec::with_capacity((self.k) as usize);
        let pairs = W
            .iter()
            .map(|b| {
                let alpha = U256::random_mod(&mut OsRng, &q);
                let z = u256_exp_mod(g, &alpha, &self.n);
                let w = u256_exp_mod(b, &alpha, &self.n); // fold w actually
                alphas.push(alpha);
                (z, w)
            })
            .collect::<Vec<(U256, U256)>>();

        self.q = Some(q);
        self.alphas = Some(alphas);
        pairs
    }

    pub fn c_response(&self, c: Vec<U256>) -> Vec<U256> {
        // zip and iter
        let q = self.q.unwrap();
        let q_tot = totient_slow(q.get());

        let mut prev = U256::ONE;
        let mut power = U256::from(2u32);

        let y = c
            .iter()
            .zip(self.alphas.as_ref().unwrap().iter())
            .enumerate()
            .map(|(idx, (ci, alphai))| {
                let cbits = ci.mul_mod(&prev, &q);
                let yi = alphai.add_mod(ci, &q);

                let mut counter = U256::ZERO;
                let mut new = U256::ONE;
                if idx == 0 {
                    prev = U256::from(2u32);
                }
                // exponentiation
                while counter.lt(&power) {
                    new = new.mul_mod(&prev, &q);
                    counter = counter.wrapping_add(&U256::ONE);
                }
                prev = new; // change the base
                power = power.mul_mod(&power, &q_tot);

                yi
            })
            .collect();

        y
    }
}

pub struct TimedCommitment<'a> {
    pub committer: &'a Committer, // committer address
    pub h: U256,
    pub g: U256,
    pub u: U256,
    pub S: Vec<bool>,
}
