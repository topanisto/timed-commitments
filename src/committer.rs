// TODO: import module to get primes
// import module to
use crypto_bigint::{
    AddMod, Checked, ConstChoice, ConstZero, Constants, NonZero, RandomMod, U256, rand_core::OsRng,
};
use crypto_primes::{generate_prime, is_prime};

use crate::{
    get_lsb, get_order,
    protocol::{BITS, DEFAULT_B, DEFAULT_K},
    totient_slow, u256_exp_mod,
};

pub struct TimedCommitment {
    pub h: U256,
    pub g: U256,
    pub u: U256,
    pub S: Vec<bool>,
}

pub struct CommitPhaseMsg {
    pub commit: TimedCommitment,
    pub W: Vec<U256>,
}

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
    W: Option<Vec<U256>>,
}

impl Committer {
    pub fn new(m: U256) -> Self {
        let l = 256 - m.leading_zeros(); // length of msg
        let mut p1: U256;
        loop {
            p1 = generate_prime(BITS);
            if p1.checked_rem(&U256::from(4u32)).unwrap() == U256::from(3u32) {
                break;
            }
        }

        let mut p2: U256;
        loop {
            p2 = generate_prime(BITS);
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
            k: DEFAULT_K,
            h,
            g,
            alphas: None,
            q: None,
            W: None,
        }
    }

    pub fn broadcast_n(&self) -> U256 {
        *self.n
    }

    // COMMIT PHASE
    pub fn commit(&mut self) -> CommitPhaseMsg {
        let u = self.generate_u(&self.g);
        let S = self.generate_S();
        let W = self.generate_W(self.g); // also send W

        let commit = TimedCommitment {
            h: self.h,
            g: self.g,
            u,
            S,
        };

        self.W = Some(W.clone());
        CommitPhaseMsg { commit, W }
        // send timed commitment to verifier, then rounds of interaction
    }

    fn generate_g(h: &U256, n: &NonZero<U256>, p1: U256, p2: U256) -> U256 {
        let checked_totient = (Checked::new(p1) - Checked::new(U256::ONE))
            * (Checked::new(p2) - Checked::new(U256::ONE));
        let totient = NonZero::new(checked_totient.0.unwrap()).unwrap();

        // qi^n
        let q_array: Vec<U256> = (1..DEFAULT_B)
            .filter_map(|x| match is_prime(&U256::from(x)) {
                true => {
                    let a = U256::from(x.pow(BITS)) % totient;
                    Some(a)
                }
                false => None,
            })
            .collect();

        let exponent = q_array
            .iter()
            .fold(U256::ONE, |acc, x| acc.mul_mod(x, &totient));

        let mut counter = U256::ZERO;
        let mut g = U256::ONE;

        while exponent.gt(&counter) {
            counter = counter.wrapping_add(&U256::ONE);
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

        let mut m_temp = self.m;
        let m_bits = (0..self.l)
            .map(|i| {
                let cur_bit = m_temp.bit(0).into();
                m_temp = m_temp >> 1;
                cur_bit
            })
            .collect::<Vec<bool>>();

        let totient = self.totient_n();
        let mut cur_exp =
            (0..(self.k)).fold(U256::from(2u32), |acc, _| acc.mul_mod(&acc, &totient));

        let inv_to_start = u256_exp_mod(&U256::from(2u32), &U256::from(self.l), &totient)
            .inv_mod(&totient)
            .unwrap();

        cur_exp = cur_exp.mul_mod(&inv_to_start, &totient);

        // Generate sequence with tail u
        let S = (0..(self.l as usize))
            .map(|i| {
                let g_cur = u256_exp_mod(&self.g, &cur_exp, &self.n);
                let lsb = g_cur.bit(0) == ConstChoice::TRUE;
                cur_exp = cur_exp.mul_mod(&cur_exp, &self.n);

                m_bits[i] ^ lsb
            })
            .collect::<Vec<bool>>();
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
}

// VERIFY COMMITS
impl Committer {
    pub fn binding_setup(&mut self) -> Vec<(U256, U256)> {
        // generate q, alphas
        let q0 = get_order(&self.g, self.p1, self.p2);
        let q = NonZero::new(q0).unwrap();

        let mut alphas: Vec<U256> = Vec::with_capacity((self.k) as usize);
        let pairs = self
            .W
            .as_ref()
            .unwrap()
            .iter()
            .map(|b| {
                let alpha = U256::random_mod(&mut OsRng, &q);
                let z = u256_exp_mod(&self.g, &alpha, &self.n);
                let w = u256_exp_mod(b, &alpha, &self.n); // fold w actually
                alphas.push(alpha);
                (z, w)
            })
            .collect::<Vec<(U256, U256)>>();

        self.q = Some(q);
        self.alphas = Some(alphas);
        pairs
    }

    pub fn challenge_response(&self, c: Vec<U256>) -> Vec<U256> {
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
                let yi = alphai.add_mod(&cbits, &q);

                // getting the next power of two

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

// OPEN
impl Committer {
    pub fn open(&self) -> U256 {
        let totient = self.totient_n();
        let mut cur_exp =
            (0..(self.k)).fold(U256::from(2u32), |acc, _| acc.mul_mod(&acc, &totient));

        let inv_to_start = u256_exp_mod(&U256::from(2u32), &U256::from(self.l), &totient)
            .inv_mod(&totient)
            .unwrap();

        cur_exp = cur_exp.mul_mod(&inv_to_start, &totient);

        let v_prime = u256_exp_mod(&self.h, &cur_exp, &self.n);
        v_prime
    }
}
