use crypto_bigint::{Checked, ConstChoice, NonZero, RandomMod, U256, rand_core::OsRng};
use crypto_primes::{generate_prime, is_prime};

use crate::{
    get_order,
    protocol::{BITS, DEFAULT_B, DEFAULT_K},
    totient_slow, u256_exp_mod,
};

/// A timed commitment containing the necessary parameters for the commitment scheme.
/// See the paper for detailed explanations here: https://crypto.stanford.edu/~dabo/abstracts/timedcommit.html
pub struct TimedCommitment {
    pub h: U256,      // Random base element
    pub g: U256,      // Generated base element
    pub u: U256,      // Tail of psuedorandom blinding sequence
    pub S: Vec<bool>, // The obfuscated message
}

/// Message sent during the commit phase containing the commitment and verification parameters
pub struct CommitPhaseMsg {
    pub commit: TimedCommitment,
    pub W: Vec<U256>, // Verification vector containing exponentiations g^2^2^i of g
    pub exp_primes: U256, // Product of prime exponents used in generating g
}

/// The main struct handling the commitment operations
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
    v_exp: U256,
    exp_primes: U256,
}

impl Committer {
    /// Creates a new Committer instance with the given message to be committed
    ///
    /// # Arguments
    /// * `m` - The message to commit to, represented as a U256
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

        let (g, exp_primes) = Self::generate_g(&h, &n, p1, p2);

        let totient = NonZero::new(
            n.get()
                .wrapping_sub(&p1.wrapping_add(&p2))
                .wrapping_add(&U256::ONE),
        )
        .unwrap();

        let two_k = U256::from(2u32.pow(DEFAULT_K));
        // then subtract l
        let exp = two_k.wrapping_sub(&U256::from(l));
        // finally calculate 2^exp mod totient using repeated squaring-- this is the
        // starting XOR power of g for the commitment.

        let v_exp = u256_exp_mod(&U256::from(2u32), &exp, &totient);

        println!("Committer initialized.");
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
            v_exp,
            exp_primes,
        }
    }

    /// Returns the modulus N used in the commitment scheme
    pub fn broadcast_n(&self) -> U256 {
        *self.n
    }

    /// Performs the commitment phase of the protocol
    /// Returns a CommitPhaseMsg containing the commitment and verification parameters
    pub fn commit(&mut self) -> CommitPhaseMsg {
        let u = self.generate_u(&self.g);
        let S = self.generate_S();
        let W = self.generate_W(self.g);

        let commit = TimedCommitment {
            h: self.h,
            g: self.g,
            u,
            S,
        };

        self.W = Some(W.clone());

        println!("Commitment sent.");
        CommitPhaseMsg {
            commit,
            W,
            exp_primes: self.exp_primes,
        }
        // send timed commitment to verifier, then rounds of interaction
    }

    /// Generates the base element g using the specified parameters
    ///
    /// # Arguments
    /// * `h` - Random base element
    /// * `n` - Modulus
    /// * `p1` - First prime factor of n
    /// * `p2` - Second prime factor of n
    ///
    /// # Returns
    /// A tuple containing the generated g and the product of prime exponents used
    fn generate_g(h: &U256, n: &NonZero<U256>, p1: U256, p2: U256) -> (U256, U256) {
        let checked_totient = (Checked::new(p1) - Checked::new(U256::ONE))
            * (Checked::new(p2) - Checked::new(U256::ONE));
        let totient = NonZero::new(checked_totient.0.unwrap()).unwrap();

        // qi^n
        let q_array: Vec<U256> = (1..DEFAULT_B)
            .filter_map(|x| match is_prime(&U256::from(x)) {
                true => {
                    let a = (0..BITS).fold(U256::ONE, |acc, _| {
                        (Checked::new(acc) * Checked::new(U256::from(x))).0.unwrap() % totient
                    });
                    Some(a % totient)
                }
                false => None,
            })
            .collect();

        let exponent = q_array.iter().fold(U256::ONE, |acc, x| {
            (Checked::new(acc) * Checked::new(U256::from(x))).0.unwrap() % totient
        });

        let mut counter = U256::ZERO;
        let mut g = U256::ONE;

        println!("Generating g...");
        while exponent.gt(&counter) {
            counter = counter.wrapping_add(&U256::ONE);
            g = g.mul_mod(h, n);
        }

        (g, exponent)
    }

    /// Generates the tail element u of the commitment sequence
    fn generate_u(&self, g: &U256) -> U256 {
        // exponentiating
        let totient = self.totient_n();
        let a = (0..self.k).fold(U256::from(2u32), |acc, _| {
            (Checked::new(acc) * Checked::new(acc)).0.unwrap() % totient
        });
        let u = u256_exp_mod(g, &a, &self.n);
        u
    }

    /// Generates the commitment sequence S by XORing the message bits with
    /// the least significant bits of successive powers
    fn generate_S(&self) -> Vec<bool> {
        // convert M to bits
        // generate a psuedorandom sequence with tail u
        // let s_i = m_i xor lsb(g^2^(2^k-i) mod N)

        let mut m_temp = self.m;
        let m_bits = (0..self.l)
            .map(|_| {
                let cur_bit = m_temp.bit(0).into();
                m_temp >>= 1;
                cur_bit
            })
            .collect::<Vec<bool>>();

        let mut cur_exp = self.v_exp.clone();
        // calculate 2^2^(k-1), then multiply by 2^(2^(k-1) - l)

        // Generate sequence with tail u

        (0..(self.l as usize))
            .map(|i| {
                let g_cur = u256_exp_mod(&self.g, &cur_exp, &self.n);
                let lsb = g_cur.bit(0) == ConstChoice::TRUE;
                cur_exp = cur_exp.mul_mod(&cur_exp, &self.n);

                m_bits[self.l as usize - 1 - i] ^ lsb
            })
            .rev()
            .collect::<Vec<bool>>()
    }

    /// Generates the verification chain W used in the binding property verification
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
            power = (Checked::new(power) * Checked::new(power)).0.unwrap() % totient;
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
    /// Sets up the parameters needed for the binding property verification
    /// Returns pairs of (z, w) values used in the verification protocol
    pub fn binding_setup(&mut self) -> Vec<(U256, U256)> {
        // generate q, alphas
        let q0 = get_order(&self.g, self.p1, self.p2);
        let q = NonZero::new(q0).unwrap();

        let mut alphas: Vec<U256> = Vec::with_capacity((self.k) as usize);
        let pairs = self.W.as_ref().unwrap()[1..]
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

    /// Generates responses to the binding verification challenges
    ///
    /// # Arguments
    /// * `c` - Vector of challenge values from the verifier
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
    /// Opens the commitment by revealing the necessary information
    /// Returns the opening value that allows verification of the commitment
    pub fn open(&self) -> U256 {
        assert!(self.W.is_some());
        u256_exp_mod(&self.h, &self.v_exp, &self.n)
    }
}
