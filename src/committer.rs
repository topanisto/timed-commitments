// TODO: import module to get primes
// import module to
use crypto_bigint::{Checked, NonZero, RandomMod, U256, rand_core::OsRng};
use crypto_primes::{generate_prime, is_prime};

pub struct Committer {
    m: u32, //message to open to
    p1: U256,
    p2: U256,
    pub n: NonZero<U256>,
    pub k: u32,             // T = 2 ** k
    pub q_array: Vec<U256>, //TODO: should this be a vector of primes?,
}

impl Committer {
    const DEFAULT_B: u32 = 128;
    const DEFAULT_K: u32 = 30;
    const BITS: u32 = 16;

    pub fn new(m: u32) -> Self {
        let mut p1: U256;
        loop {
            p1 = generate_prime(Self::BITS);
            if p1.checked_rem(&U256::from(4 as u32)).unwrap() == U256::from(3 as u32) {
                break;
            }
        }

        let mut p2: U256;
        loop {
            p2 = generate_prime(Self::BITS);
            if p2.checked_rem(&U256::from(4 as u32)).unwrap() == U256::from(3 as u32) {
                break;
            }
        }

        let n = Checked::new(p1) * Checked::new(p2);

        let q_array: Vec<U256> = (1..Self::DEFAULT_B)
            .filter_map(|n| match is_prime(&U256::from(n)) {
                true => Some(U256::from(n)),
                false => None,
            })
            .collect();

        Self {
            m,
            p1,
            p2,
            n: NonZero::new((n.0).unwrap()).unwrap(),
            k: Self::DEFAULT_K,
            q_array,
        }
    }

    fn totient_n(&self) -> NonZero<U256> {
        let checked_mul = (Checked::new(self.p1) - Checked::new(U256::ONE))
            * (Checked::new(self.p2) - Checked::new(U256::ONE));
        NonZero::new(checked_mul.0.unwrap()).unwrap()
    }

    pub fn generate_g(&self) -> U256 {
        let h = U256::random_mod(&mut OsRng, &self.n);
        let totient = self.totient_n();
        let mut exponent = self
            .q_array
            .iter()
            .fold(U256::ONE, |acc, x| acc.mul_mod(x, &totient));

        let mut g = U256::ONE;
        while exponent != U256::ZERO {
            exponent = exponent.wrapping_sub(&U256::ONE);
            g = g.mul_mod(&h, &self.n);
        }
        g
    }

    pub fn generate_u(&self, g: U256) -> U256 {
        let totient = self.totient_n();
        let mut a = (0..(2 as i32).pow(self.k)).fold(U256::ONE, |acc, _| {
            acc.mul_mod(&U256::from(2 as u32), &totient)
        });
        let mut u = U256::ONE;
        while a != U256::ZERO {
            a = a.wrapping_sub(&U256::ONE);
            u = u.mul_mod(&g, &self.n);
        }
        u
    }

    pub fn generate_w(&self, g: U256) //-> Vec<U256> {}
    {
    }

    pub fn commit() {}
}
