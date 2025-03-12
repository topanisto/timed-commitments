// TODO: import module to get primes
// import module to
use crypto_bigint::{Checked, NonZero, RandomMod, U256, rand_core::OsRng};
use crypto_primes::{generate_prime, is_prime};

pub struct Committer {
    m: u32, //message to open to
    p1: U256,
    p2: U256,
    pub n: NonZero<U256>,
    pub k: u32,            // T = 2 ** k
    pub q_array: Vec<u32>, //TODO: maybe change later?
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

        let mut p2: U256 = generate_prime(Self::BITS);
        loop {
            p2 = generate_prime(Self::BITS);
            if p2.checked_rem(&U256::from(4 as u32)).unwrap() == U256::from(3 as u32) {
                break;
            }
        }

        let n = Checked::new(p1) * Checked::new(p2);

        let q_array: Vec<u32> = (1..Self::BITS)
            .filter(|&n| is_prime(&U256::from(n)))
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

    pub fn generate_g(&self) {
        let h = U256::random_mod(&mut OsRng, &self.n);

        // calculate g by cycling through primes less than B
    }

    pub fn commit() {}
}
