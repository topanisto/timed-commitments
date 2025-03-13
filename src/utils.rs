use crypto_bigint::{Checked, NonZero, U256};

pub fn get_order(a: &U256, p: U256, q: U256) -> U256 {
    let checked_n = Checked::new(p) * Checked::new(q);
    let n = checked_n.0.unwrap();
    let checked_mul =
        (Checked::new(p) - Checked::new(U256::ONE)) * (Checked::new(q) - Checked::new(U256::ONE));
    let totient = checked_mul.0.unwrap();

    let (q, _) = totient.div_rem(&NonZero::new(a.gcd(&n)).unwrap());
    q
}

pub fn totient_slow(n: U256) -> NonZero<U256> {
    // slow!
    if n == U256::ONE {
        return NonZero::new(U256::ONE).unwrap();
    }

    let mut result = n;
    let mut num = n;

    // Check divisibility by 2 first
    if num & U256::ONE == U256::ZERO {
        result = (Checked::new(result)
            - Checked::new(result.checked_div(&U256::from(2u8)).unwrap()))
        .0
        .unwrap();
        while num & U256::ONE == U256::ZERO {
            num = num.checked_div(&U256::from(2u8)).unwrap();
        }
    }

    // Check for odd factors
    let mut factor = U256::from(3u8);
    while (Checked::new(factor) * Checked::new(factor)).0.unwrap() <= num {
        if num % factor == U256::from(0u8) {
            result = (Checked::new(result) - Checked::new(result.checked_div(&factor).unwrap()))
                .0
                .unwrap();
            while num % factor == U256::from(0u8) {
                num = num.checked_div(&factor).unwrap();
            }
        }
        factor = (Checked::new(factor) + Checked::new(U256::from(2u32)))
            .0
            .unwrap();
    }

    // If `num` is still greater than 1, it must be prime
    if num > U256::from(1u8) {
        result = (Checked::new(result) - Checked::new(result.checked_div(&num).unwrap()))
            .0
            .unwrap();
    }

    NonZero::new(result).unwrap()
}

pub fn u256_exp_mod(g: &U256, x: &U256, n: &NonZero<U256>) -> U256 {
    // slow!
    let mut counter = U256::ZERO;
    let mut fin = U256::ONE;
    while x.gt(&counter) {
        counter = counter.wrapping_add(&U256::ONE);
        fin = fin.mul_mod(g, n);
    }
    fin
}
