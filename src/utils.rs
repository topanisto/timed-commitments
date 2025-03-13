use crypto_bigint::{Checked, NonZero, U256};

pub fn get_order(a: U256, p: U256, q: U256) -> U256 {
    let checked_n = Checked::new(p) * Checked::new(q);
    let n = checked_n.0.unwrap();
    let checked_mul =
        (Checked::new(p) - Checked::new(U256::ONE)) * (Checked::new(q) - Checked::new(U256::ONE));
    let totient = checked_mul.0.unwrap();

    let (q, _) = totient.div_rem(&NonZero::new(a.gcd(&n)).unwrap());
    q
}

pub fn totient_n(p1: U256, p2: U256) -> NonZero<U256> {
    let checked_mul =
        (Checked::new(p1) - Checked::new(U256::ONE)) * (Checked::new(p2) - Checked::new(U256::ONE));
    NonZero::new(checked_mul.0.unwrap()).unwrap()
}
