use crypto_bigint::U256;

use crate::{Committer, Verifier};

pub struct TimedCommitment<'a> {
    pub committer: &'a Committer, // committer address
    pub verifier: &'a Verifier,   // verifier id
    pub h: U256,
    pub g: U256,
    pub u: U256,
    pub S: Vec<bool>,
}
