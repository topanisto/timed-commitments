use crate::{Committer, Verifier};

pub struct TimedCommitment {
    pub committer: Committer,
    pub verifier: Verifier,
}
