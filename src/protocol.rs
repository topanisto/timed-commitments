use std::fmt::Error;

use crate::{committer::*, verifier::*};
use crypto_bigint::{NonZero, U256};

pub const DEFAULT_B: u32 = 128;
pub const DEFAULT_K: u32 = 30;
pub const BITS: u32 = 16;
pub const DEFAULT_R_BITS: u32 = 10;

pub struct CommitmentProtocol<'a> {
    committer: &'a Committer,
    verifier: &'a Verifier,
    state: ProtocolState,
}

enum ProtocolState {
    Initial,
    Committed,
    VerificationInProgress { round: u32 },
    Completed,
}

impl<'a> CommitmentProtocol<'a> {
    pub fn new(committer: &'a Committer, verifier: &'a Verifier) -> Self {
        // create a new instance between committer and verifier
        Self {
            committer,
            verifier,
            state: ProtocolState::Initial,
        }
    }

    pub fn commit(&mut self) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn verify_round(&mut self) -> Result<bool, Error> {
        unimplemented!()
    }
}
