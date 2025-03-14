use std::fmt::Error;

use crate::{committer::*, verifier::*};

pub const DEFAULT_B: u32 = 128;
pub const DEFAULT_K: u32 = 20;
pub const BITS: u32 = 5;
pub const DEFAULT_R_BITS: u32 = 10;

pub struct CommitmentProtocol {
    state: ProtocolState,
}

enum ProtocolState {
    Initial,
    Committed,
    Opened,
    ForceOpened,
}

impl Default for CommitmentProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentProtocol {
    pub fn new() -> Self {
        Self {
            state: ProtocolState::Initial,
        }
    }

    pub fn commit(&mut self, c: &mut Committer, v: &mut Verifier) -> Result<(), Error> {
        match self.state {
            ProtocolState::Initial => {
                let commit_msg = c.commit();
                v.receive_timed_commitment(commit_msg);

                // binding proof
                let construction_pairs = c.binding_setup();
                let challenges = v.get_challenges();
                let response = c.challenge_response(challenges);
                assert!(v.verify_commit_zkp(response, construction_pairs));
                self.state = ProtocolState::Committed;
                Ok(())
            }
            _ => Err(Error),
        }
    }

    pub fn open(&mut self, c: &mut Committer, v: &mut Verifier) -> Result<(), Error> {
        match self.state {
            ProtocolState::Committed => {
                assert!(v.can_open());
                let opening = c.open();
                let m = v.open(opening); // maybe make this opening not public?
                println!("commitment opened to {m}!");
                self.state = ProtocolState::Opened;
                Ok(())
            }
            _ => Err(Error),
        }
    }

    pub fn force_open(&mut self, v: &mut Verifier) -> Result<(), Error> {
        match self.state {
            ProtocolState::Committed => {
                let m = v.forced_open();
                println!("forced open complete to {m}");
                self.state = ProtocolState::ForceOpened;
                Ok(())
            }
            _ => Err(Error),
        }
    }
}
