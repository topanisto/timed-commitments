use std::fmt::Error;

use crate::{committer::*, verifier::*};

/// Default number of bits in the commitment sequence
pub const DEFAULT_B: u32 = 128;
/// Default security parameter for the binding property
pub const DEFAULT_K: u32 = 20;
/// Number of bits used in the commitment scheme
pub const BITS: u32 = 5;
/// Default bit length for challenge numbers
pub const DEFAULT_R_BITS: u32 = 10;

/// Manages the state and flow of the timed commitment protocol between
/// a committer and verifier. Ensures operations occur in the correct sequence
/// and maintains the protocol's state transitions.
pub struct CommitmentProtocol {
    state: ProtocolState,
}

/// Represents the different states of the commitment protocol
enum ProtocolState {
    /// Initial state before any commitment is made
    Initial,
    /// State after a successful commitment but before opening
    Committed,
    /// State after the commitment has been opened normally
    Opened,
    /// State after the commitment has been forcefully opened
    ForceOpened,
}

impl Default for CommitmentProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentProtocol {
    /// Creates a new CommitmentProtocol instance in the Initial state
    pub fn new() -> Self {
        Self {
            state: ProtocolState::Initial,
        }
    }

    /// Executes the commitment phase of the protocol
    ///
    /// # Arguments
    /// * `c` - The committer instance
    /// * `v` - The verifier instance
    ///
    /// # Returns
    /// Ok(()) if the commitment phase succeeds, Error if in wrong state
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

    /// Opens the commitment normally using the committer's opening value
    ///
    /// # Arguments
    /// * `c` - The committer instance
    /// * `v` - The verifier instance
    ///
    /// # Returns
    /// Ok(()) if opening succeeds, Error if in wrong state
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

    /// Forces open the commitment without the committer's cooperation
    ///
    /// # Arguments
    /// * `v` - The verifier instance
    ///
    /// # Returns
    /// Ok(()) if force opening succeeds, Error if in wrong state
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
