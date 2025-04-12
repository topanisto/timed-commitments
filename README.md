Boneh-Naor Timed Commitments
---
A Rust implementation of Boneh-Naor Timed Commitments! **This is a proof of concept.** Read 'rough edges' to see the current list of vulnerabilities.

Run `cargo test benchmark -- --nocapture` to simulate an exchange.

## Rough Edges:
- In the timed commitment, the verification of the commit proof skips the rounds where the verifier commits and opens to challenge values for the prover. We'll hope to implement this later!
- An optimization can be made to the verification of the proof that the timed commitment is binding using multiple exponentiation. I did not do this, but that impl will speed up this part 2x!
- For performance reasons for using the current `crypto_int` implementation, the prover sends the prime product $$\Pi_{i=1} ^r p_i^{\text{BITS}}$$ directly to the verifier. As it's used to verify that the commitment is binding, it feels unsafe. However, the verifier can easily calculate this quantity herself at teh start of the protocol after the security parameters are revealed, and therefore we assume they have some way to obtain this (and confirm that the value sent by the prover is the correct calculation). 
- Verifier `open` exposes the message to the protocol-- we can change this to just update state on the verifier side.
