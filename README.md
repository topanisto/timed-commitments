# deniable-auth
Timed Commitment-Based Deniable Authentication

## Rough Edges:
- In the timed commitment, the verification of the commit proof skips the rounds where the verifier commits and opens to challenge values for the prover. We'll hope to implement this later!
- An optimization can be made to the verification of the proof that the timed commitment is binding using multiple exponentiation. I did not do this, but that impl will speed up this part 2x!
- Verifier `open` exposes the message to the protocol-- we can change this to just update state on the verifier side 