mod committer;
mod protocol;
mod utils;
mod verifier;

pub use committer::*;
pub use protocol::*;
pub use utils::*;
pub use verifier::*;
#[cfg(test)]
mod tests {
    use crypto_bigint::U256;

    use super::*;
    #[test]
    fn utils_totient_slow() {
        let n = U256::from(5040u32);
        let a = totient_slow(n);
        println!("{a}");
    }

    #[test]
    fn utils_get_order() {
        let a = U256::from(3u32);
        let p = U256::from(17u32);
        let q = U256::from(7u32);

        let k = get_order(&a, p, q);
        println!("{k}");
        assert!(k == U256::from(48u32));
    }

    #[test]
    fn c_commit() {
        let msg = U256::from(42u32);
        let committer = Committer::new(msg);
        assert!(committer.n.get() > U256::ONE);
        // Get the commitment
        // let commit_msg = committer.commit();

        // assert!(!commit_msg.commit.h == U256::ZERO);
        // assert!(!commit_msg.commit.g == U256::ZERO);
        // assert!(!commit_msg.commit.u == U256::ZERO);
        // assert!(!commit_msg.commit.S.is_empty());

        // assert_eq!(commit_msg.W.len(), (DEFAULT_K + 1) as usize);
    }
}
