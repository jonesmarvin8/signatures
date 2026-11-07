#![no_std]
#![doc = include_str!("../README.md")]

use core::fmt;

use sha2::{Digest, Sha256};
use slh_dsa::{Sha2_128f, hazmat};
use zeroize::Zeroize;

type Params = Sha2_128f;

/// Hash length, in bytes.
pub const N: usize = 16;

/// Tree height: the tree has `2^TREE_HEIGHT` leaves.
pub const TREE_HEIGHT: u32 = 3;

/// Number of leaves, each a WOTS+ one-time key.
pub const LEAVES: u8 = 1 << TREE_HEIGHT;

/// Length of a signed message, in bytes.
pub const MESSAGE_LEN: usize = 32;

/// Length of a public key, `PK.seed || root`.
pub const PUBLIC_KEY_LEN: usize = 2 * N;

/// Length of a signature: leaf index, `R`, 35 chain values and the authentication path.
pub const AUTH_LEN: usize = 1 + N + XMSS_SIG_LEN;

const WOTS_CHAINS: usize = 35;
const PATH_LEN: usize = 3;
const XMSS_SIG_LEN: usize = (WOTS_CHAINS + PATH_LEN) * N;
const H_MSG_LEN: usize = 34;

const DS_SK_SEED: &[u8] = b"WotsTree/v1/SK.seed";
const DS_SK_PRF: &[u8] = b"WotsTree/v1/SK.prf";
const DS_PK_SEED: &[u8] = b"WotsTree/v1/PK.seed";

// The tree is always the single tree at layer 0, tree 0.
const LAYER: u32 = 0;
const TREE: u64 = 0;

/// Why a signature was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrong length or leaf index out of range.
    Malformed,
    /// Does not verify under the public key.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed WOTS+ tree signature",
            Self::InvalidSignature => "invalid WOTS+ tree signature",
        })
    }
}

impl core::error::Error for Error {}

/// A tree of [`LEAVES`] WOTS+ keys, derived from a 32-byte seed.
///
/// Each leaf must sign at most one message. Secrets are cleared on drop.
pub struct Tree {
    sk_seed: [u8; N],
    sk_prf: [u8; N],
    pk_seed: [u8; N],
    root: [u8; N],
}

impl Tree {
    /// Derives the tree from `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk_seed = expand(DS_SK_SEED, seed);
        let sk_prf = expand(DS_SK_PRF, seed);
        let pk_seed = expand(DS_PK_SEED, seed);
        let mut root = [0; N];
        hazmat::xmss_root::<Params>(&sk_seed, &pk_seed, LAYER, TREE, &mut root);
        Self {
            sk_seed,
            sk_prf,
            pk_seed,
            root,
        }
    }

    /// `PK.seed || root`.
    #[must_use]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut public_key = [0; PUBLIC_KEY_LEN];
        public_key[..N].copy_from_slice(&self.pk_seed);
        public_key[N..].copy_from_slice(&self.root);
        public_key
    }

    /// Signs `message` with `leaf`. Deterministic: the same leaf and message give the same
    /// signature.
    ///
    /// # Panics
    ///
    /// If `leaf` is not below [`LEAVES`].
    #[must_use]
    pub fn sign(&self, leaf: u8, message: &[u8; MESSAGE_LEN]) -> [u8; AUTH_LEN] {
        assert!(leaf < LEAVES, "leaf index out of range");
        let mut auth_data = [0; AUTH_LEN];
        let (leaf_byte, rest) = auth_data.split_at_mut(1);
        let (r, xmss_sig) = rest.split_at_mut(N);
        leaf_byte[0] = leaf;
        hazmat::prf_msg::<Params>(&self.sk_prf, &self.pk_seed, message, r);
        let digest = message_digest(r, &self.pk_seed, &self.root, message);
        hazmat::xmss_sign::<Params>(
            &digest,
            &self.sk_seed,
            &self.pk_seed,
            LAYER,
            TREE,
            u32::from(leaf),
            xmss_sig,
        );
        auth_data
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        self.sk_seed.zeroize();
        self.sk_prf.zeroize();
    }
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tree")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// Cheap checks, with no hashing: length and leaf index.
///
/// # Errors
///
/// [`Error::Malformed`] if `auth_data` is not [`AUTH_LEN`] bytes or its leaf index is out of
/// range.
pub fn precheck(auth_data: &[u8]) -> Result<(), Error> {
    if auth_data.len() == AUTH_LEN && auth_data[0] < LEAVES {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

/// Verifies `auth_data` over `message` under `public_key`.
///
/// # Errors
///
/// [`Error::Malformed`] if [`precheck`] fails, [`Error::InvalidSignature`] if the signature does
/// not verify.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8; MESSAGE_LEN],
    auth_data: &[u8],
) -> Result<(), Error> {
    precheck(auth_data)?;
    let (pk_seed, root) = public_key.split_at(N);
    let (leaf, rest) = auth_data.split_at(1);
    let (r, xmss_sig) = rest.split_at(N);
    let digest = message_digest(r, pk_seed, root, message);
    let mut recovered = [0; N];
    hazmat::xmss_pk_from_sig::<Params>(
        u32::from(leaf[0]),
        xmss_sig,
        &digest,
        pk_seed,
        LAYER,
        TREE,
        &mut recovered,
    );
    if recovered == root {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// `Sha256(ds || seed)`, truncated to `N` bytes.
fn expand(ds: &[u8], seed: &[u8; 32]) -> [u8; N] {
    let mut hash: [u8; 32] = Sha256::new()
        .chain_update(ds)
        .chain_update(seed)
        .finalize()
        .into();
    let mut out = [0; N];
    out.copy_from_slice(&hash[..N]);
    hash.zeroize();
    out
}

/// `H_msg(R, PK.seed, root, message)`, truncated to `N` bytes: the value WOTS+ signs.
fn message_digest(r: &[u8], pk_seed: &[u8], root: &[u8], message: &[u8]) -> [u8; N] {
    let mut h_msg = [0; H_MSG_LEN];
    hazmat::h_msg::<Params>(r, pk_seed, root, message, &mut h_msg);
    let mut digest = [0; N];
    digest.copy_from_slice(&h_msg[..N]);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_parameter_set() {
        assert_eq!(N, hazmat::n::<Params>());
        assert_eq!(H_MSG_LEN, hazmat::m::<Params>());
        assert_eq!(TREE_HEIGHT, hazmat::tree_height::<Params>());
        assert_eq!(PATH_LEN, usize::try_from(TREE_HEIGHT).expect("small"));
        assert_eq!(XMSS_SIG_LEN, hazmat::xmss_sig_len::<Params>());
        assert_eq!(AUTH_LEN, 625);
    }

    #[test]
    fn expansion_is_domain_separated() {
        let seed = [9; 32];
        let values = [
            expand(DS_SK_SEED, &seed),
            expand(DS_SK_PRF, &seed),
            expand(DS_PK_SEED, &seed),
        ];
        assert_ne!(values[0], values[1]);
        assert_ne!(values[0], values[2]);
        assert_ne!(values[1], values[2]);
    }
}
