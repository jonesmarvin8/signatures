//! Hazardous-materials access to FIPS 205 components: the XMSS layer
//! (Algorithms 9–11, with WOTS+ at its leaves) and the message hashes
//! `PRF_msg` and `H_msg`, for building other schemes on them.
//!
//! These functions are not SLH-DSA, and using them safely is the caller's
//! responsibility. In particular, a WOTS+ key pair (an XMSS leaf) must never
//! sign two different messages. With the `zeroize` feature, the copies of
//! `SK.seed` and `SK.prf` made here are cleared after use. Lengths are checked: every function panics if a
//! slice does not have the documented length.

use hybrid_array::{Array, ArraySize};
use typenum::Unsigned;

use crate::{ParameterSet, PkSeed, SkPrf, SkSeed, address::WotsHash, xmss::XmssSig};

/// Hash length `n`, in bytes.
#[must_use]
pub fn n<P: ParameterSet>() -> usize {
    P::N::USIZE
}

/// Length of the `H_msg` output `m`, in bytes.
#[must_use]
pub fn m<P: ParameterSet>() -> usize {
    P::M::USIZE
}

/// XMSS tree height `h'`; a tree has `2^h'` leaves.
#[must_use]
pub fn tree_height<P: ParameterSet>() -> u32 {
    P::HPrime::U32
}

/// Length of an XMSS signature (WOTS+ signature, then authentication path), in bytes.
#[must_use]
pub fn xmss_sig_len<P: ParameterSet>() -> usize {
    XmssSig::<P>::SIZE
}

/// Root of the XMSS tree at `layer` and `tree` (FIPS 205 Algorithm 9 at height `h'`).
///
/// `sk_seed`, `pk_seed` and `root` are `n` bytes.
///
/// # Panics
///
/// If a slice has the wrong length.
pub fn xmss_root<P: ParameterSet>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    layer: u32,
    tree: u64,
    root: &mut [u8],
) {
    let suite = P::new_from_pk_seed(&PkSeed(array(pk_seed)));
    let mut sk_seed = SkSeed(array(sk_seed));
    let node = suite.xmss_node(&sk_seed, 0, P::HPrime::U32, &adrs(layer, tree));
    wipe(&mut sk_seed.0);
    root.copy_from_slice(&node);
}

/// Signs the `n`-byte `msg` with leaf `idx` of the XMSS tree at `layer` and `tree`
/// (FIPS 205 Algorithm 10).
///
/// `sk_seed` and `pk_seed` are `n` bytes, `sig` is [`xmss_sig_len`] bytes, and `idx` is below
/// `2^h'`.
///
/// # Panics
///
/// If a slice has the wrong length, or `idx` is out of range.
pub fn xmss_sign<P: ParameterSet>(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    layer: u32,
    tree: u64,
    idx: u32,
    sig: &mut [u8],
) {
    assert!(idx < 1 << P::HPrime::U32, "XMSS leaf index out of range");
    let suite = P::new_from_pk_seed(&PkSeed(array(pk_seed)));
    let mut sk_seed = SkSeed(array(sk_seed));
    let xmss_sig = suite.xmss_sign(&array(msg), &sk_seed, idx, &adrs(layer, tree));
    wipe(&mut sk_seed.0);
    xmss_sig.write_to(sig);
}

/// The XMSS root implied by `sig` over the `n`-byte `msg` at leaf `idx` of the tree at
/// `layer` and `tree` (FIPS 205 Algorithm 11). A signature is valid if this equals the root.
///
/// `pk_seed` and `root` are `n` bytes, `sig` is [`xmss_sig_len`] bytes, and `idx` is below
/// `2^h'`.
///
/// # Panics
///
/// If a slice has the wrong length, or `idx` is out of range.
pub fn xmss_pk_from_sig<P: ParameterSet>(
    idx: u32,
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    layer: u32,
    tree: u64,
    root: &mut [u8],
) {
    assert!(idx < 1 << P::HPrime::U32, "XMSS leaf index out of range");
    let xmss_sig = XmssSig::<P>::try_from(sig).expect("XMSS signature length mismatch");
    let suite = P::new_from_pk_seed(&PkSeed(array(pk_seed)));
    let node = suite.xmss_pk_from_sig(idx, &xmss_sig, &array(msg), &adrs(layer, tree));
    root.copy_from_slice(&node);
}

/// `PRF_msg(SK.prf, opt_rand, msg)`, the randomizer `R` (FIPS 205 §4.1).
///
/// `sk_prf`, `opt_rand` and `out` are `n` bytes.
///
/// # Panics
///
/// If a slice has the wrong length.
pub fn prf_msg<P: ParameterSet>(sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], out: &mut [u8]) {
    let mut sk_prf = SkPrf(array(sk_prf));
    out.copy_from_slice(&P::prf_msg(&sk_prf, &array(opt_rand), &[&[msg]]));
    wipe(&mut sk_prf.0);
}

/// `H_msg(R, PK.seed, PK.root, msg)` (FIPS 205 §4.1).
///
/// `r`, `pk_seed` and `pk_root` are `n` bytes, and `out` is [`m`] bytes.
///
/// # Panics
///
/// If a slice has the wrong length.
pub fn h_msg<P: ParameterSet>(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    out: &mut [u8],
) {
    let digest = P::h_msg(
        &array(r),
        &PkSeed(array(pk_seed)),
        &array(pk_root),
        &[&[msg]],
    );
    out.copy_from_slice(&digest);
}

fn adrs(layer: u32, tree: u64) -> WotsHash {
    let mut adrs = WotsHash::default();
    adrs.layer_adrs.set(layer);
    adrs.tree_adrs_low.set(tree);
    adrs
}

/// Clears a secret copy (with the `zeroize` feature).
#[cfg(feature = "zeroize")]
fn wipe<N: ArraySize>(secret: &mut Array<u8, N>) {
    zeroize::Zeroize::zeroize(secret);
}

#[cfg(not(feature = "zeroize"))]
fn wipe<N: ArraySize>(_secret: &mut Array<u8, N>) {}

fn array<N: ArraySize>(bytes: &[u8]) -> Array<u8, N> {
    Array::try_from(bytes).expect("length mismatch")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sha2_128f, SigningKey};
    use hex_literal::hex;
    use hybrid_array::typenum::Unsigned;

    type P = Sha2_128f;

    const SK_SEED: [u8; 16] = [1; 16];
    const SK_PRF: [u8; 16] = [2; 16];
    const PK_SEED: [u8; 16] = [3; 16];

    #[test]
    fn sizes_match_sha2_128f() {
        assert_eq!(n::<P>(), 16);
        assert_eq!(m::<P>(), 34);
        assert_eq!(tree_height::<P>(), 3);
        assert_eq!(xmss_sig_len::<P>(), 35 * 16 + 3 * 16);
    }

    /// The top-layer tree's root is SLH-DSA's public root.
    #[test]
    fn top_layer_root_is_the_slh_dsa_root() {
        let sk = SigningKey::<P>::slh_keygen_internal(&SK_SEED, &SK_PRF, &PK_SEED);
        let vk = sk.as_ref().to_bytes();
        let top = <P as crate::hypertree::HypertreeParams>::D::U32 - 1;
        let mut root = [0; 16];
        xmss_root::<P>(&SK_SEED, &PK_SEED, top, 0, &mut root);
        assert_eq!(&vk[..16], &PK_SEED);
        assert_eq!(&vk[16..], &root);
    }

    #[test]
    fn every_leaf_signs_and_verifies() {
        let mut root = [0; 16];
        xmss_root::<P>(&SK_SEED, &PK_SEED, 0, 0, &mut root);
        let msg = [7; 16];
        for idx in 0..8 {
            let mut sig = [0; 35 * 16 + 3 * 16];
            xmss_sign::<P>(&msg, &SK_SEED, &PK_SEED, 0, 0, idx, &mut sig);
            let mut recovered = [0; 16];
            xmss_pk_from_sig::<P>(idx, &sig, &msg, &PK_SEED, 0, 0, &mut recovered);
            assert_eq!(recovered, root);

            let mut wrong = [0; 16];
            xmss_pk_from_sig::<P>(idx, &sig, &[8; 16], &PK_SEED, 0, 0, &mut wrong);
            assert_ne!(wrong, root);
        }
    }

    #[test]
    #[should_panic(expected = "XMSS leaf index out of range")]
    fn leaf_index_out_of_range_panics() {
        let mut sig = [0; 35 * 16 + 3 * 16];
        xmss_sign::<P>(&[0; 16], &SK_SEED, &PK_SEED, 0, 0, 8, &mut sig);
    }

    /// Same vectors as the `hashes` tests.
    #[test]
    fn message_hashes_match_the_suite() {
        let mut r = [0; 16];
        prf_msg::<P>(&[0; 16], &[1; 16], &[2; 32], &mut r);
        assert_eq!(r, hex!("6a4b5cf23911d4f3a6591d7003445316"));

        let mut digest = [0; 34];
        h_msg::<P>(&[0; 16], &[1; 16], &[2; 16], &[3; 32], &mut digest);
        assert_eq!(
            digest,
            hex!("56658221f675d907a309255e8faef639d11e6a1118fa05d3bbd26179a7e0a54a7f5b")
        );
    }
}
