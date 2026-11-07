//! Fixed-seed vectors, and the same values derived step by step from SPEC.md.

use hex_literal::hex;
use sha2::{Digest, Sha256};
use slh_dsa::{Sha2_128f, hazmat};
use wots_tree::{AUTH_LEN, N, Tree, verify};

const LEAF: u8 = 5;
const MESSAGE: [u8; 32] = [0xab; 32];
const PUBLIC_KEY: [u8; 32] =
    hex!("82e8ce66e2dda65233dc06e067c6cb01d9fede44a6f92a004277afdd6ade41a9");
const AUTH_DATA_PREFIX: [u8; 48] = hex!(
    "0569538180c60a068ddc9f6a0935df1ffa28e2037c714ac9bfaf03ccb80d21bf"
    "6ffc0c057a10f75f972784cd08c49ef8"
);
const AUTH_DATA_SHA256: [u8; 32] =
    hex!("6883b240bb47d7ba57908d5a72b89c5e54e0b8100c8ef9ecf44a662d6807c015");

fn seed() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i).expect("index below 32"))
}

#[test]
fn fixed_seed_vectors() {
    let tree = Tree::from_seed(&seed());
    assert_eq!(tree.public_key(), PUBLIC_KEY);
    let auth_data = tree.sign(LEAF, &MESSAGE);
    assert_eq!(auth_data[..48], AUTH_DATA_PREFIX);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(auth_data)),
        AUTH_DATA_SHA256
    );
    assert_eq!(verify(&PUBLIC_KEY, &MESSAGE, &auth_data), Ok(()));
}

fn expand(ds: &[u8]) -> [u8; N] {
    Sha256::new()
        .chain_update(ds)
        .chain_update(seed())
        .finalize()[..N]
        .try_into()
        .expect("N is below 32")
}

#[test]
fn spec_derivation_matches() {
    let sk_seed = expand(b"WotsTree/v1/SK.seed");
    let sk_prf = expand(b"WotsTree/v1/SK.prf");
    let pk_seed = expand(b"WotsTree/v1/PK.seed");

    let mut root = [0; N];
    hazmat::xmss_root::<Sha2_128f>(&sk_seed, &pk_seed, 0, 0, &mut root);
    assert_eq!(PUBLIC_KEY[..N], pk_seed);
    assert_eq!(PUBLIC_KEY[N..], root);

    let mut r = [0; N];
    hazmat::prf_msg::<Sha2_128f>(&sk_prf, &pk_seed, &MESSAGE, &mut r);
    let mut h_msg = [0; 34];
    hazmat::h_msg::<Sha2_128f>(&r, &pk_seed, &root, &MESSAGE, &mut h_msg);
    let mut xmss_sig = [0; AUTH_LEN - 1 - N];
    hazmat::xmss_sign::<Sha2_128f>(
        &h_msg[..N],
        &sk_seed,
        &pk_seed,
        0,
        0,
        u32::from(LEAF),
        &mut xmss_sig,
    );

    let auth_data = Tree::from_seed(&seed()).sign(LEAF, &MESSAGE);
    assert_eq!(auth_data[0], LEAF);
    assert_eq!(auth_data[1..=N], r);
    assert_eq!(auth_data[1 + N..], xmss_sig);
}
