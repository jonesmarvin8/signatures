//! Behaviour of `wots_tree` signatures.

use wots_tree::{AUTH_LEN, Error, LEAVES, N, Tree, precheck, verify};

const SEED: [u8; 32] = [1; 32];
const MESSAGE: [u8; 32] = [2; 32];

#[test]
fn every_leaf_signs_and_verifies() {
    let tree = Tree::from_seed(&SEED);
    let public_key = tree.public_key();
    for leaf in 0..LEAVES {
        let auth_data = tree.sign(leaf, &MESSAGE);
        assert_eq!(auth_data[0], leaf);
        assert_eq!(verify(&public_key, &MESSAGE, &auth_data), Ok(()));
    }
}

#[test]
fn signing_is_deterministic() {
    let tree = Tree::from_seed(&SEED);
    assert_eq!(tree.sign(3, &MESSAGE), tree.sign(3, &MESSAGE));
    assert_eq!(
        Tree::from_seed(&SEED).public_key(),
        tree.public_key(),
        "the same seed gives the same tree"
    );
}

#[test]
fn different_seeds_give_different_keys() {
    assert_ne!(
        Tree::from_seed(&[1; 32]).public_key(),
        Tree::from_seed(&[2; 32]).public_key()
    );
}

#[test]
fn flipping_any_byte_is_rejected() {
    let tree = Tree::from_seed(&SEED);
    let public_key = tree.public_key();
    let auth_data = tree.sign(5, &MESSAGE);
    for i in 0..AUTH_LEN {
        let mut tampered = auth_data;
        tampered[i] ^= 1;
        assert!(
            verify(&public_key, &MESSAGE, &tampered).is_err(),
            "flipped byte {i} accepted"
        );
    }
}

#[test]
fn another_leafs_index_is_rejected() {
    let tree = Tree::from_seed(&SEED);
    let mut auth_data = tree.sign(2, &MESSAGE);
    auth_data[0] = 3;
    assert_eq!(
        verify(&tree.public_key(), &MESSAGE, &auth_data),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn leaf_index_out_of_range_is_malformed() {
    let tree = Tree::from_seed(&SEED);
    let mut auth_data = tree.sign(0, &MESSAGE);
    auth_data[0] = LEAVES;
    assert_eq!(precheck(&auth_data), Err(Error::Malformed));
    assert_eq!(
        verify(&tree.public_key(), &MESSAGE, &auth_data),
        Err(Error::Malformed)
    );
}

#[test]
#[should_panic(expected = "leaf index out of range")]
fn signing_with_a_leaf_out_of_range_panics() {
    let _ = Tree::from_seed(&SEED).sign(LEAVES, &MESSAGE);
}

#[test]
fn wrong_public_key_is_rejected() {
    let tree = Tree::from_seed(&SEED);
    let auth_data = tree.sign(1, &MESSAGE);
    for half in [0, N] {
        let mut public_key = tree.public_key();
        public_key[half] ^= 1;
        assert_eq!(
            verify(&public_key, &MESSAGE, &auth_data),
            Err(Error::InvalidSignature),
            "{}",
            if half == 0 { "PK.seed" } else { "root" }
        );
    }
}

#[test]
fn wrong_message_is_rejected() {
    let tree = Tree::from_seed(&SEED);
    let auth_data = tree.sign(4, &MESSAGE);
    assert_eq!(
        verify(&tree.public_key(), &[3; 32], &auth_data),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn wrong_lengths_are_malformed() {
    let tree = Tree::from_seed(&SEED);
    let auth_data = tree.sign(0, &MESSAGE);
    let mut extended = auth_data.to_vec();
    extended.push(0);
    for bytes in [&auth_data[..AUTH_LEN - 1], &extended[..], &[][..]] {
        assert_eq!(precheck(bytes), Err(Error::Malformed));
        assert_eq!(
            verify(&tree.public_key(), &MESSAGE, bytes),
            Err(Error::Malformed)
        );
    }
}
