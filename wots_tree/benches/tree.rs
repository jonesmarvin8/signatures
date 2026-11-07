//! Costs of tree generation, signing and verification.
#![allow(missing_docs)]

use core::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use wots_tree::{Tree, verify};

fn bench(c: &mut Criterion) {
    let seed = [1; 32];
    let message = [2; 32];
    let tree = Tree::from_seed(&seed);
    let public_key = tree.public_key();
    let auth_data = tree.sign(0, &message);

    c.bench_function("from_seed", |b| {
        b.iter(|| Tree::from_seed(black_box(&seed)));
    });
    c.bench_function("sign", |b| {
        b.iter(|| tree.sign(black_box(0), black_box(&message)));
    });
    c.bench_function("verify", |b| {
        b.iter(|| {
            verify(
                black_box(&public_key),
                black_box(&message),
                black_box(&auth_data),
            )
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
