use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use digest::Output;
use one_time_signature::{
    Scheme,
    rfc8391::{Generic, Sha256},
};

fn sha256_prf(c: &mut Criterion) {
    let seed = Output::<sha2::Sha256>::default();
    let element = Output::<sha2::Sha256>::default();
    let generic = Generic::<sha2::Sha256>::from(&seed);
    let memoized = Sha256::from(&seed);
    let mut group = c.benchmark_group("rfc8391_sha256_prf");

    group.bench_function("generic", |b| {
        b.iter(|| black_box(generic.chain(black_box(0), black_box(0), black_box(&element))))
    });
    group.bench_function("memoized", |b| {
        b.iter(|| black_box(memoized.chain(black_box(0), black_box(0), black_box(&element))))
    });
    group.finish();
}

criterion_group!(benches, sha256_prf);
criterion_main!(benches);
