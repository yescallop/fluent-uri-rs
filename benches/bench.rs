use std::net::{Ipv4Addr, Ipv6Addr};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fluent_uri::{
    encoding::{table::*, *},
    *,
};

criterion_group!(
    benches,
    bench_is_allowed,
    bench_enc,
    bench_dec,
    bench_dec_unchecked,
    bench_validate,
    bench_parse,
    bench_parse_v4,
    bench_parse_v4_std,
    bench_parse_v6,
    bench_parse_v6_std
);
criterion_main!(benches);

fn bench_is_allowed(c: &mut Criterion) {
    c.bench_function("is_allowed", |b| {
        b.iter(|| {
            for x in 0..128 {
                let _ = black_box(QUERY_FRAGMENT.contains(black_box(x)));
            }
        })
    });
}

fn bench_enc(c: &mut Criterion) {
    c.bench_function("enc", |b| {
        b.iter(|| {
            let s = "te😃a 测1`~!@试#$%st^&+=";
            let _ = black_box(encode(black_box(s), QUERY_FRAGMENT));
        })
    });
}

fn bench_dec(c: &mut Criterion) {
    c.bench_function("dec", |b| {
        b.iter(|| {
            let s = "te%F0%9F%98%83a%20%E6%B5%8B1%60~!@%E8%AF%95%23$%25st%5E&+=";
            let _ = black_box(decode(black_box(s)));
        })
    });
}

fn bench_dec_unchecked(c: &mut Criterion) {
    c.bench_function("dec_unchecked", |b| {
        b.iter(|| unsafe {
            let s = b"te%F0%9F%98%83a%20%E6%B5%8B1%60~!@%E8%AF%95%23$%25st%5E&+=";
            let _ = black_box(decode_unchecked(black_box(s)));
        })
    });
}

fn bench_validate(c: &mut Criterion) {
    c.bench_function("validate", |b| {
        b.iter(|| {
            let s = "te%F0%9F%98%83a%20%E6%B5%8B1%60~!@%E8%AF%95%23$%25st%5E&+=";
            let _ = black_box(validate(black_box(s), QUERY_FRAGMENT));
        })
    });
}

fn bench_parse(c: &mut Criterion) {
    c.bench_function("parse", |b| {
        b.iter(|| {
            let s = "https://user@example.com/search?q=%E6%B5%8B%E8%AF%95#fragment";
            let _ = black_box(UriRef::parse(black_box(s)));
        })
    });
}

fn bench_parse_v4(c: &mut Criterion) {
    c.bench_function("parse_v4", |b| {
        b.iter(|| {
            let s = "192.168.131.252";
            let _ = black_box(ip::parse_v4(black_box(s.as_bytes())));
        })
    });
}

fn bench_parse_v4_std(c: &mut Criterion) {
    c.bench_function("parse_v4_std", |b| {
        b.iter(|| {
            let s = "192.168.131.252";
            let _: Option<Ipv4Addr> = black_box(black_box(s).parse().ok());
        })
    });
}

fn bench_parse_v6(c: &mut Criterion) {
    c.bench_function("parse_v6", |b| {
        b.iter(|| {
            let s = "2a02:6b8::11:11";
            let _ = black_box(ip::parse_v6(black_box(s.as_bytes())));
        })
    });
}

fn bench_parse_v6_std(c: &mut Criterion) {
    c.bench_function("parse_v6_std", |b| {
        b.iter(|| {
            let s = "2a02:6b8::11:11";
            let _: Option<Ipv6Addr> = black_box(black_box(s).parse().ok());
        })
    });
}
