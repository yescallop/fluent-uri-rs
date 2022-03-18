use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fluent_uri::{
    encoding::{table::*, *},
    *,
};
use uriparse::URIReference;
use url::Url;

criterion_group!(
    benches,
    bench_enc,
    bench_dec,
    bench_dec_unchecked,
    bench_validate,
    bench_parse,
    bench_parse_url,
    bench_parse_uriparse,
);
criterion_main!(benches);

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
            let _ = black_box(Uri::parse(black_box(s)));
        })
    });
}

fn bench_parse_url(c: &mut Criterion) {
    c.bench_function("parse_url", |b| {
        b.iter(|| {
            let s = "https://user@example.com/search?q=%E6%B5%8B%E8%AF%95#fragment";
            let _ = black_box(Url::parse(black_box(s)));
        })
    });
}

fn bench_parse_uriparse(c: &mut Criterion) {
    c.bench_function("parse_uriparse", |b| {
        b.iter(|| {
            let s = "https://user@example.com/search?q=%E6%B5%8B%E8%AF%95#fragment";
            let _ = black_box(URIReference::try_from(black_box(s)));
        })
    });
}
